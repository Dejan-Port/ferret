"""
FastAPI ruter za portal stranu ferret sistema.

Uključuje:
  - WebSocket endpoint za agente (/ws/agent)
  - REST API za token management (/agents/*)
  - Web UI za administratore (/agents/ui)
  - Audit log UI (/agents/audit)
"""
import asyncio
import base64
import hmac
import json
import logging
import os
import time
from typing import Callable, Awaitable

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from ferret.server.registry  import TokenRegistry
from ferret.server.acl       import Acl
from ferret.server.ui        import render_ui
from ferret.server.audit     import AuditLog
from ferret.server.token_gen import TokenGen
from ferret.server.installer import generate_linux, generate_windows
from ferret                  import crypto

log = logging.getLogger("ferret.server")

security = HTTPBearer(auto_error=False)


class AgentRouter:
    def __init__(
        self,
        db_path: str = "agents.db",
        admin_token: str = "",
        secret: str = "",
        path_prefix: str = "/agents",
        ws_path: str = "/ws/agent",
        on_message: Callable[[str, dict], Awaitable] = None,
        public_url: str = "",
    ):
        self._registry    = TokenRegistry(db_path)
        self._audit       = AuditLog(db_path)
        self._public_url  = public_url
        self._admin_token = admin_token
        self._token_gen   = TokenGen(secret) if secret else None
        self._on_message  = on_message

        try:
            from ferret import hw_id as _hw
            self._server_hw_id = _hw.get()
        except Exception:
            self._server_hw_id = ""

        try:
            from ferret.server.ca import CertAuthority
            self._ca = CertAuthority()
            log.info("CA učitan | fingerprint: %s", self._ca.fingerprint[:16])
        except Exception as e:
            self._ca = None
            log.warning("CA nije dostupan: %s", e)

        self._connections: dict[str, WebSocket] = {}
        self._session_keys: dict[str, bytes]    = {}
        self._session_ciphers: dict[str, str]   = {}
        self._connect_time: dict[str, float]    = {}
        self._forward_handlers: dict[str, dict] = {}
        self._tun_sessions: dict[str, asyncio.Queue] = {}
        # Rate limiting: {ip: [timestamp, ...]}
        self._rl_attempts: dict[str, list[float]] = {}
        self._rl_window   = 864000  # 10 dana u sekundama
        self._rl_max      = 3       # max neuspešnih pokušaja pre bana

        self.router = APIRouter()
        self._register_routes(path_prefix, ws_path)

    # ── Proxy ─────────────────────────────────────────────────────────────────

    async def proxy_connect(
        self, token: str, proto: str, host: str, port: int, session_id: str
    ) -> bool:
        acl = self._registry.get_acl(token)
        if not acl.check(proto, port):
            agent = self._registry.get(token)
            self._audit.log("proxy_deny", token=token,
                            agent_name=agent["name"] if agent else "",
                            detail={"proto": proto, "host": host, "port": port,
                                    "reason": "acl"})
            log.warning("ACL blokirao %s:%d za agenta %s", proto, port, token[:8])
            return False
        msg_type = "tcp_open" if proto == "tcp" else "udp_open"
        ok = await self.send(token, {
            "type": msg_type, "session_id": session_id,
            "host": host, "port": port,
        })
        if ok:
            agent = self._registry.get(token)
            self._audit.log("proxy_open", token=token,
                            agent_name=agent["name"] if agent else "",
                            detail={"proto": proto, "host": host, "port": port,
                                    "session_id": session_id})
        return ok

    # ── Slanje ────────────────────────────────────────────────────────────────

    async def send(self, token: str, data: dict) -> bool:
        ws = self._connections.get(token)
        if not ws:
            return False
        try:
            raw    = json.dumps(data)
            key    = self._session_keys.get(token)
            cipher = self._session_ciphers.get(token, "chacha20")
            if key:
                raw = crypto.encrypt(key, raw.encode(), cipher)
            await ws.send_text(raw)
            return True
        except Exception as e:
            log.warning("Greška pri slanju agentu %s: %s", token[:8], e)
            return False

    async def broadcast(self, data: dict, capability: str = None) -> int:
        sent = 0
        for token, ws in list(self._connections.items()):
            if capability:
                info = self._registry.get(token)
                if not info or capability not in (info.get("capabilities") or ""):
                    continue
            try:
                await ws.send_text(json.dumps(data))
                sent += 1
            except Exception:
                pass
        return sent

    @property
    def registry(self) -> TokenRegistry:
        return self._registry

    @property
    def audit(self) -> AuditLog:
        return self._audit

    @property
    def online_agents(self) -> list[dict]:
        return [a for a in self._registry.list_all() if a["online"] and not a["revoked"]]

    # ── Rute ──────────────────────────────────────────────────────────────────

    def _register_routes(self, prefix: str, ws_path: str):
        router = self.router

        # ── WebSocket ─────────────────────────────────────────────────────────

        @router.websocket(ws_path)
        async def ws_agent(websocket: WebSocket, token: str = "", hw: str = ""):
            client_ip = (websocket.headers.get("x-forwarded-for", "")
                         or getattr(websocket.client, "host", ""))

            # Rate limiting — broji samo NEUSPEŠNE pokušaje po IP u vremenskom prozoru
            now = time.time()
            attempts = self._rl_attempts.setdefault(client_ip, [])
            attempts[:] = [t for t in attempts if now - t < self._rl_window]
            if len(attempts) >= self._rl_max:
                log.warning("Rate limit: previše pokušaja od %s", client_ip)
                await websocket.close(code=4029)
                return

            # Pokušaj HMAC validaciju ako je token_gen dostupan i token ima potpis
            if self._token_gen and "." in token:
                payload = self._token_gen.validate(token, hw, self._server_hw_id)
                if not payload:
                    self._audit.log("agent_connect", token=token,
                                    detail={"ok": False, "reason": "invalid_token",
                                            "hw": hw[:16]}, ip=client_ip)
                    attempts.append(now)
                    await websocket.close(code=4001)
                    return
                agent = self._registry.get(token)
                if not agent:
                    self._registry._con.execute(
                        "INSERT OR IGNORE INTO agents (token,name,note,rules,created_at)"
                        " VALUES (?,?,?,?,datetime('now'))",
                        [token, payload.get("name", ""), "", "[]"]
                    )
                    self._registry._con.commit()
                    agent = self._registry.get(token)
            else:
                agent = self._registry.get(token)
                if not agent or agent.get("revoked"):
                    self._audit.log("agent_connect", token=token,
                                    detail={"ok": False, "reason": "invalid_token"},
                                    ip=client_ip)
                    attempts.append(now)
                    await websocket.close(code=4001)
                    return

                approved = agent.get("approved", 1)
                stored_hwid = agent.get("hwid", "")

                if approved:
                    # Odobren agent — proveri HWID ako postoji
                    if stored_hwid and hw and not hmac.compare_digest(stored_hwid, hw):
                        self._audit.log("agent_connect", token=token,
                                        detail={"ok": False, "reason": "hwid_mismatch",
                                                "hw": hw[:16]}, ip=client_ip)
                        log.warning("HWID mismatch za %s: očekivan %s, dobijen %s",
                                    token[:8], stored_hwid[:16], hw[:16])
                        attempts.append(now)
                        await websocket.close(code=4003)
                        return
                else:
                    # Invite token — proveri rok
                    if not self._registry.invite_valid(token):
                        self._audit.log("agent_connect", token=token,
                                        detail={"ok": False, "reason": "invite_expired"},
                                        ip=client_ip)
                        attempts.append(now)
                        await websocket.close(code=4002)
                        return
                    # Vezuj HWID pri prvoj konekciji
                    if hw and not stored_hwid:
                        self._registry.bind_hwid(token, hw)
                        log.info("HWID vezan za token %s: %s", token[:8], hw[:16])

            await websocket.accept()
            self._connections[token]   = websocket
            self._connect_time[token]  = time.time()

            self._audit.log("agent_connect", token=token,
                            agent_name=agent["name"],
                            detail={"ok": True, "hw": hw[:16], "approved": agent.get("approved", 1)},
                            ip=client_ip)
            log.info("Agent konektovan: %s (%s) od %s", agent["name"], token[:8], client_ip)

            session_key: bytes | None = None

            async def _send_raw(data: dict):
                raw = json.dumps(data)
                if session_key:
                    raw = crypto.encrypt(session_key, raw.encode())
                await websocket.send_text(raw)

            try:
                async for raw in websocket.iter_text():
                    if len(raw) > 4 * 1024 * 1024:  # 4 MB hard limit po poruci
                        log.warning("Prevelika poruka od %s (%d B) — ignorisana",
                                    token[:8], len(raw))
                        continue
                    if session_key and crypto.is_encrypted(raw):
                        try:
                            raw = crypto.decrypt(session_key, raw).decode()
                        except Exception:
                            continue

                    try:
                        data = json.loads(raw)
                    except Exception:
                        continue
                    if not crypto.validate_payload(data):
                        log.warning("Nevalidan payload od %s — odbačen", token[:8])
                        continue
                    t = data.get("type")

                    if t == "register":
                        caps = data.get("capabilities", [])
                        wants_enc = data.get("encrypt", False)
                        _fresh = self._registry.get(token)
                        is_approved = bool(_fresh and _fresh.get("approved", 1))
                        self._registry.set_online(token, True, caps)
                        await websocket.send_text(json.dumps({
                            "ok":       True,
                            "approved": is_approved,
                            "encrypt":  wants_enc and crypto.available() and is_approved,
                        }))

                    elif t == "crypto_hello" and crypto.available():
                        client_nonce   = bytes.fromhex(data.get("nonce", ""))
                        server_nonce   = os.urandom(16)
                        agreed_cipher  = data.get("cipher", "chacha20")
                        if agreed_cipher not in ("chacha20", "aes256gcm"):
                            agreed_cipher = "chacha20"
                        session_key    = crypto.derive_session_key(
                            token, client_nonce, server_nonce, agreed_cipher
                        )
                        self._session_keys[token]   = session_key
                        self._session_ciphers[token] = agreed_cipher
                        await websocket.send_text(json.dumps({
                            "type":   "crypto_ok",
                            "nonce":  server_nonce.hex(),
                            "cipher": agreed_cipher,
                        }))

                    elif t == "pong":
                        pass

                    else:
                        # TUN paketi — rutuj ka admin tun klijentu
                        if t in ("tun_ready", "tun_packet"):
                            tun_q = self._tun_sessions.get(token)
                            if tun_q:
                                asyncio.create_task(tun_q.put(data))
                        else:
                            # Prosleđuj forward handler-ima za tu sesiju
                            sid = data.get("session_id", "")
                            fwd = self._forward_handlers.get(token, {}).get(sid)
                            if fwd:
                                asyncio.create_task(fwd(data))
                            elif self._on_message:
                                asyncio.create_task(self._on_message(token, data))

            except WebSocketDisconnect:
                pass
            finally:
                duration = int(time.time() - self._connect_time.pop(token, time.time()))
                self._connections.pop(token, None)
                dead_key = self._session_keys.pop(token, None)
                crypto.zero_key(dead_key)
                self._session_ciphers.pop(token, None)
                self._registry.set_online(token, False)
                crypto.zero_key(session_key)
                session_key = None
                self._audit.log("agent_disconnect", token=token,
                                agent_name=agent["name"],
                                detail={"duration_sec": duration},
                                ip=client_ip)
                log.info("Agent diskonektovan: %s (trajanje: %ds)", agent["name"], duration)

        # ── Local forward WebSocket (server otvara TCP direktno) ─────────────

        @router.websocket(f"{prefix}/local-forward")
        async def ws_local_forward(
            websocket: WebSocket,
            admin_token: str = "",
            host: str = "",
            port: int = 0,
        ):
            if self._admin_token and admin_token != self._admin_token:
                await websocket.close(code=4001)
                return
            if not host or not port:
                await websocket.close(code=4003)
                return
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=10
                )
            except Exception as e:
                log.warning("local-forward ne može da se konektuje na %s:%d: %s", host, port, e)
                await websocket.close(code=4004)
                return

            await websocket.accept()
            log.info("local-forward: %s:%d", host, port)

            async def pump_to_client():
                try:
                    while True:
                        chunk = await asyncio.wait_for(reader.read(32768), timeout=300)
                        if not chunk:
                            break
                        await websocket.send_bytes(chunk)
                except Exception:
                    pass
                finally:
                    try:
                        await websocket.close()
                    except Exception:
                        pass

            async def pump_to_server():
                try:
                    async for msg in websocket.iter_bytes():
                        writer.write(msg)
                        await writer.drain()
                except Exception:
                    pass
                finally:
                    try:
                        writer.close()
                    except Exception:
                        pass

            await asyncio.gather(pump_to_client(), pump_to_server())

        # ── Admin forward WebSocket ───────────────────────────────────────────

        @router.websocket(f"{prefix}/forward")
        async def ws_forward(
            websocket: WebSocket,
            admin_token: str = "",
            agent: str = "",
            host: str = "",
            port: int = 0,
        ):
            """
            Admin TCP forward: premoštava TCP konekciju kroz agenta.
            Protokol: raw binarni WebSocket = bajti TCP sesije.
            """
            if self._admin_token and admin_token != self._admin_token:
                await websocket.close(code=4001)
                return
            agent_ws = self._connections.get(agent)
            if not agent_ws:
                await websocket.close(code=4002)
                return
            await websocket.accept()

            import uuid
            sid = uuid.uuid4().hex

            loop = asyncio.get_event_loop()
            ready   = asyncio.Event()
            ok_flag = [False]
            queue: asyncio.Queue = asyncio.Queue()

            async def inject(data: dict):
                t = data.get("type", "")
                if t == "tcp_opened" and data.get("session_id") == sid:
                    ok_flag[0] = data.get("ok", False)
                    ready.set()
                elif t == "tcp_data" and data.get("session_id") == sid:
                    await queue.put(base64.b64decode(data.get("data", "")))
                elif t == "tcp_close" and data.get("session_id") == sid:
                    await queue.put(None)

            self._forward_handlers.setdefault(agent, {})[sid] = inject

            await self.send(agent, {"type": "tcp_open", "session_id": sid,
                                     "host": host, "port": port})

            try:
                await asyncio.wait_for(ready.wait(), timeout=10)
            except asyncio.TimeoutError:
                self._forward_handlers.get(agent, {}).pop(sid, None)
                await websocket.close(code=4003)
                return

            if not ok_flag[0]:
                self._forward_handlers.get(agent, {}).pop(sid, None)
                await websocket.close(code=4004)
                return

            async def pump_to_client():
                try:
                    while True:
                        chunk = await queue.get()
                        if chunk is None:
                            break
                        await websocket.send_bytes(chunk)
                except Exception:
                    pass
                finally:
                    try:
                        await websocket.close()
                    except Exception:
                        pass

            async def pump_to_agent():
                try:
                    while True:
                        msg = await websocket.receive()
                        if msg.get("type") == "websocket.disconnect":
                            break
                        raw = msg.get("bytes") or (msg.get("text", "").encode())
                        if raw:
                            await self.send(agent, {
                                "type":       "tcp_data",
                                "session_id": sid,
                                "data":       base64.b64encode(raw).decode(),
                            })
                except Exception:
                    pass
                finally:
                    await self.send(agent, {"type": "tcp_close", "session_id": sid})
                    self._forward_handlers.get(agent, {}).pop(sid, None)

            await asyncio.gather(pump_to_client(), pump_to_agent())

        # ── Admin TUN WebSocket ───────────────────────────────────────────────

        @router.websocket(f"{prefix}/tun")
        async def ws_tun(
            websocket: WebSocket,
            admin_token: str = "",
            agent: str = "",
        ):
            if self._admin_token and admin_token != self._admin_token:
                await websocket.close(code=4001)
                return
            if not self._connections.get(agent):
                await websocket.close(code=4002)
                return

            tun_queue: asyncio.Queue = asyncio.Queue()
            ready_event = asyncio.Event()
            ready_data  = [None]

            # Registruj queue — server ruter prosleđuje tun_ready/tun_packet ovde
            self._tun_sessions[agent] = tun_queue

            await websocket.accept()

            # Čitaj tun_request od klijenta
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
                req = json.loads(raw)
            except Exception:
                self._tun_sessions.pop(agent, None)
                await websocket.close(code=4003)
                return

            # Pošalji tun_config agentu
            cfg = {
                "type":         "tun_config",
                "ip":           req.get("agent_ip", "10.99.0.2"),
                "gateway":      req.get("client_ip", "10.99.0.1"),
                "mtu":          req.get("mtu", 1400),
                "routes":       [],
                "lan_access":   True,
            }
            if req.get("remap_subnet"):
                cfg["remap_subnet"] = req["remap_subnet"]
            await self.send(agent, cfg)

            # Čekaj tun_ready od agenta
            async def wait_ready():
                while True:
                    data = await tun_queue.get()
                    if data.get("type") == "tun_ready":
                        ready_data[0] = data
                        ready_event.set()
                        return
                    await tun_queue.put(data)  # vrati paket u queue

            try:
                await asyncio.wait_for(wait_ready(), timeout=15)
            except asyncio.TimeoutError:
                self._tun_sessions.pop(agent, None)
                await websocket.close(code=4003)
                return

            await websocket.send_text(json.dumps(ready_data[0]))
            log.info("TUN sesija uspostavljena za agenta %s", agent[:8])

            async def pump_to_client():
                try:
                    while True:
                        pkt = await tun_queue.get()
                        await websocket.send_text(json.dumps(pkt))
                except Exception:
                    pass
                finally:
                    try:
                        await websocket.close()
                    except Exception:
                        pass

            async def pump_to_agent():
                try:
                    async for msg in websocket.iter_text():
                        try:
                            await self.send(agent, json.loads(msg))
                        except Exception:
                            pass
                except Exception:
                    pass
                finally:
                    await self.send(agent, {"type": "tun_down"})
                    self._tun_sessions.pop(agent, None)
                    log.info("TUN sesija zatvorena za agenta %s", agent[:8])

            await asyncio.gather(pump_to_client(), pump_to_agent())

        # ── Admin check ───────────────────────────────────────────────────────

        def _check_admin(creds: HTTPAuthorizationCredentials = Depends(security)):
            if not self._admin_token:
                return
            token_ok = (creds is not None and
                        hmac.compare_digest(creds.credentials, self._admin_token))
            if not token_ok:
                raise HTTPException(401, "Nevalidan admin token")

        # ── Models ────────────────────────────────────────────────────────────

        class CreateRequest(BaseModel):
            name:  str
            note:  str = ""
            rules: list[str] = []

        class RulesRequest(BaseModel):
            rules: list[str]

        # ── Token operacije ───────────────────────────────────────────────────

        @router.post(f"{prefix}/invite", dependencies=[Depends(_check_admin)])
        def create_invite(req: CreateRequest, request: Request):
            """Kreira invite token koji važi 5 minuta za prvu konekciju."""
            token = self._registry.create(req.name, req.note, req.rules, invite_minutes=5)
            self._audit.log("invite_create",
                            token=token, agent_name=req.name,
                            detail={"note": req.note},
                            ip=request.client.host if request.client else "")
            return {"token": token, "name": req.name, "invite": True, "expires_in": 300}

        @router.post(f"{prefix}/{{token}}/approve", dependencies=[Depends(_check_admin)])
        def approve_agent(token: str, request: Request):
            """Admin odobrava pending agenta — HWID se vezuje trajno."""
            agent = self._registry.get(token)
            if not agent:
                raise HTTPException(404, "Agent nije pronađen")
            if agent.get("approved"):
                raise HTTPException(400, "Agent je već odobren")
            if not agent.get("hwid"):
                raise HTTPException(400, "Agent još nije poslao HWID — čekaj konekciju")
            self._registry.approve(token)
            self._audit.log("agent_approve",
                            token=token, agent_name=agent["name"],
                            detail={"hwid": agent["hwid"][:16]},
                            ip=request.client.host if request.client else "")
            return {"ok": True, "hwid": agent["hwid"][:16]}

        @router.get(f"{prefix}/pending", dependencies=[Depends(_check_admin)])
        def list_pending():
            """Lista agenata koji čekaju odobrenje."""
            return self._registry.list_pending()

        @router.post(f"{prefix}/token", dependencies=[Depends(_check_admin)])
        def create_token(req: CreateRequest, request: Request):
            token = self._registry.create(req.name, req.note, req.rules)
            result = {"token": token, "name": req.name}

            if self._ca:
                cert_pem, key_pem = self._ca.issue(req.name, jti=token[:8])
                self._registry.save_cert(token, cert_pem)
                result.update({
                    "cert_pem": cert_pem,
                    "key_pem":  key_pem,
                    "ca_pem":   self._ca.ca_pem,
                    "ca_fp":    self._ca.fingerprint,
                })

            self._audit.log("token_create",
                            token=token, agent_name=req.name,
                            detail={"rules": req.rules, "note": req.note},
                            ip=request.client.host if request.client else "")
            return result

        @router.patch(f"{prefix}/{{token}}/rules", dependencies=[Depends(_check_admin)])
        def update_rules(token: str, req: RulesRequest, request: Request):
            agent = self._registry.get(token)
            if not agent:
                raise HTTPException(404, "Agent nije pronađen")
            old_rules = json.loads(agent.get("rules") or "[]")
            self._registry.set_rules(token, req.rules)
            self._audit.log("rules_change",
                            token=token, agent_name=agent["name"],
                            detail={"old": old_rules, "new": req.rules},
                            ip=request.client.host if request.client else "")
            return {"ok": True}

        @router.delete(f"{prefix}/{{token}}", dependencies=[Depends(_check_admin)])
        def revoke_token(token: str, request: Request):
            agent = self._registry.get(token)
            self._registry.revoke(token)
            self._audit.log("token_revoke",
                            token=token,
                            agent_name=agent["name"] if agent else "",
                            ip=request.client.host if request.client else "")
            return {"ok": True}

        @router.get(f"{prefix}/{{token}}/bundle", dependencies=[Depends(_check_admin)])
        def download_bundle(token: str):
            if not self._ca:
                raise HTTPException(503, "CA nije inicijalizovan")
            agent = self._registry.get(token)
            if not agent:
                raise HTTPException(404, "Agent nije pronađen")
            cert_pem = agent.get("cert_pem", "")
            if not cert_pem:
                raise HTTPException(404, "Sertifikat nije pronađen — generiši novi token")
            name   = agent["name"].replace(" ", "_")
            bundle = f"# CA sertifikat\n{self._ca.ca_pem}\n# Klijentski sertifikat\n{cert_pem}"
            return Response(
                content=bundle,
                media_type="application/x-pem-file",
                headers={"Content-Disposition": f'attachment; filename="{name}_ca.pem"'},
            )

        @router.get(f"{prefix}/{{token}}/installer",
                    dependencies=[Depends(_check_admin)])
        def get_installer(token: str, os: str = "linux"):
            """
            Generiše install skript sa ugrađenim sertifikatom i ključem.
            PAŽNJA: odgovor sadrži privatni ključ — zahteva admin token.
            os = linux | windows
            """
            agent = self._registry.get(token)
            if not agent or agent.get("revoked"):
                raise HTTPException(404, "Token nije validan")

            name       = agent["name"]
            server_url = self._public_url or ""
            ca_pem     = self._ca.ca_pem        if self._ca else ""
            ca_fp      = self._ca.fingerprint   if self._ca else ""

            # Generiši novi cert + key za ovaj installer
            # (privatni ključ se ne čuva na serveru — generiše se svaki put)
            cert_pem, key_pem = ("", "")
            if self._ca:
                cert_pem, key_pem = self._ca.issue(name, jti=token[:8])
                # Sačuvaj novi cert u DB (zamenjuje prethodni)
                self._registry.save_cert(token, cert_pem)

            if os.lower() == "windows":
                content   = generate_windows(name, token, server_url,
                                             ca_pem, cert_pem, key_pem, ca_fp)
                filename  = f"{name.replace(' ','_')}_install.ps1"
                mediatype = "text/plain"
            else:
                content   = generate_linux(name, token, server_url,
                                           ca_pem, cert_pem, key_pem, ca_fp)
                filename  = f"{name.replace(' ','_')}_install.sh"
                mediatype = "text/x-shellscript"

            self._audit.log("admin_access", token=token, agent_name=name,
                            detail={"action": "download_installer", "os": os})
            return Response(
                content=content,
                media_type=mediatype,
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )

        @router.get(f"{prefix}", dependencies=[Depends(_check_admin)])
        def list_agents():
            agents = self._registry.list_all()
            for a in agents:
                a["token_short"] = a["token"][:8] + "..."
            return agents

        # ── UI ────────────────────────────────────────────────────────────────

        @router.get(f"{prefix}/auth")
        def check_auth(creds: HTTPAuthorizationCredentials = Depends(security)):
            """Jednostavan endpoint za validaciju admin tokena — 200 OK ili 401."""
            if not self._admin_token:
                return {"ok": True}
            token_ok = (creds is not None and
                        hmac.compare_digest(creds.credentials, self._admin_token))
            if not token_ok:
                raise HTTPException(401, "Nevalidan token")
            return {"ok": True}

        @router.get(f"{prefix}/ui", response_class=HTMLResponse)
        def admin_ui():
            # HTML uvek serviran — auth se proverava u JS via /agents/auth
            agents = self._registry.list_all()
            return render_ui(agents)

        @router.get(f"{prefix}/audit", response_class=HTMLResponse,
                    dependencies=[Depends(_check_admin)])
        def audit_ui(token: str = "", event: str = ""):
            events = self._audit.recent(limit=300, token=token or None, event=event or None)
            agents = self._registry.list_all()
            return _render_audit(events, agents, token, event)


# ── Audit UI ──────────────────────────────────────────────────────────────────

_EVENT_COLORS = {
    "agent_connect":    ("#166534", "#86efac"),
    "agent_disconnect": ("#1e293b", "#94a3b8"),
    "proxy_open":       ("#1e3a8a", "#93c5fd"),
    "proxy_deny":       ("#7f1d1d", "#fca5a5"),
    "tun_start":        ("#14532d", "#4ade80"),
    "tun_stop":         ("#1e293b", "#94a3b8"),
    "token_create":     ("#3b1f6e", "#c4b5fd"),
    "token_revoke":     ("#7f1d1d", "#fca5a5"),
    "rules_change":     ("#78350f", "#fcd34d"),
    "admin_access":     ("#1e3a8a", "#93c5fd"),
}

_EVENT_ICONS = {
    "agent_connect":    "⬆",
    "agent_disconnect": "⬇",
    "proxy_open":       "⇄",
    "proxy_deny":       "✗",
    "tun_start":        "▶",
    "tun_stop":         "■",
    "token_create":     "+",
    "token_revoke":     "⊘",
    "rules_change":     "⚙",
    "admin_access":     "👤",
}


def _render_audit(events, agents, filter_token, filter_event) -> str:
    agent_options = "".join(
        f'<option value="{a["token"][:16]}"'
        f'{" selected" if filter_token == a["token"][:16] else ""}>'
        f'{_esc(a["name"])}</option>'
        for a in agents if not a.get("revoked")
    )

    event_types = [
        "agent_connect", "agent_disconnect", "proxy_open", "proxy_deny",
        "tun_start", "tun_stop", "token_create", "token_revoke", "rules_change",
    ]
    event_options = "".join(
        f'<option value="{e}"{"  selected" if filter_event == e else ""}>{e}</option>'
        for e in event_types
    )

    rows = ""
    for ev in events:
        bg, fg = _EVENT_COLORS.get(ev["event"], ("#1e2235", "#e2e4ed"))
        icon   = _EVENT_ICONS.get(ev["event"], "•")
        detail = ev.get("detail", {})
        detail_str = " ".join(f'<span class="d-kv"><b>{k}</b> {_esc(str(v))}</span>'
                              for k, v in detail.items() if v not in ("", None, [], {}))
        rows += f"""
        <tr>
          <td style="color:#4b5270;white-space:nowrap">{ev["ts"]}</td>
          <td>
            <span class="badge" style="background:{bg};color:{fg}">
              {icon} {ev["event"]}
            </span>
          </td>
          <td><strong>{_esc(ev["agent_name"])}</strong></td>
          <td><code style="color:#7dd3fc;font-size:11px">{ev["token"]}</code></td>
          <td style="color:#6b7280;font-size:12px">{ev.get("ip","")}</td>
          <td style="font-size:12px">{detail_str}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="sr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audit Log</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e4ed;padding:32px}}
h1{{font-size:20px;font-weight:700;margin-bottom:6px;color:#fff}}
.subtitle{{font-size:12px;color:#4b5270;margin-bottom:24px}}
.toolbar{{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:20px}}
label{{font-size:10px;color:#8b93a7;text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:4px}}
select,input{{background:#1e2235;border:1px solid #2d3354;border-radius:7px;color:#e2e4ed;
              font-family:inherit;font-size:13px;padding:7px 11px;outline:none}}
select:focus,input:focus{{border-color:#3b5bdb}}
.btn{{padding:8px 16px;background:#3b5bdb;color:#fff;border:none;border-radius:7px;
      font-size:13px;cursor:pointer}}
.btn-ghost{{padding:8px 14px;background:#1e2235;color:#e2e4ed;border:none;border-radius:7px;
            font-size:13px;cursor:pointer;text-decoration:none;display:inline-block}}
.card{{background:#151821;border:1px solid #252840;border-radius:10px;padding:24px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{font-size:10px;color:#4b5270;text-transform:uppercase;letter-spacing:.8px;
    padding:8px 12px;border-bottom:1px solid #252840;text-align:left}}
td{{padding:8px 12px;border-bottom:1px solid #1a1d27;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#1a1d27}}
.badge{{display:inline-block;border-radius:5px;padding:2px 8px;font-size:11px;
        font-family:monospace;white-space:nowrap}}
.d-kv{{display:inline-block;background:#1e2235;border-radius:4px;padding:2px 7px;
       margin:1px;font-size:11px;font-family:monospace}}
.d-kv b{{color:#8b93a7;margin-right:4px}}
.empty{{text-align:center;color:#4b5270;padding:32px}}
</style>
</head>
<body>
<h1>Audit Log</h1>
<p class="subtitle">{len(events)} događaja | <a href="ui" class="btn-ghost" style="font-size:12px;padding:4px 10px">← Agenti</a></p>

<div class="toolbar">
  <form method="get" style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end">
    <div>
      <label>Agent</label>
      <select name="token">
        <option value="">Svi agenti</option>
        {agent_options}
      </select>
    </div>
    <div>
      <label>Tip događaja</label>
      <select name="event">
        <option value="">Svi tipovi</option>
        {event_options}
      </select>
    </div>
    <button type="submit" class="btn">Filtriraj</button>
    <a href="audit" class="btn-ghost">Reset</a>
  </form>
</div>

<div class="card">
  <table>
    <tr>
      <th>Vreme</th><th>Događaj</th><th>Agent</th>
      <th>Token</th><th>IP</th><th>Detalji</th>
    </tr>
    {rows if rows else '<tr><td colspan="6" class="empty">Nema događaja</td></tr>'}
  </table>
</div>
</body>
</html>"""


def _esc(s: str) -> str:
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _render_login(redirect: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ferret — Login</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0a0c14;color:#e2e8f0;font-family:system-ui,sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh}}
  .box{{background:#0f1117;border:1px solid #1e2235;border-radius:12px;
        padding:40px;width:340px;text-align:center}}
  h1{{font-size:28px;margin-bottom:6px}}
  p{{color:#4b5270;margin-bottom:28px;font-size:14px}}
  input{{width:100%;padding:10px 14px;background:#1a1d2e;border:1px solid #2d3354;
         border-radius:8px;color:#e2e8f0;font-size:14px;margin-bottom:16px;outline:none}}
  input:focus{{border-color:#3b5bdb}}
  button{{width:100%;padding:11px;background:#3b5bdb;border:none;border-radius:8px;
          color:#fff;font-size:15px;cursor:pointer;font-weight:600}}
  button:hover{{background:#2f4ac7}}
  .err{{color:#f87171;font-size:13px;margin-top:12px;display:none}}
</style>
</head>
<body>
<div class="box">
  <h1>🐾 Ferret</h1>
  <p>Enter admin token to continue</p>
  <input type="password" id="tok" placeholder="Admin token" autofocus
         onkeydown="if(event.key==='Enter')login()">
  <button onclick="login()">Login</button>
  <div class="err" id="err">Invalid token</div>
</div>
<script>
async function login() {{
  const tok = document.getElementById('tok').value.trim();
  if (!tok) return;
  const r = await fetch('{redirect}/auth', {{headers:{{'Authorization':'Bearer '+tok}}}});
  if (r.ok) {{
    localStorage.setItem('adminToken', tok);
    location.href = '{redirect}/ui';
  }} else {{
    document.getElementById('err').style.display = 'block';
  }}
}}
// Ako već ima token u localStorage, proveri pa preusmeri
const saved = localStorage.getItem('adminToken');
if (saved) {{
  fetch('{redirect}/auth', {{headers:{{'Authorization':'Bearer '+saved}}}})
    .then(r => {{ if(r.ok) location.href = '{redirect}/ui'; }});
}}
</script>
</body>
</html>"""
