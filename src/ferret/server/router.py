"""
FastAPI ruter za portal stranu ferret sistema.

Uključuje:
  - WebSocket endpoint za agente (/ws/agent)
  - REST API za token management (/agents/*)
  - Web UI za administratore (/agents/ui)
  - Audit log UI (/agents/audit)
"""
import asyncio
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
        self._connect_time: dict[str, float]    = {}

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
            raw = json.dumps(data)
            key = self._session_keys.get(token)
            if key:
                raw = crypto.encrypt(key, raw.encode())
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

            if self._token_gen:
                payload = self._token_gen.validate(token, hw, self._server_hw_id)
                if not payload:
                    self._audit.log("agent_connect", token=token,
                                    detail={"ok": False, "reason": "invalid_token",
                                            "hw": hw[:16]}, ip=client_ip)
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
                agent = self._registry.validate(token)
                if not agent:
                    self._audit.log("agent_connect", token=token,
                                    detail={"ok": False, "reason": "invalid_token"},
                                    ip=client_ip)
                    await websocket.close(code=4001)
                    return

            await websocket.accept()
            self._connections[token]   = websocket
            self._connect_time[token]  = time.time()

            self._audit.log("agent_connect", token=token,
                            agent_name=agent["name"],
                            detail={"ok": True, "hw": hw[:16]},
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
                    if session_key and crypto.is_encrypted(raw):
                        try:
                            raw = crypto.decrypt(session_key, raw).decode()
                        except Exception:
                            continue

                    try:
                        data = json.loads(raw)
                    except Exception:
                        continue
                    t = data.get("type")

                    if t == "register":
                        caps = data.get("capabilities", [])
                        wants_enc = data.get("encrypt", False)
                        self._registry.set_online(token, True, caps)
                        await websocket.send_text(json.dumps({
                            "ok": True,
                            "encrypt": wants_enc and crypto.available(),
                        }))

                    elif t == "crypto_hello" and crypto.available():
                        client_nonce = bytes.fromhex(data.get("nonce", ""))
                        server_nonce = os.urandom(16)
                        session_key  = crypto.derive_session_key(
                            token, client_nonce, server_nonce
                        )
                        self._session_keys[token] = session_key
                        await websocket.send_text(json.dumps({
                            "type": "crypto_ok", "nonce": server_nonce.hex(),
                        }))

                    elif t == "pong":
                        pass

                    else:
                        if self._on_message:
                            asyncio.create_task(self._on_message(token, data))

            except WebSocketDisconnect:
                pass
            finally:
                duration = int(time.time() - self._connect_time.pop(token, time.time()))
                self._connections.pop(token, None)
                self._session_keys.pop(token, None)
                self._registry.set_online(token, False)
                session_key = None
                self._audit.log("agent_disconnect", token=token,
                                agent_name=agent["name"],
                                detail={"duration_sec": duration},
                                ip=client_ip)
                log.info("Agent diskonektovan: %s (trajanje: %ds)", agent["name"], duration)

        # ── Admin check ───────────────────────────────────────────────────────

        def _check_admin(creds: HTTPAuthorizationCredentials = Depends(security)):
            if not self._admin_token:
                return
            if not creds or creds.credentials != self._admin_token:
                raise HTTPException(401, "Nevalidan admin token")

        # ── Models ────────────────────────────────────────────────────────────

        class CreateRequest(BaseModel):
            name:  str
            note:  str = ""
            rules: list[str] = []

        class RulesRequest(BaseModel):
            rules: list[str]

        # ── Token operacije ───────────────────────────────────────────────────

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

        @router.get(f"{prefix}/ui", response_class=HTMLResponse,
                    dependencies=[Depends(_check_admin)])
        def admin_ui():
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
