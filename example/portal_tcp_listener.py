"""
Portal TCP proxy — sluša lokalno, tuneluje kroz agenta.

Kako radi:
    1. Sluša na 127.0.0.1:LOCAL_PORT
    2. Kada se RDP/SSH/VNC klijent konektuje, šalje tcp_open agentu
    3. Agent otvara konekciju ka TARGET_HOST:TARGET_PORT na svojoj mreži
    4. Svi bajtovi idu bidirekciono kroz WebSocket tunel

Primer — RDP na bankomat:
    listener = PortalTcpProxy(router, token, local_port=13389,
                               target_host="localhost", target_port=3389)
    asyncio.create_task(listener.start())

    # Zatim:
    mstsc /v:127.0.0.1:13389

Primer — SSH:
    listener = PortalTcpProxy(router, token, local_port=12222,
                               target_host="localhost", target_port=22)

Napomena:
    Sluša samo na 127.0.0.1 — nije dostupan spolja.
    ACL provera se radi automatski (tcp:3389 mora biti u pravilima agenta).
"""
import asyncio
import base64
import logging
import uuid

log = logging.getLogger("portal.tcp_proxy")


class PortalTcpProxy:
    """
    TCP proxy između lokalnog klijenta i udaljenog agenta.

    Parametri:
        router      - AgentRouter instanca
        token       - token agenta ka kome se tuneluje
        local_port  - lokalni port na kome se sluša (samo 127.0.0.1)
        target_host - host koji agent otvara na svojoj strani (npr. "localhost")
        target_port - port koji agent otvara (npr. 3389 za RDP)
        bind        - na kojoj adresi sluša (default: 127.0.0.1)
    """

    def __init__(
        self,
        router,
        token: str,
        local_port: int,
        target_host: str = "localhost",
        target_port: int = 3389,
        bind: str = "127.0.0.1",
    ):
        self._router      = router
        self._token       = token
        self._local_port  = local_port
        self._target_host = target_host
        self._target_port = target_port
        self._bind        = bind
        # session_id → asyncio.StreamWriter prema lokalnom klijentu
        self._sessions: dict[str, asyncio.StreamWriter] = {}
        # session_id → Event koji signalizira da je agent potvrdio konekciju
        self._ready: dict[str, asyncio.Event] = {}

        # Registruj handler za poruke koje dolaze od agenta
        self._hook_router()

    def _hook_router(self):
        """Kači se na on_message AgentRoutera da prima odgovore od agenta."""
        orig = self._router._on_message

        async def _interceptor(token: str, data: dict):
            if token == self._token:
                t = data.get("type")
                if t in ("tcp_opened", "tcp_data", "tcp_close"):
                    await self._on_agent_message(data)
                    return
            if orig:
                await orig(token, data)

        self._router._on_message = _interceptor

    async def start(self):
        """Pokreće TCP listener. Pozovi kao asyncio.create_task(listener.start())."""
        server = await asyncio.start_server(
            self._on_client, self._bind, self._local_port
        )
        agent_info = self._router.registry.get(self._token)
        name = agent_info["name"] if agent_info else self._token[:8]
        log.info("TCP proxy: 127.0.0.1:%d → %s → %s:%d",
                 self._local_port, name, self._target_host, self._target_port)
        async with server:
            await server.serve_forever()

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Nova lokalna konekcija (npr. mstsc se konektovao)."""
        sid   = uuid.uuid4().hex[:8]
        event = asyncio.Event()
        self._sessions[sid] = writer
        self._ready[sid]    = event

        peer = writer.get_extra_info("peername", ("?", 0))
        log.info("Klijent konektovan: %s:%d → sesija %s", peer[0], peer[1], sid)

        # Traži konekciju od agenta (uključuje ACL proveru)
        ok = await self._router.proxy_connect(
            self._token, "tcp", self._target_host, self._target_port, sid
        )
        if not ok:
            log.warning("Sesija %s odbijena — agent offline ili ACL blokira tcp:%d",
                        sid, self._target_port)
            self._cleanup(sid)
            writer.close()
            return

        # Čekaj potvrdu od agenta (tcp_opened) max 10s
        try:
            await asyncio.wait_for(event.wait(), timeout=10)
        except asyncio.TimeoutError:
            log.warning("Sesija %s — agent nije odgovorio na tcp_open (timeout)", sid)
            self._cleanup(sid)
            writer.close()
            return

        # Relay: lokalni klijent → agent
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(32768), timeout=300)
                if not chunk:
                    break
                await self._router.send(self._token, {
                    "type":       "tcp_data",
                    "session_id": sid,
                    "data":       base64.b64encode(chunk).decode(),
                })
        except (asyncio.TimeoutError, Exception):
            pass
        finally:
            self._cleanup(sid)
            await self._router.send(self._token, {
                "type": "tcp_close", "session_id": sid
            })
            try:
                writer.close()
            except Exception:
                pass
            log.info("Sesija %s zatvorena (klijent)", sid)

    async def _on_agent_message(self, data: dict):
        """Prima poruke od agenta za ove sesije."""
        t   = data.get("type")
        sid = data.get("session_id", "")

        if t == "tcp_opened":
            event = self._ready.get(sid)
            if event:
                event.set()

        elif t == "tcp_data":
            writer = self._sessions.get(sid)
            if writer:
                try:
                    raw = base64.b64decode(data.get("data", ""))
                    writer.write(raw)
                    await writer.drain()
                except Exception as e:
                    log.debug("Greška pri pisanju klijentu [%s]: %s", sid, e)

        elif t == "tcp_close":
            writer = self._sessions.get(sid)
            self._cleanup(sid)
            if writer:
                try:
                    writer.close()
                except Exception:
                    pass
            log.info("Sesija %s zatvorena (agent)", sid)

    def _cleanup(self, sid: str):
        self._sessions.pop(sid, None)
        self._ready.pop(sid, None)


# ── Primer upotrebe ───────────────────────────────────────────────────────────

async def example():
    """
    Primer: RDP na bankomat + SSH na isti bankomat.

    Pokretanje:
        python portal_tcp_listener.py
    """
    from fastapi import FastAPI
    from outbound_agent.server import AgentRouter
    import uvicorn

    app    = FastAPI()
    router = AgentRouter(
        db_path="agents.db",
        admin_token="admin-tajni",
    )
    app.include_router(router.router)

    # Pretpostavljamo da "moj-token" ima tcp:3389 i tcp:22 u ACL
    TOKEN = "moj-token-ovde"

    rdp = PortalTcpProxy(router, TOKEN, local_port=13389,
                          target_host="localhost", target_port=3389)
    ssh = PortalTcpProxy(router, TOKEN, local_port=12222,
                          target_host="localhost", target_port=22)

    asyncio.create_task(rdp.start())
    asyncio.create_task(ssh.start())

    # RDP klijent: mstsc /v:127.0.0.1:13389
    # SSH klijent: ssh korisnik@127.0.0.1 -p 12222

    config = uvicorn.Config(app, host="0.0.0.0", port=8000)
    await uvicorn.Server(config).serve()


if __name__ == "__main__":
    asyncio.run(example())
