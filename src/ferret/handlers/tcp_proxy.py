"""
TCP Proxy handler — tunel za bilo koji TCP servis (SSH, RDP, HTTP...).

Agent strana: prima tcp_connect od portala, otvara lokalni TCP, relayuje podatke.
Portal strana: TCP listener koji prihvata klijente i prosljeđuje kroz WebSocket.

Protokol (JSON poruke):

  portal → agent:
    {"type": "tcp_connect", "session_id": "abc", "host": "localhost", "port": 22}
    {"type": "tcp_data",    "session_id": "abc", "data": "<base64>"}
    {"type": "tcp_close",   "session_id": "abc"}

  agent → portal:
    {"type": "tcp_connected", "session_id": "abc", "ok": true}
    {"type": "tcp_data",      "session_id": "abc", "data": "<base64>"}
    {"type": "tcp_close",     "session_id": "abc"}
"""
import asyncio
import base64
import logging
from typing import Callable, Awaitable

log = logging.getLogger("ferret.tcp_proxy")

# Aktivne sesije: session_id → asyncio.StreamWriter
_sessions: dict[str, asyncio.StreamWriter] = {}


class TcpProxyHandler:
    """
    Dozvoljava portalu da tuneluje TCP saobraćaj kroz agenta.

    Tipična upotreba — SSH bez otvaranja portova:
        proxy = TcpProxyHandler(allowed_ports={22})
        proxy.register(agent)

    Za RDP + SSH:
        proxy = TcpProxyHandler(allowed_ports={22, 3389})
        proxy.register(agent)

    Bez ograničenja (pažljivo):
        proxy = TcpProxyHandler()
        proxy.register(agent)
    """

    def __init__(self, allowed_ports: set[int] = None):
        # None = sve dozvoljeno; set = samo navedeni portovi
        self._allowed = allowed_ports

    def register(self, agent):
        agent.register_handler("tcp_connect", self._handle_connect, capability="tcp_proxy")
        agent.register_handler("tcp_data",    self._handle_data)
        agent.register_handler("tcp_close",   self._handle_close)

    async def _handle_connect(self, data: dict, send: Callable[..., Awaitable]):
        sid  = data.get("session_id", "")
        host = data.get("host", "localhost")
        port = int(data.get("port", 22))

        if self._allowed is not None and port not in self._allowed:
            log.warning("tcp_connect odbijen — port %d nije dozvoljen", port)
            await send({"type": "tcp_connected", "session_id": sid, "ok": False,
                        "error": f"Port {port} nije dozvoljen"})
            return

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
            _sessions[sid] = writer
            log.info("TCP sesija %s otvorena → %s:%d", sid, host, port)
            await send({"type": "tcp_connected", "session_id": sid, "ok": True})

            # Čita iz lokalnog TCP-a i šalje portalu
            asyncio.create_task(self._relay_to_portal(sid, reader, send))

        except Exception as e:
            log.error("tcp_connect greška [%s]: %s", sid, e)
            await send({"type": "tcp_connected", "session_id": sid, "ok": False, "error": str(e)})

    async def _relay_to_portal(self, sid: str, reader: asyncio.StreamReader, send):
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(32768), timeout=300)
                if not chunk:
                    break
                await send({
                    "type":       "tcp_data",
                    "session_id": sid,
                    "data":       base64.b64encode(chunk).decode(),
                })
        except Exception:
            pass
        finally:
            _sessions.pop(sid, None)
            await send({"type": "tcp_close", "session_id": sid})
            log.info("TCP sesija %s zatvorena (relay završen)", sid)

    async def _handle_data(self, data: dict, send):
        sid = data.get("session_id", "")
        writer = _sessions.get(sid)
        if not writer:
            return
        try:
            raw = base64.b64decode(data.get("data", ""))
            writer.write(raw)
            await writer.drain()
        except Exception as e:
            log.warning("tcp_data greška [%s]: %s", sid, e)

    async def _handle_close(self, data: dict, send):
        sid = data.get("session_id", "")
        writer = _sessions.pop(sid, None)
        if writer:
            try:
                writer.close()
            except Exception:
                pass
            log.info("TCP sesija %s zatvorena (portal zahtev)", sid)
