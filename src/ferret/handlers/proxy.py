"""
Proxy handler — TCP i UDP tunel, agent strana.

Agent je "glup izvršilac" — otvara šta god portal traži.
Sigurnosna provera (ACL) se radi isključivo na portalu pre slanja zahteva.

Protokol:

  TCP:
    portal → agent: {"type": "tcp_open",  "session_id": "x", "host": "...", "port": 22}
    agent  → portal: {"type": "tcp_opened","session_id": "x", "ok": true}
    oba smera:       {"type": "tcp_data",  "session_id": "x", "data": "<base64>"}
    oba smera:       {"type": "tcp_close", "session_id": "x"}

  UDP:
    portal → agent: {"type": "udp_open",  "session_id": "x", "host": "...", "port": 161}
    agent  → portal: {"type": "udp_opened","session_id": "x", "ok": true}
    oba smera:       {"type": "udp_data",  "session_id": "x", "data": "<base64>"}
    portal → agent: {"type": "udp_close", "session_id": "x"}
    (UDP sesija se automatski zatvara posle UDP_TIMEOUT sekundi bez aktivnosti)
"""
import asyncio
import base64
import logging
from typing import Callable, Awaitable

log = logging.getLogger("ferret.proxy")

UDP_TIMEOUT = 120   # sekundi bez aktivnosti → zatvaranje UDP sesije
UDP_BUF     = 65535


class ProxyHandler:
    """
    Unified TCP + UDP proxy handler za agenta.

    Upotreba:
        proxy = ProxyHandler()
        proxy.register(agent)

    Agent propušta sve što mu portal pošalje.
    Šta portal sme da pošalje — kontroliše se ACL-om na portalu.
    """

    def __init__(self):
        self._tcp: dict[str, asyncio.StreamWriter]          = {}
        self._udp: dict[str, asyncio.DatagramTransport]     = {}
        self._udp_send: dict[str, Callable]                 = {}
        self._udp_timers: dict[str, asyncio.TimerHandle]    = {}

    def register(self, agent):
        agent.register_handler("tcp_open",  self._tcp_open,  capability="proxy")
        agent.register_handler("tcp_data",  self._tcp_data)
        agent.register_handler("tcp_close", self._tcp_close)
        agent.register_handler("udp_open",  self._udp_open,  capability="proxy")
        agent.register_handler("udp_data",  self._udp_data)
        agent.register_handler("udp_close", self._udp_close)

    # ── TCP ───────────────────────────────────────────────────────────────────

    async def _tcp_open(self, data: dict, send: Callable[..., Awaitable]):
        sid  = data.get("session_id", "")
        host = data.get("host", "localhost")
        port = int(data.get("port", 0))
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
            self._tcp[sid] = writer
            log.info("TCP sesija %s otvorena → %s:%d", sid, host, port)
            await send({"type": "tcp_opened", "session_id": sid, "ok": True})
            asyncio.create_task(self._tcp_relay(sid, reader, send))
        except Exception as e:
            log.error("tcp_open greška [%s]: %s", sid, e)
            await send({"type": "tcp_opened", "session_id": sid, "ok": False, "error": str(e)})

    async def _tcp_relay(self, sid: str, reader: asyncio.StreamReader, send):
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
            self._tcp.pop(sid, None)
            await send({"type": "tcp_close", "session_id": sid})
            log.info("TCP sesija %s zatvorena", sid)

    async def _tcp_data(self, data: dict, send):
        writer = self._tcp.get(data.get("session_id", ""))
        if not writer:
            return
        try:
            writer.write(base64.b64decode(data.get("data", "")))
            await writer.drain()
        except Exception as e:
            log.warning("tcp_data greška: %s", e)

    async def _tcp_close(self, data: dict, send):
        writer = self._tcp.pop(data.get("session_id", ""), None)
        if writer:
            try:
                writer.close()
            except Exception:
                pass

    # ── UDP ───────────────────────────────────────────────────────────────────

    async def _udp_open(self, data: dict, send: Callable[..., Awaitable]):
        sid  = data.get("session_id", "")
        host = data.get("host", "localhost")
        port = int(data.get("port", 0))
        try:
            loop = asyncio.get_running_loop()

            class _Protocol(asyncio.DatagramProtocol):
                def __init__(self, handler, sid, send_fn):
                    self._h    = handler
                    self._sid  = sid
                    self._send = send_fn

                def datagram_received(self, raw, addr):
                    asyncio.ensure_future(self._send({
                        "type":       "udp_data",
                        "session_id": self._sid,
                        "data":       base64.b64encode(raw).decode(),
                    }))
                    self._h._udp_reset_timer(self._sid, self._send)

                def error_received(self, exc):
                    log.warning("UDP error [%s]: %s", self._sid, exc)

                def connection_lost(self, exc):
                    self._h._udp.pop(self._sid, None)

            transport, _ = await loop.create_datagram_endpoint(
                lambda: _Protocol(self, sid, send),
                remote_addr=(host, port),
            )
            self._udp[sid]      = transport
            self._udp_send[sid] = send
            self._udp_reset_timer(sid, send)
            log.info("UDP sesija %s otvorena → %s:%d", sid, host, port)
            await send({"type": "udp_opened", "session_id": sid, "ok": True})

        except Exception as e:
            log.error("udp_open greška [%s]: %s", sid, e)
            await send({"type": "udp_opened", "session_id": sid, "ok": False, "error": str(e)})

    def _udp_reset_timer(self, sid: str, send):
        old = self._udp_timers.pop(sid, None)
        if old:
            old.cancel()
        loop = asyncio.get_event_loop()
        self._udp_timers[sid] = loop.call_later(
            UDP_TIMEOUT, lambda: asyncio.ensure_future(self._udp_expire(sid, send))
        )

    async def _udp_expire(self, sid: str, send):
        if sid in self._udp:
            log.info("UDP sesija %s istekla (timeout)", sid)
            self._udp.pop(sid, None).close()
            self._udp_send.pop(sid, None)
            await send({"type": "udp_close", "session_id": sid})

    async def _udp_data(self, data: dict, send):
        transport = self._udp.get(data.get("session_id", ""))
        if not transport:
            return
        try:
            raw = base64.b64decode(data.get("data", ""))
            transport.sendto(raw)
            self._udp_reset_timer(data["session_id"], send)
        except Exception as e:
            log.warning("udp_data greška: %s", e)

    async def _udp_close(self, data: dict, send):
        sid = data.get("session_id", "")
        t = self._udp_timers.pop(sid, None)
        if t:
            t.cancel()
        transport = self._udp.pop(sid, None)
        self._udp_send.pop(sid, None)
        if transport:
            try:
                transport.close()
            except Exception:
                pass
