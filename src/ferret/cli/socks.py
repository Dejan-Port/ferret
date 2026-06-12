"""
ferret socks — SOCKS5 proxy kroz ferret tunel.

Primer:
    ferret socks \\
        --server https://ferret.servisport.rs \\
        --admin-token test123 \\
        --agent 23a10c1770ae... \\
        --local 1080

    Podesi browser: SOCKS5 proxy = localhost:1080
    Zatim otvori bilo koji sajt na agentovoj LAN mreži.
"""
import argparse
import asyncio
import logging
import struct

log = logging.getLogger("ferret.socks")

SOCKS_VER = 5
ATYP_IPV4   = 1
ATYP_DOMAIN = 3
ATYP_IPV6   = 4


def _ws_url(server: str, admin_token: str, agent: str, host: str, port: int) -> str:
    base = server.replace("https://", "wss://").replace("http://", "ws://")
    base = base.rstrip("/")
    return (f"{base}/agents/forward"
            f"?admin_token={admin_token}&agent={agent}&host={host}&port={port}")


async def _socks5_handshake(reader, writer) -> tuple[str, int] | None:
    # Greeting
    data = await reader.read(2)
    if len(data) < 2 or data[0] != SOCKS_VER:
        return None
    nmethods = data[1]
    await reader.read(nmethods)
    writer.write(b"\x05\x00")  # no auth
    await writer.drain()

    # Request
    header = await reader.read(4)
    if len(header) < 4 or header[0] != SOCKS_VER or header[1] != 1:
        return None
    atyp = header[3]

    if atyp == ATYP_IPV4:
        raw = await reader.read(4)
        host = ".".join(str(b) for b in raw)
    elif atyp == ATYP_DOMAIN:
        ln = (await reader.read(1))[0]
        host = (await reader.read(ln)).decode()
    elif atyp == ATYP_IPV6:
        raw = await reader.read(16)
        import ipaddress
        host = str(ipaddress.IPv6Address(raw))
    else:
        return None

    port_raw = await reader.read(2)
    port = struct.unpack("!H", port_raw)[0]

    # Success response
    writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    await writer.drain()
    return host, port


async def _handle(reader, writer, server: str, admin_token: str, agent: str):
    try:
        result = await _socks5_handshake(reader, writer)
        if not result:
            writer.close()
            return
        host, port = result
        log.info("SOCKS5 → %s:%d", host, port)

        try:
            import websockets
        except ImportError:
            log.error("Nedostaje: pip install websockets")
            writer.close()
            return

        ws_url = _ws_url(server, admin_token, agent, host, port)
        ssl_ctx = True if ws_url.startswith("wss://") else None

        async with websockets.connect(ws_url, ssl=ssl_ctx) as ws:
            async def pump_ws():
                try:
                    async for msg in ws:
                        chunk = msg if isinstance(msg, bytes) else msg.encode()
                        writer.write(chunk)
                        await writer.drain()
                except Exception:
                    pass
                finally:
                    try:
                        writer.close()
                    except Exception:
                        pass

            async def pump_tcp():
                try:
                    while True:
                        data = await reader.read(32768)
                        if not data:
                            break
                        await ws.send(data)
                except Exception:
                    pass
                finally:
                    try:
                        await ws.close()
                    except Exception:
                        pass

            await asyncio.gather(pump_ws(), pump_tcp())
    except Exception as e:
        log.error("SOCKS5 greška: %s", e)
        try:
            writer.close()
        except Exception:
            pass


async def _run(local_port: int, server: str, admin_token: str, agent: str):
    async def cb(reader, writer):
        asyncio.create_task(_handle(reader, writer, server, admin_token, agent))

    srv = await asyncio.start_server(cb, "127.0.0.1", local_port)
    addr = srv.sockets[0].getsockname()
    print(f"[ferret socks] SOCKS5 proxy na {addr[0]}:{addr[1]}")
    print(f"[ferret socks] Agent: {agent[:16]}...")
    print(f"[ferret socks] Podesi browser: SOCKS5 proxy = localhost:{addr[1]}")
    async with srv:
        await srv.serve_forever()


def main():
    p = argparse.ArgumentParser(description="ferret socks — SOCKS5 proxy kroz ferret tunel")
    p.add_argument("--server",      required=True, help="URL ferret servera")
    p.add_argument("--admin-token", required=True, help="Admin token")
    p.add_argument("--agent",       required=True, help="Token agenta")
    p.add_argument("--local",       type=int, default=1080, help="Lokalni SOCKS5 port (default: 1080)")
    p.add_argument("--log-level",   default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = p.parse_args()

    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    try:
        asyncio.run(_run(args.local, args.server, args.admin_token, args.agent))
    except KeyboardInterrupt:
        print("\n[ferret socks] Zaustavljeno.")
