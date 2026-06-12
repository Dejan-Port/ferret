"""
ferret forward — TCP port forward kroz ferret tunel.

Primer:
    ferret forward \\
        --server https://ferret.servisport.rs \\
        --admin-token test123 \\
        --agent 23a10c1770ae... \\
        192.168.1.1:80 \\
        --local 8080

    Zatim otvori http://localhost:8080 u browseru.
"""
import argparse
import asyncio
import logging
import sys

log = logging.getLogger("ferret.forward")


def _ws_url(server: str, admin_token: str, host: str, port: int, agent: str = "") -> str:
    base = server.replace("https://", "wss://").replace("http://", "ws://")
    base = base.rstrip("/")
    if agent:
        return (f"{base}/agents/forward"
                f"?admin_token={admin_token}&agent={agent}&host={host}&port={port}")
    else:
        return (f"{base}/agents/local-forward"
                f"?admin_token={admin_token}&host={host}&port={port}")


async def _handle(reader, writer, ws_url: str):
    try:
        import websockets
    except ImportError:
        log.error("Nedostaje: pip install websockets")
        writer.close()
        return

    import ssl as _ssl
    ssl_ctx = True if ws_url.startswith("wss://") else None

    try:
        async with websockets.connect(ws_url, ssl=ssl_ctx) as ws:
            async def pump_ws():
                try:
                    async for msg in ws:
                        if isinstance(msg, bytes):
                            writer.write(msg)
                            await writer.drain()
                        elif isinstance(msg, str):
                            writer.write(msg.encode())
                            await writer.drain()
                except Exception:
                    pass
                finally:
                    writer.close()

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
                    await ws.close()

            await asyncio.gather(pump_ws(), pump_tcp())
    except Exception as e:
        log.error("Forward greška: %s", e)
        try:
            writer.close()
        except Exception:
            pass


async def _run(local_port: int, ws_url: str):
    async def client_cb(reader, writer):
        peer = writer.get_extra_info("peername")
        log.info("Konekcija od %s", peer)
        asyncio.create_task(_handle(reader, writer, ws_url))

    srv = await asyncio.start_server(client_cb, "127.0.0.1", local_port)
    addr = srv.sockets[0].getsockname()
    print(f"[ferret forward] Slušam na {addr[0]}:{addr[1]}")
    print(f"[ferret forward] Tunel → {ws_url}")
    async with srv:
        await srv.serve_forever()


def main():
    p = argparse.ArgumentParser(description="ferret forward — TCP port forward kroz tunel")
    p.add_argument("target", help="host:port na agentovoj mreži (npr. 192.168.1.1:80)")
    p.add_argument("--server",      required=True, help="URL ferret servera (https://...)")
    p.add_argument("--admin-token", required=True, help="Admin token")
    p.add_argument("--agent",       default="", help="Token agenta (opciono; bez agenta = server koristi svoju mrežu)")
    p.add_argument("--local",       type=int, default=0,
                   help="Lokalni port (default: isti kao target port)")
    p.add_argument("--log-level",   default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = p.parse_args()

    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    if ":" not in args.target:
        p.error("target mora biti host:port")

    host, _, port_str = args.target.rpartition(":")
    try:
        port = int(port_str)
    except ValueError:
        p.error("Neispravan port u target")

    local = args.local or port
    ws_url = _ws_url(args.server, args.admin_token, host, port, args.agent)

    try:
        asyncio.run(_run(local, ws_url))
    except KeyboardInterrupt:
        print("\n[ferret forward] Zaustavljeno.")
