"""
ferret tun — Layer 3 VPN klijent (admin strana).

Zahteva root / CAP_NET_ADMIN (za kreiranje TUN interfejsa).

Primer:
    sudo ferret tun \\
        --server https://ferret.servisport.rs \\
        --admin-token test123 \\
        --agent 23a10c1770ae...

    Nakon pokretanja:
    - ping 192.168.1.100  → radi
    - browser na http://192.168.1.1 → radi
    - SSH na 192.168.1.x → radi
"""
import argparse
import asyncio
import base64
import fcntl
import json
import logging
import os
import random
import struct
import subprocess
import sys

log = logging.getLogger("ferret.tun")

TUNSETIFF = 0x400454CA
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

TUN_IFACE      = "ferret0"
TUN_IP         = "10.99.0.1"
TUN_GW         = "10.99.0.2"  # agent dobija ovu adresu
MTU            = 1400
REMAP_SUBNET   = "10.8.0.0/24"  # klijent koristi ovaj subnet umesto LAN subneta


def _ws_url(server: str, admin_token: str, agent: str) -> str:
    base = server.replace("https://", "wss://").replace("http://", "ws://")
    base = base.rstrip("/")
    return f"{base}/agents/tun?admin_token={admin_token}&agent={agent}"


def _run(*cmd):
    subprocess.run(cmd, check=True, capture_output=True)


def _create_tun(iface: str) -> object:
    tun = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH14s", iface.encode(), IFF_TUN | IFF_NO_PI, b"\x00" * 14)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun


def _setup_iface(iface: str, local_ip: str, remote_ip: str, routes: list[str]):
    _run("ip", "link", "set", iface, "mtu", str(MTU), "up")
    _run("ip", "addr", "add", f"{local_ip}/32", "peer", remote_ip, "dev", iface)
    for route in routes:
        _run("ip", "route", "add", route, "dev", iface)
    log.info("TUN interfejs %s podignut | lokalna IP: %s | gateway: %s", iface, local_ip, remote_ip)


def _get_local_subnets() -> list:
    """Vraća listu lokalnih subneta (osim loopback i TUN interfejsa)."""
    import ipaddress
    subnets = []
    try:
        out = subprocess.check_output(["ip", "-o", "-4", "addr"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                if iface.startswith(("lo", "tun", "ferret", "docker", "virbr")):
                    continue
                try:
                    subnets.append(ipaddress.IPv4Network(parts[3], strict=False))
                except ValueError:
                    pass
    except Exception:
        pass
    return subnets


def _filter_conflicting_routes(agent_subnets: list[str]) -> list[str]:
    """Uklanja rute koje se poklapaju sa lokalnim mrežama."""
    import ipaddress
    local = _get_local_subnets()
    safe = []
    for s in agent_subnets:
        try:
            net = ipaddress.IPv4Network(s, strict=False)
            conflict = any(net.overlaps(loc) for loc in local)
            if conflict:
                log.warning("Ruta %s konflikuje sa lokalnom mrežom — preskačem", s)
            else:
                safe.append(s)
        except ValueError:
            pass
    return safe


def _setup_dns(iface: str, dns_server: str):
    """Postavi DNS server za ferret interfejs via systemd-resolved."""
    if not dns_server:
        return
    try:
        dns_arg = dns_server.replace(":", "#")
        r = subprocess.run(["resolvectl", "dns", iface, dns_arg],
                           capture_output=True, timeout=5)
        if r.returncode != 0:
            log.warning("resolvectl dns: %s", r.stderr.decode().strip())
        log.info("Split DNS: %s → %s", iface, dns_server)
    except Exception as e:
        log.warning("DNS setup nije uspeo: %s", e)


def _teardown_dns(iface: str):
    try:
        subprocess.run(["resolvectl", "revert", iface], capture_output=True)
    except Exception:
        pass


def _teardown(iface: str, routes: list[str]):
    _teardown_dns(iface)
    for route in routes:
        try:
            _run("ip", "route", "del", route, "dev", iface)
        except Exception:
            pass
    try:
        _run("ip", "link", "del", iface)
    except Exception:
        pass


async def _run_tun(server: str, admin_token: str, agent: str,
                   dns_override: str = "", forced_routes: list[str] | None = None):
    try:
        import websockets
    except ImportError:
        log.error("Nedostaje: pip install websockets")
        return

    ws_url  = _ws_url(server, admin_token, agent)
    ssl_ctx = True if ws_url.startswith("wss://") else None

    tun    = None
    routes = []

    _headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Origin": server.rstrip("/"),
    }

    async with websockets.connect(ws_url, ssl=ssl_ctx,
                                   extra_headers=_headers,
                                   ping_interval=None,
                                   open_timeout=15) as ws:

        async def _keepalive():
            try:
                while True:
                    await asyncio.sleep(random.uniform(3, 8))
                    await ws.ping()
            except Exception:
                pass
        # Pošalji tun_request — server prosleđuje agentu
        await ws.send(json.dumps({
            "type":        "tun_request",
            "client_ip":   TUN_IP,
            "agent_ip":    TUN_GW,
            "mtu":         MTU,
            "remap_subnet": REMAP_SUBNET,
        }))

        # Čekaj tun_config od agenta (server prosledi)
        raw = await asyncio.wait_for(ws.recv(), timeout=15)
        cfg = json.loads(raw)
        if cfg.get("type") != "tun_ready":
            log.error("Očekivan tun_ready, dobio: %s", cfg.get("type"))
            return

        agent_subnets = cfg.get("subnets", [])
        log.info("Agent subneti: %s", agent_subnets)

        # Kreiraj TUN interfejs
        try:
            tun = _create_tun(TUN_IFACE)
        except OSError:
            subprocess.run(["ip", "link", "del", TUN_IFACE], capture_output=True)
            tun = _create_tun(TUN_IFACE)
        except PermissionError:
            log.error("Potreban je root: sudo ferret tun ...")
            return

        # --route override: korisnik bira koje rute idu kroz tunel
        if forced_routes:
            routes = forced_routes
            log.info("Rute (override): %s", routes)
        else:
            routes = agent_subnets or [TUN_GW + "/32"]
        _setup_iface(TUN_IFACE, TUN_IP, TUN_GW, routes)

        dns_server = dns_override or cfg.get("dns", "")
        if dns_server:
            _setup_dns(TUN_IFACE, dns_server)

        log.info("VPN aktivan | lokalna IP: %s | rute: %s", TUN_IP, routes)
        print(f"[ferret tun] VPN aktivan | lokalna IP: {TUN_IP}", flush=True)

        loop = asyncio.get_event_loop()

        async def read_tun():
            while True:
                pkt = await loop.run_in_executor(None, tun.read, MTU + 4)
                if not pkt:
                    break
                await ws.send(json.dumps({
                    "type": "tun_packet",
                    "data": base64.b64encode(pkt).decode(),
                }))

        async def read_ws():
            async for msg in ws:
                try:
                    data = json.loads(msg)
                    if data.get("type") == "tun_packet":
                        pkt = base64.b64decode(data.get("data", ""))
                        await loop.run_in_executor(None, tun.write, pkt)
                except Exception as e:
                    log.warning("WS poruka greška: %s", e)

        try:
            await asyncio.gather(read_tun(), read_ws(), _keepalive())
        finally:
            _teardown(TUN_IFACE, routes)
            if tun:
                tun.close()


async def _run_tun_reconnect(server: str, admin_token: str, agent: str,
                             dns_override: str = "", forced_routes: list[str] | None = None):
    while True:
        try:
            await _run_tun(server, admin_token, agent, dns_override, forced_routes)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            log.warning("Konekcija prekinuta: %s — pokušavam za 5s", e)
            await asyncio.sleep(5)


def main():
    p = argparse.ArgumentParser(description="ferret tun — Layer 3 VPN (zahteva root)")
    p.add_argument("--server",      required=True, help="URL ferret servera")
    p.add_argument("--admin-token", required=True, help="Admin token")
    p.add_argument("--agent",       required=True, help="Token agenta")
    p.add_argument("--dns",         default="", help="DNS server za office mrežu (npr. 192.168.1.100)")
    p.add_argument("--route",       action="append", dest="routes", metavar="CIDR",
                   help="Ruta kroz tunel (može više puta). Npr: --route 192.168.1.100/32 --route 192.168.1.235/32")
    p.add_argument("--log-level",   default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = p.parse_args()

    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    if os.geteuid() != 0:
        print("GREŠKA: ferret tun zahteva root. Pokrenite sa: sudo ferret tun ...")
        sys.exit(1)

    try:
        asyncio.run(_run_tun_reconnect(args.server, args.admin_token, args.agent, args.dns, args.routes))
    except KeyboardInterrupt:
        print("\n[ferret tun] Zaustavljeno.")
