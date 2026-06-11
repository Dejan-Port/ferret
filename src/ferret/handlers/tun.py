"""
TUN handler — pravi Layer 3 VPN tunel, agent strana.

Kreira virtuelni mrežni interfejs i tuneluje sve IP pakete kroz WebSocket.
Opciono propušta celu lokalnu mrežu agenta (ne samo sam agent).

Zahteva: Linux, root ili CAP_NET_ADMIN

Protokol:
  portal → agent: {"type": "tun_config", "ip": "10.8.0.2", "gateway": "10.8.0.1",
                    "dns": "10.8.0.1", "mtu": 1500, "routes": ["0.0.0.0/0"],
                    "portal_ip": "1.2.3.4", "lan_access": true}
  agent  → portal: {"type": "tun_ready", "subnets": ["192.168.1.0/24"]}
  oba smera:       {"type": "tun_packet", "data": "<base64 IP paket>"}
  portal → agent:  {"type": "tun_down"}
"""
import asyncio
import base64
import fcntl
import ipaddress
import logging
import os
import struct
import subprocess
from typing import Callable, Awaitable

log = logging.getLogger("ferret.tun")

TUNSETIFF   = 0x400454CA
IFF_TUN     = 0x0001
IFF_NO_PI   = 0x1000
MTU_DEFAULT = 1500


class TunHandler:
    """
    Layer 3 VPN handler za agenta.

    Parametri:
        iface      - naziv TUN interfejsa (default: "tun-agent")
        lan_iface  - LAN interfejs za forwarding (default: auto-detect)
                     Ako je None, forwarding se ne uključuje i LAN nije dostupan.
    """

    def __init__(self, iface: str = "tun-agent", lan_iface: str = "auto"):
        self._iface      = iface
        self._lan_iface  = lan_iface  # "auto" = detectuj, None = isključi LAN
        self._tun        = None
        self._mtu        = MTU_DEFAULT
        self._routes_added: list[str] = []
        self._orig_gateway: str = ""
        self._lan_masq_active = False

    def register(self, agent):
        agent.register_handler("tun_config", self._handle_config, capability="tun")
        agent.register_handler("tun_packet", self._handle_packet)
        agent.register_handler("tun_down",   self._handle_down)
        agent.add_background(self._read_loop)

    # ── Konfiguracija ─────────────────────────────────────────────────────────

    async def _handle_config(self, data: dict, send: Callable[..., Awaitable]):
        ip         = data.get("ip", "")
        gateway    = data.get("gateway", "")
        dns        = data.get("dns", "")
        mtu        = int(data.get("mtu", MTU_DEFAULT))
        routes     = data.get("routes", [])
        portal_ip  = data.get("portal_ip", "")
        lan_access = data.get("lan_access", False)

        try:
            self._mtu = mtu
            self._tun = open("/dev/net/tun", "r+b", buffering=0)
            ifr = struct.pack("16sH14s", self._iface.encode(), IFF_TUN | IFF_NO_PI, b"\x00"*14)
            fcntl.ioctl(self._tun, TUNSETIFF, ifr)

            _run("ip", "addr", "add", f"{ip}/32", "peer", gateway, "dev", self._iface)
            _run("ip", "link", "set", self._iface, "mtu", str(mtu), "up")

            if dns:
                _set_dns(dns)

            for route in routes:
                if route in ("0.0.0.0/0", "::/0"):
                    self._orig_gateway = _get_default_gateway()
                    if self._orig_gateway and portal_ip:
                        # WebSocket konekcija ka portalu mora ići starim putem
                        _run("ip", "route", "add", f"{portal_ip}/32",
                             "via", self._orig_gateway)
                        self._routes_added.append(f"{portal_ip}/32")
                        log.info("Izuzetak od tunela: %s via %s", portal_ip, self._orig_gateway)
                _run("ip", "route", "add", route, "dev", self._iface)
                self._routes_added.append(route)

            # ── LAN forwarding ────────────────────────────────────────────────
            local_subnets = []
            if lan_access and self._lan_iface is not None:
                lan_iface = (
                    _detect_lan_iface() if self._lan_iface == "auto"
                    else self._lan_iface
                )
                if lan_iface:
                    local_subnets = _get_local_subnets(lan_iface)
                    if local_subnets:
                        _enable_forwarding(self._iface, lan_iface)
                        self._lan_masq_active = True
                        log.info("LAN forwarding: %s → %s, subneti: %s",
                                 self._iface, lan_iface, local_subnets)
                    else:
                        log.warning("LAN: nije pronađen subnet na %s", lan_iface)
                else:
                    log.warning("LAN: nije detektovan LAN interfejs")

            log.info("TUN %s up — IP: %s", self._iface, ip)
            await send({"type": "tun_ready", "subnets": local_subnets})

        except Exception as e:
            log.error("tun_config greška: %s", e)
            await send({"type": "tun_ready", "ok": False, "error": str(e), "subnets": []})

    # ── Čitanje paketa iz kernela → portal ───────────────────────────────────

    async def _read_loop(self, send: Callable[..., Awaitable]):
        while self._tun is None:
            await asyncio.sleep(0.2)

        loop   = asyncio.get_running_loop()
        tun_fd = self._tun.fileno()
        queue  = asyncio.Queue(maxsize=512)

        def _on_readable():
            try:
                pkt = os.read(tun_fd, self._mtu + 4)
                queue.put_nowait(pkt)
            except Exception:
                pass

        loop.add_reader(tun_fd, _on_readable)
        try:
            while True:
                pkt = await queue.get()
                await send({
                    "type": "tun_packet",
                    "data": base64.b64encode(pkt).decode(),
                })
        finally:
            loop.remove_reader(tun_fd)

    # ── Primanje paketa od portala → kernel ──────────────────────────────────

    async def _handle_packet(self, data: dict, send):
        if self._tun is None:
            return
        try:
            os.write(self._tun.fileno(), base64.b64decode(data.get("data", "")))
        except Exception as e:
            log.debug("tun_packet write greška: %s", e)

    # ── Gašenje ───────────────────────────────────────────────────────────────

    async def _handle_down(self, data: dict, send):
        self._teardown()

    def _teardown(self):
        try:
            for route in self._routes_added:
                try:
                    _run("ip", "route", "del", route)
                except Exception:
                    pass
            self._routes_added.clear()
            if self._lan_masq_active:
                try:
                    _disable_forwarding(self._iface)
                    self._lan_masq_active = False
                except Exception:
                    pass
            _run("ip", "link", "set", self._iface, "down")
            if self._tun:
                self._tun.close()
                self._tun = None
            log.info("TUN %s down", self._iface)
        except Exception as e:
            log.warning("TUN teardown greška: %s", e)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _detect_lan_iface() -> str:
    """Vraća naziv primarnog LAN interfejsa (nije tun/lo/docker)."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True
        )
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                if not iface.startswith(("tun", "lo", "docker", "br-", "virbr")):
                    return iface
    except Exception:
        pass
    return ""


def _get_local_subnets(iface: str) -> list[str]:
    """Vraća IPv4 subnete na datom interfejsu, bez loopback i link-local."""
    subnets = []
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show", "dev", iface], text=True
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                try:
                    net = ipaddress.IPv4Network(parts[3], strict=False)
                    if not net.is_loopback and not net.is_link_local:
                        subnets.append(str(net))
                except ValueError:
                    pass
    except Exception:
        pass
    return subnets


def _enable_forwarding(tun_iface: str, lan_iface: str):
    """Uključuje IP forwarding i NAT masquerade za LAN."""
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")
    _run("iptables", "-t", "nat", "-A", "POSTROUTING",
         "-o", lan_iface, "-j", "MASQUERADE",
         "-m", "comment", "--comment", f"ferret-{tun_iface}")
    _run("iptables", "-A", "FORWARD",
         "-i", tun_iface, "-o", lan_iface, "-j", "ACCEPT",
         "-m", "comment", "--comment", f"ferret-{tun_iface}")
    _run("iptables", "-A", "FORWARD",
         "-i", lan_iface, "-o", tun_iface,
         "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT",
         "-m", "comment", "--comment", f"ferret-{tun_iface}")


def _disable_forwarding(tun_iface: str):
    """Uklanja iptables pravila koja je agent dodao."""
    try:
        out = subprocess.check_output(
            ["iptables-save"], text=True
        )
        comment = f"ferret-{tun_iface}"
        for line in out.splitlines():
            if comment in line and line.startswith("-A"):
                table = "filter"
                if "-t nat" in line or "POSTROUTING" in line:
                    table = "nat"
                del_line = line.replace("-A", "-D", 1)
                try:
                    _run("iptables", "-t", table, *del_line.split()[1:])
                except Exception:
                    pass
    except Exception as e:
        log.warning("iptables cleanup greška: %s", e)


def _run(*args):
    r = subprocess.run(list(args), capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {r.stderr.strip()}")


def _get_default_gateway() -> str:
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return ""


def _set_dns(dns_ip: str):
    try:
        with open("/etc/resolv.conf", "r") as f:
            existing = f.read()
        if f"nameserver {dns_ip}" not in existing:
            with open("/etc/resolv.conf", "w") as f:
                f.write(f"nameserver {dns_ip}\n" + existing)
    except Exception as e:
        log.warning("DNS podešavanje neuspešno: %s", e)
