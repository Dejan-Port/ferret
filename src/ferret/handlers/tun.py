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
        self._remap_subnet: str = ""   # "10.8.0.0/24" → remap LAN na ovaj subnet
        self._dns_task: asyncio.Task | None = None

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
        routes         = data.get("routes", [])
        portal_ip      = data.get("portal_ip", "")
        lan_access     = data.get("lan_access", False)
        remap_subnet   = data.get("remap_subnet", "")

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
            local_subnets  = []
            report_subnets = []
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
                        if remap_subnet:
                            # NETMAP: remap LAN subnet na drugi opseg
                            for lan_sub in local_subnets:
                                _enable_netmap(self._iface, lan_sub, remap_subnet)
                            self._remap_subnet = remap_subnet
                            report_subnets = [remap_subnet] + local_subnets
                            log.info("Subnet remap: %s → %s", local_subnets, remap_subnet)
                        else:
                            report_subnets = local_subnets
                    else:
                        log.warning("LAN: nije pronađen subnet na %s", lan_iface)
                else:
                    log.warning("LAN: nije detektovan LAN interfejs")

            # DNS rewrite mapa: 192.168.1.x → 10.8.0.x
            dns_rewrite = None
            if remap_subnet and local_subnets:
                try:
                    old_p = bytes(int(x) for x in local_subnets[0].split(".")[:3])
                    new_p = bytes(int(x) for x in remap_subnet.split("/")[0].rsplit(".", 1)[0].split("."))
                    dns_rewrite = (old_p, new_p)
                except Exception:
                    pass

            self._dns_task = asyncio.create_task(_run_dns_proxy(ip, rewrite=dns_rewrite))

            log.info("TUN %s up — IP: %s | DNS proxy: %s:5353", self._iface, ip, ip)
            await send({"type": "tun_ready", "subnets": report_subnets, "dns": f"{ip}:5353"})

        except Exception as e:
            log.error("tun_config greška: %s", e)
            await send({"type": "tun_ready", "ok": False, "error": str(e), "subnets": []})

    # ── Čitanje paketa iz kernela → portal ───────────────────────────────────

    async def _read_loop(self, send: Callable[..., Awaitable]):
        while True:
            while self._tun is None:
                await asyncio.sleep(0.2)

            loop   = asyncio.get_running_loop()
            tun    = self._tun
            tun_fd = tun.fileno()
            queue  = asyncio.Queue(maxsize=512)

            def _on_readable():
                try:
                    pkt = os.read(tun_fd, self._mtu + 4)
                    queue.put_nowait(pkt)
                except Exception:
                    pass

            loop.add_reader(tun_fd, _on_readable)
            try:
                while self._tun is tun:
                    try:
                        pkt = await asyncio.wait_for(queue.get(), timeout=0.5)
                        await send({
                            "type": "tun_packet",
                            "data": base64.b64encode(pkt).decode(),
                        })
                    except asyncio.TimeoutError:
                        pass
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
            if self._dns_task:
                self._dns_task.cancel()
                self._dns_task = None
            if self._lan_masq_active:
                try:
                    _disable_forwarding(self._iface)
                    self._lan_masq_active = False
                except Exception:
                    pass
            if self._tun:
                self._tun.close()
                self._tun = None
            _run("ip", "link", "del", self._iface)
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


def _enable_netmap(tun_iface: str, lan_subnet: str, remap_subnet: str):
    """NETMAP: paketi koji dolaze na remap_subnet → prevodi u lan_subnet i obratno."""
    comment = f"ferret-remap-{tun_iface}"
    # Dolazni paketi kroz TUN: dst remap → lan
    _run("iptables", "-t", "nat", "-A", "PREROUTING",
         "-i", tun_iface, "-d", remap_subnet,
         "-j", "NETMAP", "--to", lan_subnet,
         "-m", "comment", "--comment", comment)
    # Odlazni paketi prema TUN: src lan → remap
    _run("iptables", "-t", "nat", "-A", "POSTROUTING",
         "-o", tun_iface, "-s", lan_subnet,
         "-j", "NETMAP", "--to", remap_subnet,
         "-m", "comment", "--comment", comment)


def _enable_forwarding(tun_iface: str, lan_iface: str):
    """Uključuje IP forwarding i NAT masquerade za LAN."""
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")
    _run("iptables", "-t", "nat", "-I", "POSTROUTING", "2",
         "-o", tun_iface, "-j", "ACCEPT",
         "-m", "comment", "--comment", f"ferret-{tun_iface}")
    _run("iptables", "-t", "nat", "-A", "POSTROUTING",
         "-o", lan_iface, "-j", "MASQUERADE",
         "-m", "comment", "--comment", f"ferret-{tun_iface}")
    _run("iptables", "-I", "INPUT", "1",
         "-i", tun_iface, "-j", "ACCEPT",
         "-m", "comment", "--comment", f"ferret-{tun_iface}")
    _run("iptables", "-I", "FORWARD", "1",
         "-i", tun_iface, "-o", lan_iface, "-j", "ACCEPT",
         "-m", "comment", "--comment", f"ferret-{tun_iface}")
    _run("iptables", "-I", "FORWARD", "1",
         "-i", lan_iface, "-o", tun_iface,
         "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT",
         "-m", "comment", "--comment", f"ferret-{tun_iface}")


def _disable_forwarding(tun_iface: str):
    """Uklanja iptables pravila koja je agent dodao."""
    try:
        out = subprocess.check_output(["iptables-save"], text=True)
        comments = [f"ferret-{tun_iface}", f"ferret-remap-{tun_iface}"]
        table = "filter"
        for line in out.splitlines():
            if line.startswith("*"):
                table = line[1:].strip()
                continue
            if not line.startswith("-A"):
                continue
            if any(c in line for c in comments):
                del_line = line.replace("-A", "-D", 1)
                try:
                    _run("iptables", "-t", table, *del_line.split())
                except Exception:
                    pass
    except Exception as e:
        log.warning("iptables cleanup greška: %s", e)


def _get_local_dns() -> str:
    """Vraća DNS server za klijente — ako je loopback, koristi pravi LAN IP."""
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        if ip.startswith("127."):
                            # Loopback DNS — vrati pravi LAN IP mašine
                            lan = _detect_lan_iface()
                            if lan:
                                out = subprocess.check_output(
                                    ["ip", "-o", "-4", "addr", "show", "dev", lan],
                                    text=True
                                )
                                for l in out.splitlines():
                                    p = l.split()
                                    if len(p) >= 4:
                                        return p[3].split("/")[0]
                            return ip
                        return ip
    except Exception:
        pass
    return ""


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


async def _run_dns_proxy(bind_ip: str, upstream: str = "", port: int = 5353,
                         rewrite: tuple[bytes, bytes] | None = None):
    """UDP DNS proxy: prima upite na bind_ip:port, prosleđuje na upstream:53.
    rewrite=(old_prefix, new_prefix) — rewrite IP adresa u DNS odgovorima."""
    import socket as _socket
    if not upstream:
        upstream = _get_local_dns() or "8.8.8.8"
    loop = asyncio.get_running_loop()

    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    try:
        srv.bind((bind_ip, port))
    except OSError as e:
        log.warning("DNS proxy bind %s:%s neuspešan: %s", bind_ip, port, e)
        srv.close()
        return
    srv.setblocking(False)

    fwd = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    fwd.setblocking(False)

    pending: dict[bytes, tuple] = {}

    def _dns_local_resolve(name: str) -> bytes | None:
        """Pokušaj lokalno razrešavanje (mDNS/NetBIOS/hosts) za jednočlana imena."""
        import socket as _socket
        try:
            infos = _socket.getaddrinfo(name, None, _socket.AF_INET)
            if infos:
                return _socket.inet_aton(infos[0][4][0])
        except Exception:
            pass
        # Fallback: NetBIOS broadcast via nmblookup
        try:
            out = subprocess.check_output(["nmblookup", name], text=True, timeout=3)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and not parts[0].startswith("name") \
                        and not parts[0].startswith("added") \
                        and not parts[0].startswith("Got") \
                        and not parts[0].startswith("Socket"):
                    try:
                        return _socket.inet_aton(parts[0])
                    except Exception:
                        pass
        except Exception:
            pass
        return None

    def _build_dns_response(query: bytes, ip_bytes: bytes) -> bytes:
        """Gradi sintetički DNS A odgovor za datu IP adresu."""
        tid = query[:2]
        flags = b'\x81\x80'  # QR=1 AA=0 RD=1 RA=1, NOERROR
        qdcount = query[4:6]
        ancount = b'\x00\x01'
        nscount = b'\x00\x00'
        arcount = b'\x00\x00'
        question = query[12:]
        # A record: name pointer 0xc00c, type A, class IN, TTL 30, rdlen 4, rdata
        answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04' + ip_bytes
        return tid + flags + qdcount + ancount + nscount + arcount + question + answer

    def _parse_qname(data: bytes) -> str:
        """Izvuci ime upita iz DNS paketa."""
        try:
            pos = 12
            labels = []
            while pos < len(data):
                ln = data[pos]
                if ln == 0:
                    break
                labels.append(data[pos+1:pos+1+ln].decode(errors="replace"))
                pos += 1 + ln
            return ".".join(labels)
        except Exception:
            return ""

    def on_client():
        try:
            data, addr = srv.recvfrom(4096)
            name = _parse_qname(data)
            # Jednočlano ime (bez tačke) — pokušaj lokalni NSS pre DNS-a
            if name and "." not in name:
                ip_b = _dns_local_resolve(name)
                if ip_b:
                    if rewrite and ip_b[:3] == rewrite[0]:
                        ip_b = rewrite[1] + ip_b[3:]
                    srv.sendto(_build_dns_response(data, ip_b), addr)
                    log.debug("DNS local: %s → %s", name, ".".join(str(b) for b in ip_b))
                    return
            pending[data[:2]] = addr
            fwd.sendto(data, (upstream, 53))
        except Exception:
            pass

    def on_upstream():
        try:
            data, _ = fwd.recvfrom(4096)
            tid = data[:2]
            if rewrite:
                data = data.replace(rewrite[0], rewrite[1])
            addr = pending.pop(tid, None)
            if addr:
                srv.sendto(data, addr)
        except Exception:
            pass

    loop.add_reader(srv.fileno(), on_client)
    loop.add_reader(fwd.fileno(), on_upstream)
    log.info("DNS proxy aktivan: %s:53 → %s:53", bind_ip, upstream)
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        loop.remove_reader(srv.fileno())
        loop.remove_reader(fwd.fileno())
        srv.close()
        fwd.close()
        log.info("DNS proxy ugašen")


def _set_dns(dns_ip: str):
    try:
        with open("/etc/resolv.conf", "r") as f:
            existing = f.read()
        if f"nameserver {dns_ip}" not in existing:
            with open("/etc/resolv.conf", "w") as f:
                f.write(f"nameserver {dns_ip}\n" + existing)
    except Exception as e:
        log.warning("DNS podešavanje neuspešno: %s", e)
