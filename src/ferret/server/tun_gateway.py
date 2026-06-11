"""
TUN gateway — server strana Layer 3 VPN-a.

Za svaki konektovani agent kreira tun interfejs na serveru,
dodeljuje IP iz pool-a i rutira pakete između agenata i interneta.

ACL pravila se primenjuju kao iptables chain po agentu i mogu se
menjati u hodu (hot-reload) bez prekidanja konekcije.

Zahteva:
  - Linux, root ili CAP_NET_ADMIN
  - IP forwarding: sysctl -w net.ipv4.ip_forward=1
  - Za internet pristup: NAT na izlaznom interfejsu

Upotreba:
    gw = TunGateway(subnet="10.8.0.0/24", internet_iface="eth0")
    gw.attach(router)  # router je AgentRouter instanca

Svaki agent dobija:
  - Svoju IP adresu iz pool-a (npr. 10.8.0.2)
  - Server IP je 10.8.0.1
  - Opciono default route (full tunnel) ili samo subnet route (split tunnel)
  - ACL filter: samo dozvoljeni proto:port prolaze
"""
import asyncio
import base64
import fcntl
import ipaddress
import logging
import os
import struct
import subprocess
import time
from typing import Callable

log = logging.getLogger("ferret.tun_gateway")

TUNSETIFF = 0x400454CA
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000


class TunGateway:
    """
    Server-side VPN gateway.

    Parametri:
        subnet         - IP pool za agente, npr. "10.8.0.0/24"
                         Server uzima prvu adresu (.1), agenti dobijaju .2, .3...
        internet_iface - izlazni interfejs za NAT (npr. "eth0"); None = bez NAT-a
        dns            - DNS server koji se šalje agentima (default: server IP)
        full_tunnel    - True = sav saobraćaj agenta kroz tunel (default route)
                         False = samo subnet (split tunnel)
        mtu            - MTU za TUN interfejse
    """

    def __init__(
        self,
        subnet: str = "10.8.0.0/24",
        internet_iface: str = None,
        public_ip: str = "",
        dns: str = None,
        full_tunnel: bool = True,
        mtu: int = 1500,
    ):
        net              = ipaddress.IPv4Network(subnet, strict=False)
        hosts            = list(net.hosts())
        self._server_ip  = str(hosts[0])
        self._public_ip  = public_ip or _detect_public_ip()
        self._pool       = [str(h) for h in hosts[1:]]
        self._used: dict[str, str] = {}
        self._tuns: dict[str, object] = {}
        self._dns        = dns or self._server_ip
        self._full_tunnel = full_tunnel
        self._mtu        = mtu
        self._net_iface  = internet_iface
        self._nat_active = False
        self._send_fns: dict[str, Callable] = {}
        self._agent_subnets: dict[str, list[str]] = {}
        self._tun_start_time: dict[str, float] = {}
        self._registry = None
        self._audit    = None  # postavlja attach()

    def attach(self, agent_router):
        """Kači se na AgentRouter — prima sve poruke od agenata."""
        self._registry = agent_router._registry
        self._audit    = agent_router._audit
        orig = agent_router._on_message

        async def _interceptor(token: str, data: dict):
            t = data.get("type")
            if t == "tun_ready":
                subnets = data.get("subnets", [])
                if subnets:
                    await self._on_tun_ready(token, subnets)
                else:
                    log.info("Agent %s TUN spreman (bez LAN subneta)", token[:8])
            elif t == "tun_packet":
                await self._agent_to_tun(token, data)
            elif orig:
                await orig(token, data)

        agent_router._on_message = _interceptor

        # Hook: agent online/offline
        orig_set_online = agent_router._registry.set_online

        def _set_online_hook(token, online, capabilities=None):
            orig_set_online(token, online, capabilities)
            if online and capabilities and "tun" in capabilities:
                if agent_router._connections.get(token):
                    asyncio.create_task(
                        self._on_agent_connect(token, agent_router.send)
                    )
            elif not online and token in self._used:
                asyncio.create_task(self._on_agent_disconnect(token))

        agent_router._registry.set_online = _set_online_hook

        # Hook: ACL pravila promenjena → hot-reload iptables
        orig_set_rules = agent_router._registry.set_rules

        def _set_rules_hook(token, rules):
            orig_set_rules(token, rules)
            if token in self._used:
                asyncio.create_task(self._reload_acl(token))

        agent_router._registry.set_rules = _set_rules_hook

    # ── Agent se konektovao ───────────────────────────────────────────────────

    async def _on_agent_connect(self, token: str, send_fn: Callable):
        if not self._pool:
            log.error("IP pool iscrpljen!")
            return

        ip = self._pool.pop(0)
        self._used[token] = ip
        self._send_fns[token] = send_fn

        iface = f"tun-{token[:6]}"
        try:
            tun = _create_tun(iface, self._mtu)
            self._tuns[token] = tun

            _run("ip", "addr", "add", f"{self._server_ip}/32", "peer", ip, "dev", iface)
            _run("ip", "link", "set", iface, "mtu", str(self._mtu), "up")
            _run("ip", "route", "add", f"{ip}/32", "dev", iface)

            if self._net_iface and not self._nat_active:
                _setup_nat(self._net_iface)
                self._nat_active = True

            # ACL chain za ovaj interfejs
            acl = self._registry.get_acl(token) if self._registry else None
            _acl_chain_create(iface, acl)

            routes = ["0.0.0.0/0"] if self._full_tunnel else []
            await send_fn(token, {
                "type":       "tun_config",
                "ip":         ip,
                "gateway":    self._server_ip,
                "dns":        self._dns,
                "mtu":        self._mtu,
                "routes":     routes,
                "portal_ip":  self._public_ip,
                "lan_access": True,
            })

            asyncio.create_task(self._tun_to_agent(token, tun, send_fn))
            self._tun_start_time[token] = time.time()
            agent_info = self._registry.get(token) if self._registry else {}
            if self._audit:
                self._audit.log("tun_start", token=token,
                                agent_name=agent_info.get("name", "") if agent_info else "",
                                detail={"vpn_ip": ip,
                                        "acl": acl.to_json() if acl else "[]"})
            log.info("VPN sesija: %s → agent %s | ACL: %s",
                     ip, token[:8], acl.to_json() if acl else "[]")

        except Exception as e:
            log.error("TUN setup greška za %s: %s", token[:8], e)
            self._pool.insert(0, ip)
            self._used.pop(token, None)

    async def _on_tun_ready(self, token: str, subnets: list[str]):
        """Kada agent javi svoje LAN subnete, dodaje rute na serveru."""
        iface = f"tun-{token[:6]}"
        added = []
        for subnet in subnets:
            try:
                _run("ip", "route", "add", subnet, "dev", iface)
                added.append(subnet)
                log.info("LAN ruta: %s → agent %s (via %s)", subnet, token[:8], iface)
            except Exception as e:
                log.warning("Ruta %s greška: %s", subnet, e)
        if added:
            self._agent_subnets[token] = added

    async def _reload_acl(self, token: str):
        """Hot-reload ACL pravila bez diskonektovanja agenta."""
        if token not in self._used:
            return
        iface = f"tun-{token[:6]}"
        acl   = self._registry.get_acl(token) if self._registry else None
        _acl_chain_reload(iface, acl)
        log.info("ACL reload: agent %s | nova pravila: %s",
                 token[:8], acl.to_json() if acl else "[]")

    async def _on_agent_disconnect(self, token: str):
        ip    = self._used.pop(token, None)
        tun   = self._tuns.pop(token, None)
        iface = f"tun-{token[:6]}"
        self._send_fns.pop(token, None)

        for subnet in self._agent_subnets.pop(token, []):
            try:
                _run("ip", "route", "del", subnet, "dev", iface)
            except Exception:
                pass

        _acl_chain_delete(iface)

        if tun:
            try:
                tun.close()
            except Exception:
                pass
        try:
            _run("ip", "link", "del", iface)
        except Exception:
            pass
        if ip:
            self._pool.append(ip)
            duration = int(time.time() - self._tun_start_time.pop(token, time.time()))
            agent_info = self._registry.get(token) if self._registry else {}
            if self._audit:
                self._audit.log("tun_stop", token=token,
                                agent_name=agent_info.get("name", "") if agent_info else "",
                                detail={"vpn_ip": ip,
                                        "subnets": self._agent_subnets.get(token, []),
                                        "duration_sec": duration})
            log.info("VPN sesija zatvorena: %s (agent %s, trajanje: %ds)",
                     ip, token[:8], duration)

    # ── Relay paketa ──────────────────────────────────────────────────────────

    async def _tun_to_agent(self, token: str, tun, send_fn: Callable):
        loop  = asyncio.get_running_loop()
        fd    = tun.fileno()
        queue = asyncio.Queue(maxsize=512)

        def _on_readable():
            try:
                pkt = os.read(fd, self._mtu + 4)
                queue.put_nowait(pkt)
            except Exception:
                pass

        loop.add_reader(fd, _on_readable)
        try:
            while token in self._tuns:
                pkt = await asyncio.wait_for(queue.get(), timeout=30)
                await send_fn(token, {
                    "type": "tun_packet",
                    "data": base64.b64encode(pkt).decode(),
                })
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log.debug("tun_to_agent greška: %s", e)
        finally:
            loop.remove_reader(fd)

    async def _agent_to_tun(self, token: str, data: dict):
        tun = self._tuns.get(token)
        if not tun:
            return
        try:
            pkt = base64.b64decode(data.get("data", ""))
            os.write(tun.fileno(), pkt)
        except Exception as e:
            log.debug("agent_to_tun greška: %s", e)

    # ── Status ────────────────────────────────────────────────────────────────

    @property
    def sessions(self) -> dict[str, str]:
        return {k[:8]: v for k, v in self._used.items()}

    @property
    def session_info(self) -> list[dict]:
        return [
            {
                "token":   k[:8],
                "ip":      v,
                "subnets": self._agent_subnets.get(k, []),
            }
            for k, v in self._used.items()
        ]


# ── ACL iptables helpers ──────────────────────────────────────────────────────

def _chain_name(iface: str) -> str:
    # iptables chain ime max 29 znakova; tun-abc123 → OA-abc123
    return f"OA-{iface[4:]}"  # "tun-abc123" → "OA-abc123"


def _acl_chain_create(iface: str, acl):
    """Kreira iptables chain za agent interfejs i dodaje pravila."""
    chain = _chain_name(iface)
    try:
        _run("iptables", "-N", chain)
    except RuntimeError:
        # Chain već postoji — flush
        _run("iptables", "-F", chain)
    _fill_chain(chain, acl)
    # Jump iz FORWARD na ovaj chain za saobraćaj koji dolazi sa interfejsa
    try:
        _run("iptables", "-I", "FORWARD", "1", "-i", iface, "-j", chain)
    except RuntimeError:
        pass


def _acl_chain_reload(iface: str, acl):
    """Atomski reload: flush chain + ubaci nova pravila. Bez diskonekta."""
    chain = _chain_name(iface)
    try:
        _run("iptables", "-F", chain)
        _fill_chain(chain, acl)
    except Exception as e:
        log.warning("ACL reload greška za %s: %s", iface, e)


def _acl_chain_delete(iface: str):
    """Briše chain i jump pravilo pri diskonektu agenta."""
    chain = _chain_name(iface)
    try:
        _run("iptables", "-D", "FORWARD", "-i", iface, "-j", chain)
    except Exception:
        pass
    try:
        _run("iptables", "-F", chain)
        _run("iptables", "-X", chain)
    except Exception:
        pass


def _fill_chain(chain: str, acl):
    """
    Puni chain pravilima iz ACL objekta.

    Pravila:
        tcp:80   → -p tcp --dport 80 -j ACCEPT
        udp:161  → -p udp --dport 161 -j ACCEPT
        tcp:*    → -p tcp -j ACCEPT
        udp:*    → -p udp -j ACCEPT
        *:*      → -j ACCEPT (sve)

    Bez pravila (prazan ACL) → DROP sve (chain je prazan, default DROP).
    """
    if not acl:
        return

    allow_all = False
    for rule in acl._rules:
        proto, port = rule
        if proto == "*":
            allow_all = True
            break

    if allow_all:
        _run("iptables", "-A", chain, "-j", "ACCEPT")
        return

    # Uvek propusti established/related
    _run("iptables", "-A", chain,
         "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")

    for proto, port in acl._rules:
        if proto == "tcp" or proto == "udp":
            if port is None:
                _run("iptables", "-A", chain, "-p", proto, "-j", "ACCEPT")
            else:
                _run("iptables", "-A", chain,
                     "-p", proto, "--dport", str(port), "-j", "ACCEPT")

    # Default DROP — sve što nije eksplicitno dozvoljeno
    _run("iptables", "-A", chain, "-j", "DROP")


# ── Ostali helpers ────────────────────────────────────────────────────────────

def _create_tun(iface: str, mtu: int):
    tun = open("/dev/net/tun", "r+b", buffering=0)
    ifr = struct.pack("16sH14s", iface.encode(), IFF_TUN | IFF_NO_PI, b"\x00" * 14)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun


def _run(*args):
    r = subprocess.run(list(args), capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {r.stderr.strip()}")


def _detect_public_ip() -> str:
    try:
        import urllib.request
        with urllib.request.urlopen("https://api4.my-ip.io/ip", timeout=3) as r:
            return r.read().decode().strip()
    except Exception:
        pass
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def _setup_nat(iface: str):
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")
    try:
        _run("iptables", "-t", "nat", "-A", "POSTROUTING",
             "-o", iface, "-j", "MASQUERADE")
        _run("iptables", "-A", "FORWARD", "-i", "tun+",
             "-o", iface, "-j", "ACCEPT")
        _run("iptables", "-A", "FORWARD", "-i", iface,
             "-o", "tun+", "-m", "state",
             "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
        log.info("NAT aktivan na %s", iface)
    except Exception as e:
        log.warning("iptables greška: %s", e)
