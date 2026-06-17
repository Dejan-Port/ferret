"""
ferret-db — LUKS encrypted database container.

Štiti podatke od fizičke krađe: ključ se izvodi iz hardware
fingerprinta (HWID) i machine.key. Bez originalnog hardvera container
ostaje šifrovana gomila bajtova.

Komande:
  ferret-db init   [--size GB]   — jednom, kreira container
  ferret-db unlock               — pri svakom startu servera
  ferret-db lock                 — pri gašenju servera
  ferret-db status               — pregled stanja
  ferret-db reset                — re-key za novi hardware (audit logged)
"""

import argparse
import ctypes
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger("ferret.db")

DEFAULT_CONTAINER = "/db/ferret-data.img"
DEFAULT_MOUNT     = "/db/secure"
MAPPER_NAME       = "ferret-db"
SALT_PATH         = "/etc/ferret/db.salt"
HEADER_PATH       = "/etc/ferret/db.header"
MACHINE_KEY_PATH  = "/etc/ferret/machine.key"
AUDIT_LOG         = "/var/log/ferret-db-audit.log"

_libc = ctypes.CDLL("libc.so.6", use_errno=True)

# ── HWID prikupljanje (cached) ────────────────────────────────────────────────

_hwid_cache: str | None = None


def _read_safe(path: str) -> str:
    JUNK = {"none", "to be filled by o.e.m.", "default string",
            "not specified", "n/a", "", "0"}
    try:
        val = Path(path).read_text().strip()
        if val.lower() not in JUNK:
            return val
    except Exception:
        pass
    return ""


def _collect_network() -> list[str]:
    """
    Mrežni otisak servera — SVE stavke su obavezne.
    Ako bilo koja ne uspe, ferret-db odbija da nastavi.

    Skuplja:
      gw:       IP default gateway-a
      subnet:   lokalni subnet CIDR (npr. 192.168.1.100/24)
      gw_mac:   MAC adresa gateway-a iz ARP tabele
      hop2:     IP prvog hopa iza gateway-a (switch/ruter prema internetu)
    """
    parts = []

    # Putanja do interneta → gateway IP + interface
    r = subprocess.run(["ip", "route", "get", "1.1.1.1"],
                       capture_output=True, text=True, timeout=5)
    line = r.stdout.splitlines()[0] if r.stdout.strip() else ""
    cols = line.split()

    if "via" not in cols:
        log.error("Mrežni otisak: ne mogu da pronađem default gateway (ip route get 1.1.1.1)")
        sys.exit(1)

    gw_ip = cols[cols.index("via") + 1]
    iface = cols[cols.index("dev") + 1] if "dev" in cols else ""
    parts.append(f"gw:{gw_ip}")

    # Subnet lokalne mreže
    if not iface:
        log.error("Mrežni otisak: ne mogu da pronađem mrežni interfejs")
        sys.exit(1)

    r2 = subprocess.run(["ip", "-o", "-4", "addr", "show", iface],
                        capture_output=True, text=True, timeout=5)
    subnet = ""
    for aline in r2.stdout.splitlines():
        acols = aline.split()
        if len(acols) >= 4 and "/" in acols[3]:
            subnet = acols[3]
            break

    if not subnet:
        log.error("Mrežni otisak: ne mogu da pronađem subnet na interfejsu %s", iface)
        sys.exit(1)
    parts.append(f"subnet:{subnet}")

    # MAC gateway-a iz ARP tabele (ping da osvežimo cache)
    subprocess.run(["ping", "-c", "1", "-W", "1", gw_ip],
                   capture_output=True, timeout=3)
    r3 = subprocess.run(["ip", "neigh", "show", gw_ip],
                        capture_output=True, text=True, timeout=5)
    gw_mac = ""
    for nline in r3.stdout.splitlines():
        if "lladdr" in nline:
            ncols = nline.split()
            gw_mac = ncols[ncols.index("lladdr") + 1]
            break

    if not gw_mac:
        log.error("Mrežni otisak: ne mogu da pronađem MAC gateway-a %s iz ARP tabele", gw_ip)
        sys.exit(1)
    parts.append(f"gw_mac:{gw_mac}")

    # Prvi hop iza gateway-a (switch/ruter prema internetu), traceroute TTL=2
    r4 = subprocess.run(
        ["traceroute", "-n", "-m", "2", "-w", "2", "-q", "1", "1.1.1.1"],
        capture_output=True, text=True, timeout=15
    )
    hop2 = ""
    for tline in r4.stdout.splitlines():
        tline = tline.strip()
        if tline.startswith("2 "):
            hop_cols = tline.split()
            if len(hop_cols) >= 2 and hop_cols[1] != "*":
                hop2 = hop_cols[1]
            break

    if not hop2:
        log.error("Mrežni otisak: traceroute hop2 nije dostupan — "
                  "instalirajte traceroute i proverite da ICMP nije blokiran")
        sys.exit(1)
    parts.append(f"hop2:{hop2}")

    return parts


def collect_hwid() -> str:
    global _hwid_cache
    if _hwid_cache is not None:
        return _hwid_cache

    parts = []

    # ── Hardware identifikatori ───────────────────────────────────────────────
    for dmi in [
        "/sys/class/dmi/id/product_uuid",
        "/sys/class/dmi/id/board_serial",
        "/sys/class/dmi/id/product_serial",
        "/sys/class/dmi/id/chassis_serial",
    ]:
        val = _read_safe(dmi)
        if val:
            parts.append(val)

    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if "model name" in line:
                parts.append(line.split(":", 1)[1].strip())
                break
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["lsblk", "-ndo", "NAME,SERIAL"],
            capture_output=True, text=True, timeout=5
        )
        for line in r.stdout.splitlines()[:3]:
            cols = line.split()
            if len(cols) >= 2 and cols[1].lower() not in ("serial", ""):
                parts.append(cols[1])
    except Exception:
        pass

    if len(parts) < 2:
        log.error("Premalo hardware identifikatora (%d) — nije bezbedno nastaviti", len(parts))
        sys.exit(1)

    # ── Mrežni otisak (lokacija servera) ─────────────────────────────────────
    net_parts = _collect_network()
    parts.extend(net_parts)
    log.debug("HWID: %d hw + %d net komponenti", len(parts) - len(net_parts), len(net_parts))

    _hwid_cache = "|".join(parts)
    return _hwid_cache


# ── Key derivation + memory protection ───────────────────────────────────────

def derive_key(hwid: str, salt: bytes, machine_key: bytes) -> bytearray:
    """Izvodi LUKS passphrase, vraća mutable bytearray (za zeroing)."""
    material = hashlib.sha256(hwid.encode() + b":" + machine_key).digest()
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"ferret-db-key-v1",
    ).derive(material)
    return bytearray(raw.hex().encode())


def _zero(buf: bytearray):
    for i in range(len(buf)):
        buf[i] = 0


def _load_passphrase(salt_path: str = SALT_PATH,
                     key_path:  str = MACHINE_KEY_PATH) -> bytearray:
    if not Path(salt_path).exists():
        log.error("db.salt ne postoji — pokrenite: sudo ferret-db init")
        sys.exit(1)
    salt        = Path(salt_path).read_bytes()
    machine_key = Path(key_path).read_bytes() if Path(key_path).exists() else b""
    return derive_key(collect_hwid(), salt, machine_key)


# ── memfd key — nikad ne dodiruje disk ───────────────────────────────────────

def _key_fd(passphrase: bytearray) -> int:
    """Kreira anonimni memfd, upisuje passphrase, seek na 0. Vrača fd."""
    try:
        fd = os.memfd_create("ferret-key", flags=os.MFD_CLOEXEC)
    except AttributeError:
        # Python < 3.8 — tmpfs fallback, odmah unlink
        import tempfile
        fd, path = tempfile.mkstemp(dir="/dev/shm", prefix="fdb-")
        os.unlink(path)

    buf = (ctypes.c_char * len(passphrase)).from_buffer(passphrase)
    try:
        _libc.mlock(buf, ctypes.c_size_t(len(passphrase)))
    except Exception:
        pass

    os.write(fd, bytes(passphrase))
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


# ── Audit log (append-only) ───────────────────────────────────────────────────

def _audit(action: str, reason: str = ""):
    entry = {
        "ts":     time.strftime("%Y-%m-%dT%H:%M:%S"),
        "action": action,
        "reason": reason,
        "hwid":   hashlib.sha256(collect_hwid().encode()).hexdigest()[:16],
    }
    first_write = not Path(AUDIT_LOG).exists()
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        if first_write:
            subprocess.run(["chattr", "+a", AUDIT_LOG],
                           capture_output=True, timeout=5)
    except Exception as e:
        log.warning("Audit log greška: %s", e)


# ── LUKS helpers ──────────────────────────────────────────────────────────────

def _crypt(*args, key_fd: int = None, new_key_fd: int = None,
           header: bool = True, check: bool = True, timeout: int = 120):
    cmd = ["cryptsetup"] + list(args)
    if header and Path(HEADER_PATH).exists():
        cmd += ["--header", HEADER_PATH]
    pass_fds = []
    if key_fd is not None:
        cmd += ["--key-file", f"/proc/self/fd/{key_fd}"]
        pass_fds.append(key_fd)
    if new_key_fd is not None:
        cmd.append(f"/proc/self/fd/{new_key_fd}")
        pass_fds.append(new_key_fd)
    r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                       pass_fds=tuple(pass_fds))
    if check and r.returncode != 0:
        raise RuntimeError(r.stderr.decode().strip())
    return r


def _is_mounted(mount: str) -> bool:
    return subprocess.run(
        ["mountpoint", "-q", mount], capture_output=True, timeout=5
    ).returncode == 0


# ── Komande ───────────────────────────────────────────────────────────────────

def cmd_init(args):
    container = args.container
    mount     = args.mount
    size_gb   = args.size

    for tool in ("cryptsetup", "mkfs.ext4", "fallocate"):
        if subprocess.run(["which", tool], capture_output=True,
                          timeout=5).returncode != 0:
            log.error("Nedostaje alat: %s", tool)
            sys.exit(1)

    if Path(container).exists():
        log.error("Container već postoji: %s — koristite 'ferret-db reset'", container)
        sys.exit(1)

    Path(SALT_PATH).parent.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(32)
    Path(SALT_PATH).write_bytes(salt)
    os.chmod(SALT_PATH, 0o600)

    passphrase = _load_passphrase()
    fd = _key_fd(passphrase)

    try:
        Path(container).parent.mkdir(parents=True, exist_ok=True)
        log.info("Kreiram container %dGB: %s", size_gb, container)
        subprocess.run(["fallocate", "-l", f"{size_gb}G", container],
                       check=True, timeout=60)

        log.info("LUKS format (header: %s)...", HEADER_PATH)
        _crypt("luksFormat", "--batch-mode",
               "--type", "luks2",
               "--cipher", "aes-xts-plain64",
               "--key-size", "512",
               "--hash", "sha256",
               "--iter-time", "3000",
               "--header", HEADER_PATH,
               container,
               key_fd=fd, header=False)

        os.lseek(fd, 0, os.SEEK_SET)
        _crypt("luksOpen", "--header", HEADER_PATH,
               container, MAPPER_NAME,
               key_fd=fd, header=False)

        log.info("ext4 format...")
        subprocess.run(
            ["mkfs.ext4", "-q", "-L", "ferret-db", f"/dev/mapper/{MAPPER_NAME}"],
            check=True, timeout=60
        )

        Path(mount).mkdir(parents=True, exist_ok=True)
        subprocess.run(["mount", f"/dev/mapper/{MAPPER_NAME}", mount],
                       check=True, timeout=30)

        os.chmod(HEADER_PATH, 0o600)
        _audit("init")
        print(f"\nLUKS container inicijalizovan")
        print(f"  Container : {container} ({size_gb}GB)")
        print(f"  Header    : {HEADER_PATH}  ← čuvaj odvojeno!")
        print(f"  Montiran  : {mount}")

    finally:
        os.close(fd)
        _zero(passphrase)


def cmd_unlock(args):
    container = args.container
    mount     = args.mount

    if _is_mounted(mount):
        log.info("Već montirano: %s", mount)
        return

    if not Path(container).exists():
        log.error("Container ne postoji: %s", container)
        sys.exit(1)

    passphrase = _load_passphrase()
    fd = _key_fd(passphrase)

    try:
        if not Path(f"/dev/mapper/{MAPPER_NAME}").exists():
            r = _crypt("luksOpen", container, MAPPER_NAME,
                       key_fd=fd, check=False)
            if r.returncode != 0:
                log.error("HWID provera NEUSPEŠNA — hardware se promenio")
                log.error("Za re-key: sudo ferret-db reset")
                sys.exit(2)

        Path(mount).mkdir(parents=True, exist_ok=True)
        subprocess.run(["mount", f"/dev/mapper/{MAPPER_NAME}", mount],
                       check=True, timeout=30)
        log.info("Baze otključane: %s", mount)

    finally:
        os.close(fd)
        _zero(passphrase)


def cmd_lock(args):
    mount = args.mount

    if _is_mounted(mount):
        subprocess.run(["umount", mount], timeout=30, check=False)
    else:
        log.info("Nije montirano: %s", mount)

    r = _crypt("luksClose", MAPPER_NAME, check=False, header=False)
    if r.returncode == 0:
        log.info("Baze zaključane")
    else:
        log.debug("luksClose: %s", r.stderr.decode().strip())


def cmd_status(args):
    container = args.container
    mount     = args.mount

    c_exists = Path(container).exists()
    h_exists = Path(HEADER_PATH).exists()
    m_exists = Path(f"/dev/mapper/{MAPPER_NAME}").exists()
    mounted  = _is_mounted(mount)

    print(f"Container : {'OK' if c_exists else 'NE POSTOJI':12} {container}")
    print(f"Header    : {'OK' if h_exists else 'NE POSTOJI':12} {HEADER_PATH}")
    print(f"Mapper    : {'OTVOREN' if m_exists else 'ZATVOREN':12} /dev/mapper/{MAPPER_NAME}")
    print(f"Montiran  : {'DA' if mounted else 'NE':12} {mount}")

    if c_exists:
        mb = Path(container).stat().st_size // (1024 ** 2)
        print(f"Veličina  : {mb}MB")

    if mounted:
        r = subprocess.run(["df", "-h", mount], capture_output=True,
                           text=True, timeout=5)
        lines = r.stdout.strip().splitlines()
        if len(lines) > 1:
            print(f"Disk      : {lines[1]}")

    if Path(AUDIT_LOG).exists():
        try:
            lines = Path(AUDIT_LOG).read_text().strip().splitlines()
            if lines:
                last = json.loads(lines[-1])
                print(f"Posl.akcija: {last.get('action')} @ {last.get('ts')}")
        except Exception:
            pass


def cmd_reset(args):
    print("UPOZORENJE: Re-key menja hardware binding containera.")
    print("Koristite SAMO ako ste promenili hardware na originalnom serveru.")
    confirm = input("\nUnesite 'RESETUJ' za potvrdu: ").strip()
    if confirm != "RESETUJ":
        print("Prekinuto.")
        sys.exit(0)

    reason = input("Razlog (biće logovan): ").strip()
    if not reason:
        print("Razlog je obavezan.")
        sys.exit(1)

    old_pass = _load_passphrase()
    old_fd   = _key_fd(old_pass)

    try:
        # Provjeri da li stari ključ radi
        r = _crypt("luksOpen", args.container, MAPPER_NAME + "-reset",
                   key_fd=old_fd, check=False)
        if r.returncode != 0:
            log.error("Stari HWID ne otvara container — podaci nedostupni bez backup ključa")
            sys.exit(1)
        _crypt("luksClose", MAPPER_NAME + "-reset", check=False, header=False)

        new_salt = os.urandom(32)
        machine_key = Path(MACHINE_KEY_PATH).read_bytes() if Path(MACHINE_KEY_PATH).exists() else b""
        new_pass = derive_key(collect_hwid(), new_salt, machine_key)
        os.lseek(old_fd, 0, os.SEEK_SET)
        new_fd = _key_fd(new_pass)

        try:
            # Dodaj novi slot PRVO, pa tek onda briši stari (atomičnost)
            _crypt("luksAddKey", "--batch-mode", args.container,
                   key_fd=old_fd, new_key_fd=new_fd)
            # Sačuvaj novi salt pre brisanja starog slota
            Path(SALT_PATH).write_bytes(new_salt)
            os.lseek(old_fd, 0, os.SEEK_SET)
            _crypt("luksRemoveKey", "--batch-mode", args.container,
                   key_fd=old_fd)
            _audit("reset", reason)
            print("Re-key uspešan.")
        finally:
            os.close(new_fd)
            _zero(new_pass)

    finally:
        os.close(old_fd)
        _zero(old_pass)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("GREŠKA: ferret-db zahteva root — koristite: sudo ferret-db ...")
        sys.exit(1)

    p = argparse.ArgumentParser(
        description="ferret-db — LUKS encrypted database management (HWID bound)"
    )
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = p.add_subparsers(dest="cmd", required=True)

    def _add_paths(sp):
        sp.add_argument("--container", default=DEFAULT_CONTAINER)
        sp.add_argument("--mount",     default=DEFAULT_MOUNT)

    pi = sub.add_parser("init",   help="Inicijalizuj container (jednom)")
    pi.add_argument("--size", type=int, default=20, metavar="GB")
    _add_paths(pi)

    _add_paths(sub.add_parser("unlock", help="Otključaj pri startu"))
    _add_paths(sub.add_parser("lock",   help="Zaključaj pri gašenju"))
    _add_paths(sub.add_parser("status", help="Prikaži status"))

    pr = sub.add_parser("reset", help="Re-key za promenu hardwarea (audit logged)")
    pr.add_argument("--container", default=DEFAULT_CONTAINER)

    args = p.parse_args()
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s"
    )

    {
        "init":   cmd_init,
        "unlock": cmd_unlock,
        "lock":   cmd_lock,
        "status": cmd_status,
        "reset":  cmd_reset,
    }[args.cmd](args)


if __name__ == "__main__":
    main()
