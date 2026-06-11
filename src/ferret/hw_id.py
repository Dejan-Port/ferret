"""
Hardverski otisak mašine sa lokalnim tajnim ključem.

Princip:
    hw_id = HMAC(machine_key, hardware_values)

    machine_key — random 32-bajtni ključ koji se generiše pri prvom pokretanju
                  i čuva lokalno (/etc/ferret/machine.key, mode 0600).
                  Nikad ne napušta mašinu, nikad ne ide u token ni kroz mrežu.

    hardware_values — kombinacija vrednosti koje su fizički vezane za hardver:
                  BIOS verzija, DMI serijski brojevi, UUID, CPU serial, machine-id.

Zašto ovako:
    Napadač može da ima token + server secret + sve vidljive DMI vrednosti.
    Bez machine.key fajla ne može da reprodukuje hw_id ni na identičnom hardveru.
    Čak i klonirana mašina (isti BIOS, isti serijski brojevi) ima drugačiji
    machine.key jer je generisan random pri prvom pokretanju agenta.

Na RPi:
    /proc/cpuinfo Serial je jedinstven po čipu, burn-in pri proizvodnji.
    Zajedno sa machine.key — praktično nemoguće replicirati bez fizičkog pristupa.
"""
import hashlib
import hmac
import os
import platform
import stat
import uuid

_KEY_PATH = "/etc/ferret/machine.key"
_KEY_PATH_FALLBACK = os.path.expanduser("~/.ferret/machine.key")


def get() -> str:
    """
    Vraća 64-značni hex string koji jedinstveno identifikuje ovu mašinu.

    Deterministički — isti rezultat pri svakom pozivu na istoj mašini.
    Menja se samo ako se obriše machine.key (što zahteva root).
    """
    key     = _get_or_create_key()
    hw_data = _collect_hardware().encode()
    return hmac.new(key, hw_data, hashlib.sha256).hexdigest()


def short() -> str:
    """Prvih 16 znakova — za prikaz u UI-u."""
    return get()[:16]


def key_path() -> str:
    """Putanja machine.key fajla koji se koristi na ovoj mašini."""
    return _KEY_PATH if _can_write(_KEY_PATH) else _KEY_PATH_FALLBACK


# ── Lokalni ključ ─────────────────────────────────────────────────────────────

def _get_or_create_key() -> bytes:
    """Učitava ili generiše machine.key. Čuva root-only (0600)."""
    for path in (_KEY_PATH, _KEY_PATH_FALLBACK):
        try:
            with open(path, "rb") as f:
                key = f.read()
            if len(key) == 32:
                return key
        except OSError:
            pass

    # Nije pronađen — generišemo novi
    key  = os.urandom(32)
    path = _KEY_PATH if _can_write(os.path.dirname(_KEY_PATH)) else _KEY_PATH_FALLBACK

    os.makedirs(os.path.dirname(path), exist_ok=True)
    # Otvori sa mode=0600 pre pisanja
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)

    return key


def _can_write(path: str) -> bool:
    try:
        return os.access(path, os.W_OK)
    except Exception:
        return False


# ── Hardware vrednosti ────────────────────────────────────────────────────────

def _collect_hardware() -> str:
    """
    Skuplja sve dostupne hardware identifikatore.

    Koristi što više izvora — čak i ako neki nisu dostupni (virtuelne mašine,
    kontejneri), kombinacija ostalih + machine.key ostaje jedinstvena.
    """
    parts = []

    # machine-id — najstabilniji Linux identifikator, menja se samo reinstalacijom
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            v = open(path).read().strip()
            if v:
                parts.append(f"machine-id:{v}")
                break
        except OSError:
            pass

    # BIOS — jedinstven po matičnoj ploči, zahteva BIOS flash da se promeni
    for dmi_key, dmi_path in (
        ("bios-vendor",   "/sys/class/dmi/id/bios_vendor"),
        ("bios-version",  "/sys/class/dmi/id/bios_version"),
        ("bios-date",     "/sys/class/dmi/id/bios_date"),
        ("board-serial",  "/sys/class/dmi/id/board_serial"),
        ("board-name",    "/sys/class/dmi/id/board_name"),
        ("product-uuid",  "/sys/class/dmi/id/product_uuid"),
        ("product-serial","/sys/class/dmi/id/product_serial"),
        ("chassis-serial","/sys/class/dmi/id/chassis_serial"),
    ):
        try:
            v = open(dmi_path).read().strip()
            if v and v not in ("", "0", "None", "To Be Filled By O.E.M.",
                               "Not Specified", "Default string"):
                parts.append(f"{dmi_key}:{v}")
        except OSError:
            pass

    # RPi / ARM — CPU serial burn-in pri proizvodnji, jedinstven po čipu
    try:
        for line in open("/proc/cpuinfo"):
            if line.lower().startswith("serial"):
                v = line.split(":", 1)[1].strip()
                if v and v != "0000000000000000":
                    parts.append(f"cpu-serial:{v}")
                    break
    except OSError:
        pass

    # RPi device tree serial (noviji kerneli)
    try:
        with open("/sys/firmware/devicetree/base/serial-number", "rb") as f:
            v = f.read().rstrip(b"\x00").decode(errors="ignore").strip()
            if v:
                parts.append(f"dt-serial:{v}")
    except OSError:
        pass

    # MAC adresa — manje pouzdana (može se promeniti softverski), ali dodaje entropiju
    mac = hex(uuid.getnode())
    if mac != "0x0":
        parts.append(f"mac:{mac}")

    # Hostname kao fallback entropija
    parts.append(f"host:{platform.node()}")

    return "\n".join(parts)
