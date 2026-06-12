"""
Ferret GUI — system tray klijent.

Pokreni: ferret-gui
Zahteva: pystray, Pillow, keyring
"""
import json
import logging
import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

try:
    import keyring
except ImportError:
    keyring = None

try:
    from PIL import Image, ImageDraw
    import pystray
except ImportError:
    print("Nedostaje: pip install pystray Pillow")
    sys.exit(1)

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ferret.gui")

CONFIG_DIR  = Path.home() / ".config" / "ferret"
CONFIG_FILE = CONFIG_DIR / "config.json"
KEYRING_SVC = "ferret-tun"
AUTOSTART_DIR  = Path.home() / ".config" / "autostart"
AUTOSTART_FILE = AUTOSTART_DIR / "ferret-gui.desktop"


# ── Ikone ─────────────────────────────────────────────────────────────────────

def _make_icon(color: str) -> Image.Image:
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d   = ImageDraw.Draw(img)
    d.ellipse((4, 4, 60, 60), fill=color)
    # Šapica — tri tačke
    for cx, cy in [(22, 20), (32, 16), (42, 20)]:
        d.ellipse((cx-5, cy-5, cx+5, cy+5), fill="white")
    d.ellipse((22, 32, 42, 52), fill="white")
    return img

ICON_GRAY   = _make_icon("#888888")
ICON_YELLOW = _make_icon("#f0a000")
ICON_GREEN  = _make_icon("#22bb44")
ICON_RED    = _make_icon("#cc3333")


# ── Config ────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}


def save_config(cfg: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def get_token(key: str) -> str:
    if keyring:
        return keyring.get_password(KEYRING_SVC, key) or ""
    return ""


def set_token(key: str, value: str):
    if keyring:
        keyring.set_password(KEYRING_SVC, key, value)


# ── Autostart ─────────────────────────────────────────────────────────────────

def _ferret_gui_exe() -> str:
    return sys.argv[0]


def enable_autostart():
    AUTOSTART_DIR.mkdir(parents=True, exist_ok=True)
    exe = _ferret_gui_exe()
    AUTOSTART_FILE.write_text(
        f"[Desktop Entry]\n"
        f"Type=Application\n"
        f"Name=Ferret VPN\n"
        f"Exec={exe}\n"
        f"Hidden=false\n"
        f"NoDisplay=false\n"
        f"X-GNOME-Autostart-enabled=true\n"
    )


def disable_autostart():
    AUTOSTART_FILE.unlink(missing_ok=True)


def autostart_enabled() -> bool:
    return AUTOSTART_FILE.exists()


# ── Config dijalog ────────────────────────────────────────────────────────────

class ConfigDialog:
    def __init__(self, app: "FerretTray"):
        self._app = app
        self._win: tk.Tk | None = None

    def show(self):
        if self._win and self._win.winfo_exists():
            self._win.lift()
            return
        self._win = tk.Tk()
        self._win.title("Ferret VPN — Podešavanja")
        self._win.resizable(False, False)
        self._win.protocol("WM_DELETE_WINDOW", self._on_close)

        cfg = load_config()
        pad = {"padx": 10, "pady": 5}

        tk.Label(self._win, text="Server URL:").grid(row=0, column=0, sticky="e", **pad)
        self._server = tk.Entry(self._win, width=40)
        self._server.insert(0, cfg.get("server", ""))
        self._server.grid(row=0, column=1, **pad)

        tk.Label(self._win, text="Admin token:").grid(row=1, column=0, sticky="e", **pad)
        self._admin = tk.Entry(self._win, width=40, show="*")
        self._admin.insert(0, get_token("admin_token"))
        self._admin.grid(row=1, column=1, **pad)

        tk.Label(self._win, text="Agent token:").grid(row=2, column=0, sticky="e", **pad)
        self._agent = tk.Entry(self._win, width=40, show="*")
        self._agent.insert(0, get_token("agent_token"))
        self._agent.grid(row=2, column=1, **pad)

        self._autostart_var = tk.BooleanVar(value=autostart_enabled())
        tk.Checkbutton(self._win, text="Pokretanje sa sistemom",
                       variable=self._autostart_var).grid(
            row=3, column=0, columnspan=2, pady=5)

        self._autoconnect_var = tk.BooleanVar(value=cfg.get("autoconnect", True))
        tk.Checkbutton(self._win, text="Automatski se poveži pri pokretanju",
                       variable=self._autoconnect_var).grid(
            row=4, column=0, columnspan=2, pady=5)

        btn_frame = tk.Frame(self._win)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=10)
        tk.Button(btn_frame, text="Sačuvaj", command=self._save, width=12).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Otkaži", command=self._on_close, width=12).pack(side="left", padx=5)

        self._win.mainloop()

    def _save(self):
        server      = self._server.get().strip()
        admin_token = self._admin.get().strip()
        agent_token = self._agent.get().strip()

        if not server or not admin_token or not agent_token:
            messagebox.showerror("Greška", "Sva polja su obavezna.")
            return

        cfg = load_config()
        cfg["server"]      = server
        cfg["autoconnect"] = self._autoconnect_var.get()
        save_config(cfg)

        set_token("admin_token", admin_token)
        set_token("agent_token", agent_token)

        if self._autostart_var.get():
            enable_autostart()
        else:
            disable_autostart()

        messagebox.showinfo("Ferret VPN", "Podešavanja sačuvana.")
        self._on_close()

    def _on_close(self):
        if self._win:
            self._win.destroy()
            self._win = None


# ── Tray aplikacija ───────────────────────────────────────────────────────────

class FerretTray:
    def __init__(self):
        self._proc: subprocess.Popen | None = None
        self._state = "disconnected"  # disconnected | connecting | connected
        self._icon: pystray.Icon | None = None
        self._config_dialog = ConfigDialog(self)

    # ── Konekcija ─────────────────────────────────────────────────────────────

    def _set_state(self, state: str, title: str = ""):
        self._state = state
        icons = {
            "disconnected": ICON_GRAY,
            "connecting":   ICON_YELLOW,
            "connected":    ICON_GREEN,
            "error":        ICON_RED,
        }
        labels = {
            "disconnected": "Ferret VPN — nije povezan",
            "connecting":   "Ferret VPN — povezivanje...",
            "connected":    "Ferret VPN — povezan",
            "error":        f"Ferret VPN — greška: {title}",
        }
        if self._icon:
            self._icon.icon  = icons.get(state, ICON_GRAY)
            self._icon.title = labels.get(state, "Ferret VPN")
            self._icon.update_menu()

    def connect(self):
        if self._state in ("connecting", "connected"):
            return
        cfg         = load_config()
        server      = cfg.get("server", "")
        admin_token = get_token("admin_token")
        agent_token = get_token("agent_token")

        if not server or not admin_token or not agent_token:
            self._show_settings()
            return

        self._set_state("connecting")
        threading.Thread(target=self._connect_thread,
                         args=(server, admin_token, agent_token),
                         daemon=True).start()

    def _connect_thread(self, server: str, admin_token: str, agent_token: str):
        exe = Path(sys.argv[0]).parent / "ferret-tun"
        if not exe.exists():
            exe = "ferret-tun"

        cmd = ["sudo", str(exe),
               "--server", server,
               "--admin-token", admin_token,
               "--agent", agent_token]
        try:
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            # Čitaj stdout u pozadini, stderr posebno za greške
            import select, threading

            stderr_lines = []

            def _read_stderr():
                for line in self._proc.stderr:
                    stderr_lines.append(line.rstrip())
                    log.warning("ferret-tun stderr: %s", line.rstrip())

            threading.Thread(target=_read_stderr, daemon=True).start()

            connected = False
            for line in self._proc.stdout:
                log.debug("ferret-tun: %s", line.rstrip())
                if "VPN aktivan" in line:
                    connected = True
                    self._set_state("connected")
                elif "Greška" in line or "greška" in line or "ERROR" in line:
                    self._set_state("error", line.strip())
                    return

            self._proc.wait()
            if not connected:
                err = "; ".join(stderr_lines[-3:]) if stderr_lines else "ferret-tun nije startovao"
                self._set_state("error", err)
            else:
                self._set_state("disconnected")
        except Exception as e:
            self._set_state("error", str(e))

    def disconnect(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        self._set_state("disconnected")
        # Počisti TUN interfejs
        subprocess.run(["sudo", "ip", "link", "del", "ferret0"],
                       capture_output=True)

    # ── Tray meni ─────────────────────────────────────────────────────────────

    def _menu(self):
        if self._state == "connected":
            toggle = pystray.MenuItem("Prekini vezu", lambda: self.disconnect())
        elif self._state == "connecting":
            toggle = pystray.MenuItem("Povezivanje...", lambda: None, enabled=False)
        else:
            toggle = pystray.MenuItem("Poveži se", lambda: self.connect())

        return pystray.Menu(
            toggle,
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Podešavanja", lambda: threading.Thread(
                target=self._show_settings, daemon=True).start()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Izlaz", lambda: self._quit()),
        )

    def _show_settings(self):
        self._config_dialog.show()

    def _quit(self):
        self.disconnect()
        if self._icon:
            self._icon.stop()

    # ── Start ─────────────────────────────────────────────────────────────────

    def run(self):
        self._icon = pystray.Icon(
            name="ferret",
            icon=ICON_GRAY,
            title="Ferret VPN",
            menu=pystray.Menu(lambda: self._menu()),
        )

        # Auto-connect
        cfg = load_config()
        if cfg.get("autoconnect", False) and get_token("admin_token"):
            threading.Thread(target=self.connect, daemon=True).start()

        self._icon.run()


def main():
    FerretTray().run()
