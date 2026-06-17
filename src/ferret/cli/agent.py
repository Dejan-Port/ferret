"""
ferret — pokretanje agenta jednom komandom.

Upotreba:
    ferret --server wss://portal.rs/ws/agent --token abc123

    ferret --config /etc/ferret/agent.conf

    ferret --install-service   # instaliraj kao systemd servis

Config fajl format (/etc/ferret/agent.conf):
    server       = wss://portal.rs/ws/agent
    token        = abc123def456...
    ca_fingerprint = e3b0c44298fc...
    handlers     = proxy,tun
    log_level    = INFO
"""
import argparse
import configparser
import os
import sys

_DEFAULT_CONF_PATHS = (
    "/etc/ferret/agent.conf",
    os.path.expanduser("~/.ferret/agent.conf"),
    "agent.conf",
)


def main():
    p = argparse.ArgumentParser(
        prog="ferret",
        description="Outbound Agent — sigurni tunel do portala",
    )
    p.add_argument("--config",  default="", help="Putanja do config fajla")
    p.add_argument("--server",  default="", help="WebSocket URL servera")
    p.add_argument("--token",   default="", help="Agent token")
    p.add_argument("--handlers",default="", help="Handleri: proxy,tun,ami,sms (csv)")
    p.add_argument("--ca-fingerprint", default="",
                   help="SHA-256 CA otisak za pinning (iz bundle fajla)")
    p.add_argument("--log-level", default="",
                   choices=["", "DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--install-service", action="store_true",
                   help="Instaliraj kao systemd servis i izađi")
    p.add_argument("--no-encrypt", action="store_true",
                   help="Isključi aplikativnu enkripciju")
    p.add_argument("--cipher", default="",
                   choices=["", "chacha20", "aes256gcm"],
                   help="Cipher za enkripciju (default: chacha20)")

    args = p.parse_args()

    # Učitaj config fajl
    cfg = _load_config(args.config)

    server       = args.server          or cfg.get("server", "")
    token        = args.token           or cfg.get("token", "")
    handlers_str = args.handlers        or cfg.get("handlers", "proxy")
    ca_fp        = args.ca_fingerprint  or cfg.get("ca_fingerprint", "")
    cert_file    = cfg.get("cert_file", "")
    log_level    = args.log_level       or cfg.get("log_level", "INFO")
    encrypt      = not args.no_encrypt and cfg.get("encrypt", "true").lower() != "false"
    cipher       = args.cipher          or cfg.get("cipher", "chacha20")

    if not server or not token:
        print("Greška: --server i --token su obavezni (ili config fajl)", file=sys.stderr)
        print(f"Config fajl se traži na: {_DEFAULT_CONF_PATHS[0]}", file=sys.stderr)
        sys.exit(1)

    if args.install_service:
        _install_systemd(server, token, handlers_str, ca_fp, log_level)
        return

    _run(server, token, handlers_str, ca_fp, cert_file, log_level, encrypt, cipher)


def _load_config(explicit_path: str) -> dict:
    paths = [explicit_path] if explicit_path else _DEFAULT_CONF_PATHS
    for path in paths:
        if path and os.path.exists(path):
            cfg = configparser.ConfigParser()
            cfg.read_string("[agent]\n" + open(path).read())
            return dict(cfg["agent"])
    return {}


def _run(server, token, handlers_str, ca_fp, cert_file, log_level, encrypt, cipher="chacha20"):
    import logging

    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    from ferret.core import Agent
    from ferret import hw_id

    ssl_ctx = None
    if ca_fp and server.startswith("wss://"):
        ssl_ctx = _build_ssl_context(ca_fp, cert_file)

    agent = Agent(
        url=server,
        token=token,
        hw_id=hw_id.get(),
        encrypt=encrypt,
        cipher=cipher,
        ssl_context=ssl_ctx,
    )

    for h in [x.strip() for x in handlers_str.split(",") if x.strip()]:
        _attach_handler(agent, h)

    print(f"Outbound Agent")
    print(f"  Server    : {server}")
    print(f"  hw_id     : {hw_id.short()}")
    print(f"  Handleri  : {handlers_str}")
    print(f"  CA pin    : {'da' if ca_fp else 'ne'}")
    print(f"  Cert fajl : {cert_file or '—'}")
    print(f"  Enkripcija: {'da' if encrypt else 'ne'}")
    print()

    agent.run()


def _attach_handler(agent, name: str):
    try:
        if name == "proxy":
            from ferret.handlers.proxy import ProxyHandler
            ProxyHandler().register(agent)
        elif name == "tun":
            from ferret.handlers.tun import TunHandler
            TunHandler().register(agent)
        elif name == "ami":
            from ferret.handlers.ami import AmiHandler
            AmiHandler().register(agent)
        elif name == "sms":
            from ferret.handlers.sms import SmsHandler
            SmsHandler().register(agent)
        else:
            print(f"Nepoznat handler: {name}", file=sys.stderr)
    except ImportError as e:
        print(f"Handler '{name}' nije dostupan: {e}", file=sys.stderr)


def _build_ssl_context(ca_fp: str, cert_file: str = ""):
    """SSL kontekst koji veruje samo CA sa datim SHA-256 otiskom."""
    import ssl
    import hashlib

    import ssl, hashlib

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    # Klijentski sertifikat za mTLS
    if cert_file and os.path.exists(cert_file):
        ctx.load_cert_chain(cert_file)

    # CA fingerprint pinning — omotač koji proverava pri svakoj konekciji
    class _PinningContext:
        def __init__(self, inner_ctx, fp):
            self._ctx = inner_ctx
            self._fp  = fp

        def wrap_socket(self, *a, **kw):
            sock = self._ctx.wrap_socket(*a, **kw)
            der  = sock.getpeercert(binary_form=True)
            if der:
                fp = hashlib.sha256(der).hexdigest()
                if fp != self._fp:
                    sock.close()
                    raise ssl.SSLError(
                        f"CA fingerprint mismatch!\n"
                        f"  Očekivan: {self._fp}\n"
                        f"  Dobijen : {fp}"
                    )
            return sock

    return _PinningContext(ctx, ca_fp)


def _install_systemd(server, token, handlers, ca_fp, log_level):
    import getpass
    user    = getpass.getuser()
    bin_dir = os.path.dirname(sys.executable)
    cmd     = f"{bin_dir}/ferret"

    conf_dir  = "/etc/ferret"
    conf_path = f"{conf_dir}/agent.conf"

    conf_content = f"server = {server}\ntoken = {token}\nhandlers = {handlers}\nlog_level = {log_level}\n"
    if ca_fp:
        conf_content += f"ca_fingerprint = {ca_fp}\n"

    unit = f"""[Unit]
Description=Outbound Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
ExecStart={cmd} --config {conf_path}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    try:
        os.makedirs(conf_dir, exist_ok=True)
        # Config fajl samo root može da čita
        fd = os.open(conf_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, conf_content.encode())
        os.close(fd)

        with open("/etc/systemd/system/ferret.service", "w") as f:
            f.write(unit)

        os.system("systemctl daemon-reload")
        os.system("systemctl enable --now ferret")
        print(f"Agent instaliran i pokrenut.")
        print(f"  Config : {conf_path}")
        print(f"  Status : systemctl status ferret")
        print(f"  Logovi : journalctl -u ferret -f")
    except PermissionError:
        print(f"Potreban je root. Pokušaj: sudo {' '.join(sys.argv)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
