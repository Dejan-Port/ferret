"""
ferret-server — pokretanje portal servera jednom komandom.

Upotreba:
    ferret-server --admin-token moj-tajni-token

    ferret-server \\
        --host :: --port 8000 \\
        --admin-token xyz \\
        --secret hw-kljuc-32-znaka \\
        --public-url wss://portal.mojafirma.rs/ws/agent \\
        --db /var/lib/ferret/agents.db

Opcije se mogu zadati i kroz env varijable:
    OA_ADMIN_TOKEN, OA_SECRET, OA_PUBLIC_URL, OA_DB, OA_PORT
"""
import argparse
import os
import sys


def main():
    p = argparse.ArgumentParser(
        prog="ferret-server",
        description="Outbound Agent portal server",
    )
    p.add_argument("--host",        default=os.getenv("OA_HOST", "::"))
    p.add_argument("--port",        default=int(os.getenv("OA_PORT", "8000")), type=int)
    p.add_argument("--admin-token", default=os.getenv("OA_ADMIN_TOKEN", ""),
                   help="Bearer token za admin API (obavezno za produkciju)")
    p.add_argument("--secret",      default=os.getenv("OA_SECRET", ""),
                   help="HMAC secret za hardware-bound tokene (min 32 znaka)")
    p.add_argument("--public-url",  default=os.getenv("OA_PUBLIC_URL", ""),
                   help="Javni WebSocket URL servera (npr. wss://portal.rs/ws/agent)")
    p.add_argument("--db",          default=os.getenv("OA_DB", "agents.db"),
                   help="Putanja do SQLite baze")
    p.add_argument("--install-service", action="store_true",
                   help="Instaliraj kao systemd servis i izađi")
    p.add_argument("--log-level",   default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    args = p.parse_args()

    if args.install_service:
        _install_systemd(args)
        return

    if not args.admin_token:
        print("UPOZORENJE: --admin-token nije podešen, admin UI nije zaštićen!", file=sys.stderr)

    _run(args)


def _run(args):
    import logging
    import uvicorn
    from fastapi import FastAPI
    from ferret.server import AgentRouter

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    app    = FastAPI(title="Outbound Agent Server", docs_url=None, redoc_url=None)
    router = AgentRouter(
        db_path=args.db,
        admin_token=args.admin_token,
        secret=args.secret,
        public_url=args.public_url,
    )
    app.include_router(router.router)

    print(f"Outbound Agent Server")
    print(f"  Admin UI : http://{args.host}:{args.port}/agents/ui")
    print(f"  Audit log: http://{args.host}:{args.port}/agents/audit")
    print(f"  WS path  : ws://{args.host}:{args.port}/ws/agent")
    if args.public_url:
        print(f"  Javni URL: {args.public_url}")
    print()

    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level.lower())


def _install_systemd(args):
    import getpass
    user    = getpass.getuser()
    bin_dir = os.path.dirname(sys.executable)
    cmd     = f"{bin_dir}/ferret-server"

    env_lines = ""
    if args.admin_token:
        env_lines += f"Environment=OA_ADMIN_TOKEN={args.admin_token}\n"
    if args.secret:
        env_lines += f"Environment=OA_SECRET={args.secret}\n"
    if args.public_url:
        env_lines += f"Environment=OA_PUBLIC_URL={args.public_url}\n"
    if args.db != "agents.db":
        env_lines += f"Environment=OA_DB={args.db}\n"

    unit = f"""[Unit]
Description=Outbound Agent Server
After=network.target

[Service]
Type=simple
User={user}
ExecStart={cmd} --host {args.host} --port {args.port} --db {args.db}
{env_lines}Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    path = "/etc/systemd/system/ferret-server.service"
    try:
        with open(path, "w") as f:
            f.write(unit)
        os.system("systemctl daemon-reload")
        os.system("systemctl enable --now ferret-server")
        print(f"Servis instaliran i pokrenut.")
        print(f"  Status: systemctl status ferret-server")
        print(f"  Logovi: journalctl -u ferret-server -f")
    except PermissionError:
        print(f"Potreban je root. Pokušaj: sudo {' '.join(sys.argv)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
