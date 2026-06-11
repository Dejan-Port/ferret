"""
Token registry — SQLite baza za upravljanje agentima i tokenima.

Svaki token identifikuje jednog agenta (klijenta). Token se generiše
na portalu, upisuje u agent.conf na klijentskoj mašini, i koristi
pri svakom WebSocket konektovanju.

ACL pravila se čuvaju kao JSON lista u koloni `rules`.
Prazan rules znači da agent ne sme da propušta nikakav tunel saobraćaj.
"""
import json
import secrets
import sqlite3
import threading
from datetime import datetime

from ferret.server.acl import Acl


class TokenRegistry:
    """
    Thread-safe SQLite registry za agent tokene.

    Upotreba:
        reg = TokenRegistry("/var/lib/my-portal/agents.db")
        token = reg.create("Firma ABC", rules=["tcp:22", "tcp:3389"])
    """

    def __init__(self, db_path: str = "agents.db"):
        self._lock = threading.Lock()
        self._con  = sqlite3.connect(str(db_path), check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        with self._lock:
            self._con.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    token        TEXT PRIMARY KEY,
                    name         TEXT NOT NULL,
                    note         TEXT DEFAULT '',
                    rules        TEXT DEFAULT '[]',
                    created_at   TEXT NOT NULL,
                    last_seen    TEXT,
                    capabilities TEXT DEFAULT '',
                    online       INTEGER DEFAULT 0,
                    revoked      INTEGER DEFAULT 0
                )
            """)
            # Migracije za stare baze
            for migration in (
                "ALTER TABLE agents ADD COLUMN rules    TEXT DEFAULT '[]'",
                "ALTER TABLE agents ADD COLUMN cert_pem TEXT DEFAULT ''",
            ):
                try:
                    self._con.execute(migration)
                except Exception:
                    pass
            self._con.commit()

    # ── Token operacije ───────────────────────────────────────────────────────

    def save_cert(self, token: str, cert_pem: str):
        """Čuva klijentski sertifikat (samo cert, ne private key)."""
        with self._lock:
            self._con.execute(
                "UPDATE agents SET cert_pem=? WHERE token=?", [cert_pem, token]
            )
            self._con.commit()

    def create(self, name: str, note: str = "", rules: list[str] = None) -> str:
        """
        Generiše novi token za agenta.

        rules — lista ACL pravila, npr. ["tcp:22", "udp:161", "tcp:*"]
                Prazna lista = tunel nije dozvoljen.
                None = isti efekat kao prazna lista.
        """
        token     = secrets.token_hex(24)
        now       = datetime.now().isoformat(timespec="seconds")
        rules_json = json.dumps(rules or [])
        with self._lock:
            self._con.execute(
                "INSERT INTO agents (token, name, note, rules, created_at) VALUES (?,?,?,?,?)",
                [token, name, note, rules_json, now]
            )
            self._con.commit()
        return token

    def validate(self, token: str) -> dict | None:
        """Vraća info o agentu ako je token validan i nije revokovan, inače None."""
        with self._lock:
            row = self._con.execute(
                "SELECT * FROM agents WHERE token=? AND revoked=0", [token]
            ).fetchone()
        return dict(row) if row else None

    def revoke(self, token: str):
        """Onemogućava token (agent se neće moći konektovati)."""
        with self._lock:
            self._con.execute("UPDATE agents SET revoked=1, online=0 WHERE token=?", [token])
            self._con.commit()

    def set_rules(self, token: str, rules: list[str]):
        """Ažurira ACL pravila za agenta (bez rekonektovanja)."""
        with self._lock:
            self._con.execute(
                "UPDATE agents SET rules=? WHERE token=?", [json.dumps(rules), token]
            )
            self._con.commit()

    def get_acl(self, token: str) -> Acl:
        """Vraća ACL objekat za agenta."""
        with self._lock:
            row = self._con.execute(
                "SELECT rules FROM agents WHERE token=?", [token]
            ).fetchone()
        if not row:
            return Acl([])
        return Acl.from_json(row["rules"])

    def set_online(self, token: str, online: bool, capabilities: list = None):
        """Ažurira status agenta pri konektu/diskonektu."""
        now  = datetime.now().isoformat(timespec="seconds") if online else None
        caps = ",".join(capabilities or [])
        with self._lock:
            if online:
                self._con.execute(
                    "UPDATE agents SET online=1, last_seen=?, capabilities=? WHERE token=?",
                    [now, caps, token]
                )
            else:
                self._con.execute("UPDATE agents SET online=0 WHERE token=?", [token])
            self._con.commit()

    def list_all(self) -> list[dict]:
        """Lista svih agenata (aktivnih i revokovanih)."""
        with self._lock:
            rows = self._con.execute(
                "SELECT * FROM agents ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get(self, token: str) -> dict | None:
        with self._lock:
            row = self._con.execute(
                "SELECT * FROM agents WHERE token=?", [token]
            ).fetchone()
        return dict(row) if row else None
