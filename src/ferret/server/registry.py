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
                    token          TEXT PRIMARY KEY,
                    name           TEXT NOT NULL,
                    note           TEXT DEFAULT '',
                    rules          TEXT DEFAULT '[]',
                    created_at     TEXT NOT NULL,
                    last_seen      TEXT,
                    capabilities   TEXT DEFAULT '',
                    online         INTEGER DEFAULT 0,
                    revoked        INTEGER DEFAULT 0,
                    hwid           TEXT DEFAULT '',
                    approved       INTEGER DEFAULT 0,
                    invite_expires TEXT DEFAULT ''
                )
            """)
            # Migracije za stare baze
            for migration in (
                "ALTER TABLE agents ADD COLUMN rules          TEXT    DEFAULT '[]'",
                "ALTER TABLE agents ADD COLUMN cert_pem       TEXT    DEFAULT ''",
                "ALTER TABLE agents ADD COLUMN hwid           TEXT    DEFAULT ''",
                "ALTER TABLE agents ADD COLUMN approved       INTEGER DEFAULT 1",
                "ALTER TABLE agents ADD COLUMN invite_expires TEXT    DEFAULT ''",
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

    def create(self, name: str, note: str = "", rules: list[str] = None,
               invite_minutes: int = 0) -> str:
        """
        Generiše novi token za agenta.

        rules          — lista ACL pravila, npr. ["tcp:22", "udp:161", "tcp:*"]
        invite_minutes — ako > 0, token je invite (važi N minuta za prvu konekciju,
                         čeka odobrenje; posle odobrenja trajan je)
        """
        token      = secrets.token_hex(24)  # 192 bita entropije — otporno na brute force
        now        = datetime.now().isoformat(timespec="seconds")
        rules_json = json.dumps(rules or [])
        expires    = ""
        approved   = 1  # normalni tokeni su odmah odobreni (stari flow)
        if invite_minutes > 0:
            from datetime import timedelta
            exp_dt  = datetime.now() + timedelta(minutes=invite_minutes)
            expires = exp_dt.isoformat(timespec="seconds")
            approved = 0  # invite čeka odobrenje
        with self._lock:
            self._con.execute(
                "INSERT INTO agents (token, name, note, rules, created_at, approved, invite_expires)"
                " VALUES (?,?,?,?,?,?,?)",
                [token, name, note, rules_json, now, approved, expires]
            )
            self._con.commit()
        return token

    def invite_valid(self, token: str) -> bool:
        """True ako je invite token još uvek u roku (5 min)."""
        with self._lock:
            row = self._con.execute(
                "SELECT invite_expires, approved FROM agents WHERE token=? AND revoked=0", [token]
            ).fetchone()
        if not row:
            return False
        if row["approved"]:
            return True  # već odobren — uvek validan
        expires = row["invite_expires"]
        if not expires:
            return True  # stari token bez expiry — prihvati
        return datetime.now().isoformat() < expires

    def bind_hwid(self, token: str, hwid: str):
        """Vezuje HWID za token pri prvoj konekciji (pre odobrenja)."""
        with self._lock:
            self._con.execute(
                "UPDATE agents SET hwid=? WHERE token=? AND hwid=''",
                [hwid, token]
            )
            self._con.commit()

    def approve(self, token: str):
        """Admin odobrava agenta — token postaje trajan."""
        with self._lock:
            self._con.execute(
                "UPDATE agents SET approved=1, invite_expires='' WHERE token=?", [token]
            )
            self._con.commit()

    def check_hwid(self, token: str, hwid: str) -> bool:
        """Proverava HWID pri rekonekciji. True ako se poklapa."""
        with self._lock:
            row = self._con.execute(
                "SELECT hwid, approved FROM agents WHERE token=? AND revoked=0", [token]
            ).fetchone()
        if not row:
            return False
        if not row["approved"]:
            return False  # nije odobren
        stored = row["hwid"]
        if not stored:
            return True  # stari agent bez HWID — prihvati
        return stored == hwid

    def list_pending(self) -> list[dict]:
        """Lista agenata koji čekaju odobrenje."""
        with self._lock:
            rows = self._con.execute(
                "SELECT * FROM agents WHERE approved=0 AND revoked=0 ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

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
