"""
Audit log — beleži sve značajne događaje u sistemu.

Čuva se u SQLite (ista baza kao tokeni ili odvojena).
Svaki red = jedan događaj sa timestamp, tipom, agentom i JSON detaljima.

Tipovi događaja:
    agent_connect     - agent se konektovao
    agent_disconnect  - agent se diskonektovao
    proxy_open        - TCP/UDP tunel otvoren
    proxy_deny        - ACL blokirao zahtev
    tun_start         - VPN sesija počela (IP dodeljen)
    tun_stop          - VPN sesija završena
    token_create      - novi token kreiran
    token_revoke      - token revokovan
    rules_change      - ACL pravila promenjena
    admin_access      - admin API poziv
"""
import json
import sqlite3
import threading
from datetime import datetime


class AuditLog:
    """
    Thread-safe audit log u SQLite.

    Upotreba:
        audit = AuditLog("agents.db")
        audit.log("agent_connect", token="abc123", agent_name="Bankomat 1",
                  detail={"ip": "1.2.3.4", "capabilities": ["tun"]})
    """

    def __init__(self, db_path: str = "agents.db"):
        self._lock = threading.Lock()
        self._con  = sqlite3.connect(str(db_path), check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        with self._lock:
            self._con.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          TEXT NOT NULL,
                    event       TEXT NOT NULL,
                    token       TEXT DEFAULT '',
                    agent_name  TEXT DEFAULT '',
                    detail      TEXT DEFAULT '{}',
                    ip          TEXT DEFAULT ''
                )
            """)
            self._con.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit_log(ts DESC)"
            )
            self._con.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_token ON audit_log(token)"
            )
            self._con.commit()

    def log(
        self,
        event: str,
        token: str = "",
        agent_name: str = "",
        detail: dict = None,
        ip: str = "",
    ):
        ts = datetime.now().isoformat(timespec="seconds")
        with self._lock:
            self._con.execute(
                "INSERT INTO audit_log (ts, event, token, agent_name, detail, ip)"
                " VALUES (?,?,?,?,?,?)",
                [ts, event, token[:16] if token else "", agent_name,
                 json.dumps(detail or {}), ip]
            )
            self._con.commit()

    def recent(
        self,
        limit: int = 200,
        token: str = None,
        event: str = None,
    ) -> list[dict]:
        """Vraća poslednje događaje, opciono filtrirane po tokenu ili tipu."""
        where, params = [], []
        if token:
            where.append("token = ?")
            params.append(token[:16])
        if event:
            where.append("event = ?")
            params.append(event)
        sql = "SELECT * FROM audit_log"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._con.execute(sql, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = json.loads(d["detail"])
            except Exception:
                d["detail"] = {}
            result.append(d)
        return result

    def stats(self) -> dict:
        """Brzi pregled: ukupno događaja, poslednji timestamp."""
        with self._lock:
            total = self._con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            last  = self._con.execute(
                "SELECT ts FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return {"total": total, "last": last[0] if last else "—"}
