"""
ACL — pravila za dozvoljeni saobraćaj po agentu.

Format pravila (lista stringova, čuva se kao JSON u bazi):
    "tcp:22"      — samo TCP port 22
    "udp:161"     — samo UDP port 161
    "tcp:*"       — sav TCP saobraćaj
    "udp:*"       — sav UDP saobraćaj
    "*:*"         — sve (TCP i UDP, svi portovi)
    "*"           — isto kao *:*

Primeri:
    acl = Acl(["tcp:22", "tcp:3389"])
    acl.check("tcp", 22)   → True
    acl.check("tcp", 80)   → False
    acl.check("udp", 161)  → False

    acl = Acl(["tcp:*", "udp:161"])
    acl.check("tcp", 8080) → True
    acl.check("udp", 161)  → True
    acl.check("udp", 162)  → False
"""
import json


class Acl:
    def __init__(self, rules: list[str]):
        self._rules = [_parse(r) for r in rules]

    def check(self, proto: str, port: int) -> bool:
        """Vraća True ako je proto/port dozvoljen bar jednim pravilom."""
        for rule_proto, rule_port in self._rules:
            proto_ok = rule_proto in ("*", proto.lower())
            port_ok  = rule_port is None or rule_port == port
            if proto_ok and port_ok:
                return True
        return False

    def is_empty(self) -> bool:
        return len(self._rules) == 0

    @staticmethod
    def from_json(rules_json: str) -> "Acl":
        """Kreira ACL iz JSON stringa koji je sačuvan u bazi."""
        try:
            rules = json.loads(rules_json or "[]")
        except Exception:
            rules = []
        return Acl(rules)

    @staticmethod
    def allow_all() -> "Acl":
        return Acl(["*:*"])

    def to_json(self) -> str:
        result = []
        for proto, port in self._rules:
            result.append(f"{proto}:{port if port is not None else '*'}")
        return json.dumps(result)

    def __repr__(self):
        return f"Acl({self.to_json()})"


def _parse(rule: str) -> tuple:
    """Parsira "tcp:22" → ("tcp", 22), "tcp:*" → ("tcp", None), "*" → ("*", None)."""
    rule = rule.strip().lower()
    if rule in ("*", "*:*"):
        return ("*", None)
    if ":" not in rule:
        # samo protokol bez porta — tretira se kao wildcard port
        return (rule, None)
    proto, _, port_str = rule.partition(":")
    port = None if port_str == "*" else int(port_str)
    return (proto, port)
