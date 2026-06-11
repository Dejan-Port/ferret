"""
Token generator — HMAC-SHA256 potpisani tokeni vezani za hardver i vreme.

Struktura tokena:
    <base64url(payload)>.<hmac_signature>

Payload (JSON):
    {
        "hw":     "HMAC(secret, client_hw_id)",  # nikad plain hw_id
        "srv_hw": "HMAC(secret, server_hw_id)",  # nikad plain server hw_id
        "name":   "Firma ABC",
        "iat":    1718000000,
        "exp":    1749536000,
        "jti":    "a1b2c3d4",
        "kid":    "v1",
        "srv":    "wss://portal.rs/ws/agent"     # opciono
    }

Zašto HMAC umesto plain hw_id:
    Token payload je base64 — čitljiv bez ključa.
    Ako bi hw_id bio plain, napadač koji vidi token + zna secret
    može da kuje novi token za istu mašinu.
    Sa HMAC(secret, hw_id) u tokenu: napadač vidi samo hash,
    ne može da rekonstruiše hw_id (HMAC je jednosmerna funkcija).

Validacija:
    1. kid → poznat ključ
    2. HMAC potpis tokena
    3. exp → nije istekao
    4. HMAC(secret, hw_id koji šalje agent) == hw iz tokena
    5. HMAC(secret, server_hw_id) == srv_hw iz tokena

Rotacija secretova:
    gen = TokenGen(secrets={"v1": "stari-secret", "v2": "novi-secret"}, active="v2")
"""
import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone


class TokenGen:
    """
    Generator i validator tokena sa podrškom za rotaciju secretova.

    Jednostavna upotreba (jedan secret):
        gen = TokenGen(secret="moj-tajni-kljuc-min-32-znaka")

    Sa rotacijom:
        gen = TokenGen(
            secrets={"v1": "stari-kljuc-32+znaka", "v2": "novi-kljuc-32+znaka"},
            active="v2"
        )

    Generisanje:
        token = gen.create(hw_id="abc123...", name="Firma ABC", valid_days=365)

    Validacija (pri konektu agenta):
        payload = gen.validate(token, hw_id="abc123...")
        if payload is None:
            # nevalidan, istekao, pogrešna mašina ili nepoznat kid
    """

    def __init__(
        self,
        secret: str = "",
        secrets: dict[str, str] = None,
        active: str = "",
    ):
        """
        secret  — jedan secret (prečica za secrets={"v1": secret}, active="v1")
        secrets — rečnik {kid: secret_string}, svi secretovi koji su ikad korišćeni
        active  — kid koji se koristi za potpisivanje novih tokena
        """
        if secrets:
            for kid, s in secrets.items():
                if len(s) < 32:
                    raise ValueError(f"Secret '{kid}' mora biti najmanje 32 znaka")
            self._secrets = {k: v.encode() for k, v in secrets.items()}
            self._active  = active or next(iter(secrets))
        elif secret:
            if len(secret) < 32:
                raise ValueError("Secret mora biti najmanje 32 znaka")
            self._secrets = {"v1": secret.encode()}
            self._active  = "v1"
        else:
            raise ValueError("Potreban je secret ili secrets rečnik")

        if self._active not in self._secrets:
            raise ValueError(f"active='{self._active}' nije u secrets rečniku")

    # ── Generisanje ───────────────────────────────────────────────────────────

    def create(
        self,
        hw_id: str,
        name: str,
        valid_days: int = 365,
        server_url: str = "",
        server_hw_id: str = "",
    ) -> str:
        """
        Kreira novi token vezan za dati hw_id, server URL i server hardware.

        hw_id        - hardverski otisak klijentske mašine (ferret.hw_id.get())
        name         - naziv agenta (samo za čitljivost)
        valid_days   - koliko dana token važi (default: 1 godina)
        server_url   - WebSocket URL servera (npr. "wss://portal.rs/ws/agent")
                       Ako je prazan, agent ne proverava adresu servera.
        server_hw_id - hardverski otisak server mašine (ferret.hw_id.get()
                       pokrenut na serveru). Token neće biti prihvaćen na drugom serveru
                       čak i ako neko ukrade i bazu i secret.
        """
        now = int(time.time())
        payload = {
            "hw":   self._hw_proof(hw_id, self._active),
            "name": name,
            "iat":  now,
            "exp":  now + valid_days * 86400,
            "jti":  os.urandom(4).hex(),
            "kid":  self._active,
        }
        if server_url:
            payload["srv"] = server_url
        if server_hw_id:
            payload["srv_hw"] = self._hw_proof(server_hw_id, self._active)
        payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")))
        sig = self._sign(payload_b64, self._active)
        return f"{payload_b64}.{sig}"

    # ── Validacija ────────────────────────────────────────────────────────────

    def validate(self, token: str, hw_id: str, server_hw_id: str = "") -> dict | None:
        """
        Validira token.

        Vraća payload dict ako su sve provere prošle, None inače.

        Redosled provera:
            1. kid → poznat ključ
            2. HMAC potpis
            3. exp → nije istekao
            4. hw → odgovara klijentskom hw_id-u
            5. srv_hw → odgovara server hw_id-u (ako je prisutan u tokenu)

        server_hw_id - hw otisak ove server mašine; ako token sadrži srv_hw
                       a server_hw_id nije prosleđen, provera se preskače
                       (backward compat)
        """
        try:
            payload_b64, _, sig = token.rpartition(".")
            if not payload_b64 or not sig:
                return None

            payload = json.loads(_b64_decode(payload_b64))
            kid = payload.get("kid", "v1")

            if kid not in self._secrets:
                return None

            expected = self._sign(payload_b64, kid)
            if not hmac.compare_digest(sig, expected):
                return None

            if payload.get("exp", 0) < time.time():
                return None

            # Provera klijentskog hardvera — poredimo HMAC, ne plain hw_id
            if payload.get("hw") != self._hw_proof(hw_id, kid):
                return None

            # Provera server hardvera
            token_srv_hw = payload.get("srv_hw", "")
            if token_srv_hw and server_hw_id:
                if token_srv_hw != self._hw_proof(server_hw_id, kid):
                    return None

            return payload

        except Exception:
            return None

    # ── Rotacija ──────────────────────────────────────────────────────────────

    def rotate(self, new_kid: str, new_secret: str):
        """
        Dodaje novi ključ i čini ga aktivnim za potpisivanje novih tokena.

        Stari ključevi ostaju u rečniku i nastavljaju da validiraju
        postojeće tokene dok ne isteknu.

        Primer:
            gen.rotate("v2", "novi-tajni-kljuc-minimum-32-znaka")
        """
        if len(new_secret) < 32:
            raise ValueError("Novi secret mora biti najmanje 32 znaka")
        if new_kid in self._secrets:
            raise ValueError(f"kid '{new_kid}' već postoji")
        self._secrets[new_kid] = new_secret.encode()
        self._active = new_kid

    def retire(self, kid: str):
        """
        Povlači ključ — tokeni potpisani tim ključem više ne prolaze validaciju.

        Koristiti tek kada su svi tokeni sa tim kid-om istekli ili revokirani.
        """
        if kid == self._active:
            raise ValueError("Ne može se povući aktivni ključ")
        self._secrets.pop(kid, None)

    @property
    def active_kid(self) -> str:
        return self._active

    @property
    def known_kids(self) -> list[str]:
        return list(self._secrets.keys())

    # ── Pomoćne ───────────────────────────────────────────────────────────────

    def decode_insecure(self, token: str) -> dict | None:
        """Dekodira payload bez validacije (za prikaz u UI-u)."""
        try:
            payload_b64 = token.rpartition(".")[0]
            return json.loads(_b64_decode(payload_b64))
        except Exception:
            return None

    def expiry_str(self, token: str) -> str:
        info = self.decode_insecure(token)
        if not info:
            return "—"
        exp = info.get("exp", 0)
        return datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%d")

    def _sign(self, payload_b64: str, kid: str) -> str:
        key = self._secrets[kid]
        return hmac.new(key, payload_b64.encode(), hashlib.sha256).hexdigest()

    def _hw_proof(self, hw_id: str, kid: str) -> str:
        """HMAC(secret, hw_id) — čuva hw_id tajnim čak i ako token procuri."""
        key = self._secrets[kid]
        return hmac.new(key, hw_id.encode(), hashlib.sha256).hexdigest()


def _b64_encode(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)
