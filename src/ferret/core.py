"""
Outbound WebSocket Agent — core tunnel.

Konekcija je uvek outbound (klijentska strana inicira), bez otvaranja portova.
Server šalje komande; agent ih dispečuje registrovanim handler-ima.

Enkripcija (opcionalna, zahteva: pip install cryptography):
    Posle handshake-a sve poruke su enkriptovane ChaCha20-Poly1305.
    Ključ sesije = HKDF(token + client_nonce + server_nonce).
    Hardverski otisak (hw_id) se šalje serveru radi validacije tokena.
"""
import asyncio
import json
import logging
import os
from typing import Callable, Awaitable

try:
    import websockets
except ImportError:
    raise ImportError("Nedostaje: pip install websockets")

from ferret import crypto

log = logging.getLogger("ferret")


class Agent:
    """
    Outbound WebSocket agent sa plugabilnim handler-ima.

    Upotreba:
        agent = Agent(url="wss://portal.rs/ws/agent", token="xxx")

        @agent.on("moja_komanda", capability="moj_modul")
        async def handle(data, send):
            await send({"type": "response", "ok": True})

        agent.run()

    Sa enkripcijom i hardware binding:
        import ferret.hw_id as hw_id
        agent = Agent(url=..., token=..., hw_id=hw_id.get(), encrypt=True)
    """

    def __init__(
        self,
        url: str,
        token: str,
        reconnect_sec: int = 10,
        hw_id: str = "",
        encrypt: bool = True,
        cipher: str = "chacha20",
        ssl_context=None,
    ):
        self._url          = url
        self._token        = token
        self._reconnect_sec = reconnect_sec
        self._hw_id        = hw_id
        self._encrypt      = encrypt and crypto.available()
        self._cipher       = cipher if cipher in ("chacha20", "aes256gcm") else "chacha20"
        self._ssl_context  = ssl_context
        self._session_key: bytes | None = None

        self._handlers: dict[str, Callable]  = {}
        self._backgrounds: list[Callable]    = []
        self._capabilities: list[str]        = []
        self._ws = None
        self._send_lock = asyncio.Lock()

    # ── Registracija ─────────────────────────────────────────────────────────

    def on(self, message_type: str, capability: str = None):
        """Dekorator koji registruje handler za određeni tip poruke."""
        def decorator(fn: Callable[..., Awaitable]):
            self._handlers[message_type] = fn
            if capability and capability not in self._capabilities:
                self._capabilities.append(capability)
            return fn
        return decorator

    def register_handler(self, message_type: str, fn: Callable, capability: str = None):
        self._handlers[message_type] = fn
        if capability and capability not in self._capabilities:
            self._capabilities.append(capability)

    def background(self, fn: Callable[..., Awaitable]):
        """Dekorator za pozadinski task."""
        self._backgrounds.append(fn)
        return fn

    def add_background(self, fn: Callable[..., Awaitable]):
        self._backgrounds.append(fn)

    # ── Slanje ───────────────────────────────────────────────────────────────

    async def send(self, data: dict):
        """Šalje poruku portalu. Enkriptuje ako je sesija aktivna."""
        if self._ws is None:
            return
        try:
            async with self._send_lock:
                raw = json.dumps(data)
                if self._session_key and self._encrypt:
                    raw = crypto.encrypt(self._session_key, raw.encode(), self._cipher)
                await self._ws.send(raw)
        except Exception as e:
            log.warning("send greška: %s", e)

    # ── Pokretanje ────────────────────────────────────────────────────────────

    def run(self):
        try:
            asyncio.run(self._loop())
        except KeyboardInterrupt:
            log.info("Agent zaustavljen")

    async def run_async(self):
        await self._loop()

    # ── Interna petlja ────────────────────────────────────────────────────────

    async def _loop(self):
        if not self._token:
            log.error("Token nije podešen")
            return

        # Provera da token odgovara ovom serveru (ako token sadrži srv polje)
        token_srv = _decode_token_srv(self._token)
        if token_srv and not _url_matches(token_srv, self._url):
            log.error(
                "Token je izdat za drugi server!\n"
                "  Token srv: %s\n"
                "  Ovaj URL:  %s\n"
                "Agent neće pokušati konekciju.",
                token_srv, self._url
            )
            return

        sep = "&" if "?" in self._url else "?"
        connect_url = f"{self._url}{sep}token={self._token}"
        if self._hw_id:
            connect_url += f"&hw={self._hw_id}"
        log.info("Konektujem na %s | capabilities: %s | enkripcija: %s",
                 self._url, self._capabilities,
                 "da" if self._encrypt else "ne")

        while True:
            try:
                _ssl = self._ssl_context
                if _ssl is None and connect_url.startswith("wss://"):
                    _ssl = True
                async with websockets.connect(
                    connect_url,
                    ping_interval=None,
                    ssl=_ssl,
                ) as ws:
                    self._ws = ws
                    self._session_key = None

                    # ── Handshake ─────────────────────────────────────────────
                    # 1. Registracija + capabilities
                    await ws.send(json.dumps({
                        "type":         "register",
                        "capabilities": self._capabilities,
                        "hw":           self._hw_id,
                        "encrypt":      self._encrypt,
                    }))
                    resp = json.loads(await ws.recv())
                    if not resp.get("ok"):
                        log.error("Registracija odbijena: %s", resp.get("error", ""))
                        return
                    if not resp.get("approved", True):
                        log.info("Agent čeka odobrenje admina — HWID vezan, konekcija otvorena")
                        # Drži konekciju živom ali ne obrađuje tunel zahteve
                        async for _ in ws:
                            pass
                        return

                    # 2. Crypto handshake (ako obe strane podržavaju)
                    if self._encrypt and resp.get("encrypt"):
                        client_nonce = os.urandom(16)
                        await ws.send(json.dumps({
                            "type":   "crypto_hello",
                            "nonce":  client_nonce.hex(),
                            "cipher": self._cipher,
                        }))
                        hs = json.loads(await ws.recv())
                        if hs.get("type") == "crypto_ok":
                            server_nonce  = bytes.fromhex(hs["nonce"])
                            self._cipher  = hs.get("cipher", "chacha20")
                            self._session_key = crypto.derive_session_key(
                                self._token, client_nonce, server_nonce, self._cipher
                            )
                            log.info("Enkriptovana sesija | cipher: %s", self._cipher)
                        else:
                            log.warning("Server odbio enkripciju — nastavljam bez")

                    log.info("Registrovan | capabilities: %s", self._capabilities)

                    # ── Pozadinski taskovi ────────────────────────────────────
                    tasks = [
                        asyncio.create_task(bg(self.send))
                        for bg in self._backgrounds
                    ]

                    try:
                        async for raw in ws:
                            # Dekripcija ako je aktivna
                            if self._session_key and crypto.is_encrypted(raw):
                                try:
                                    raw = crypto.decrypt(
                                        self._session_key, raw
                                    ).decode()
                                except Exception:
                                    log.warning("Dekripcija neuspešna — poruka odbačena")
                                    continue

                            try:
                                data = json.loads(raw)
                            except Exception:
                                continue

                            t = data.get("type")
                            if t == "ping":
                                await self.send({"type": "pong"})
                            elif t in self._handlers:
                                asyncio.create_task(
                                    self._handlers[t](data, self.send)
                                )
                            else:
                                log.debug("Nepoznati tip: %s", t)
                    finally:
                        for task in tasks:
                            task.cancel()
                        self._ws = None
                        crypto.zero_key(self._session_key)
                        self._session_key = None

            except Exception as e:
                self._ws = None
                crypto.zero_key(self._session_key)
                self._session_key = None
                log.warning("Konekcija prekinuta: %s — pokušavam za %ds",
                            e, self._reconnect_sec)
                await asyncio.sleep(self._reconnect_sec)


# ── Token helpers (bez zavisnosti od server modula) ───────────────────────────

def _decode_token_srv(token: str) -> str:
    """Izvlači srv polje iz tokena bez validacije potpisa. Vraća "" ako nema."""
    try:
        import base64, json
        payload_b64 = token.rpartition(".")[0]
        pad = 4 - len(payload_b64) % 4
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * pad))
        return payload.get("srv", "")
    except Exception:
        return ""


def _url_matches(token_srv: str, connect_url: str) -> bool:
    """
    Poredi server URL iz tokena sa URL-om na koji se agent konektuje.
    Token sadrži base URL (npr. wss://server.com), agent se konektuje
    na puni WS path (npr. wss://server.com/ws/agent) — path agenta
    mora počinjati sa pathom iz tokena.
    """
    from urllib.parse import urlparse
    a = urlparse(token_srv)
    b = urlparse(connect_url)
    scheme_ok = a.scheme == b.scheme or {a.scheme, b.scheme} in (
        {"ws", "wss"}, {"http", "https"}
    )
    if not scheme_ok or a.netloc != b.netloc:
        return False
    token_path = a.path.rstrip("/") or ""
    return b.path.startswith(token_path)
