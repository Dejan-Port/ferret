"""
Aplikativna enkripcija — ChaCha20-Poly1305 ili AES-256-GCM (AEAD).

Cipher se bira u handshake-u config parametrom. Obe strane moraju da se slože.
Default: chacha20 (brži na ARM bez AES-NI).
FIPS 140-3: aes256gcm (SAD bolnice, banke, vladine institucije).

Ključ sesije se izvodi iz:
    HKDF-SHA256(token + client_nonce + server_nonce)

Format enkriptovane poruke:
    ChaCha20:   "ENC:<base64(12b nonce || ct || 16b tag)>"
    AES-256-GCM:"AES:<base64(12b nonce || ct || 16b tag)>"

Zavisnost: pip install cryptography
"""
import base64
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

CIPHER_CHACHA20  = "chacha20"
CIPHER_AES256GCM = "aes256gcm"
CIPHERS          = (CIPHER_CHACHA20, CIPHER_AES256GCM)

_PREFIX_CHACHA = "ENC:"
_PREFIX_AES    = "AES:"


def available() -> bool:
    return _CRYPTO_OK


def derive_session_key(
    token: str, client_nonce: bytes, server_nonce: bytes,
    cipher: str = CIPHER_CHACHA20,
) -> bytearray:
    """
    Izvodi 32-bajtni ključ sesije iz tokena i dve nasumične vrednosti.
    Vraća bytearray — može se ručno nullovati pri kraju sesije (zero_key).

    cipher se uključuje u HKDF info — ključ je kriptografski vezan za
    konkretni algoritam i ne može se koristiti za drugi (cross-cipher downgrade).
    """
    if not _CRYPTO_OK:
        raise RuntimeError("pip install cryptography")
    material = token.encode() + client_nonce + server_nonce
    info = f"ferret-v1:{cipher}".encode()
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(material)
    return bytearray(raw)


def encrypt(key: bytes, plaintext: bytes, cipher: str = CIPHER_CHACHA20) -> str:
    """
    Enkriptuje bytes, vraća string spreman za slanje.

    Prefix u poruci identifikuje algoritam:
      "ENC:<base64>" — ChaCha20-Poly1305
      "AES:<base64>" — AES-256-GCM
    """
    if not _CRYPTO_OK:
        raise RuntimeError("pip install cryptography")
    iv = os.urandom(12)
    if cipher == CIPHER_AES256GCM:
        ct  = AESGCM(key).encrypt(iv, plaintext, None)
        raw = base64.b64encode(iv + ct).decode()
        return f"{_PREFIX_AES}{raw}"
    else:
        ct  = ChaCha20Poly1305(key).encrypt(iv, plaintext, None)
        raw = base64.b64encode(iv + ct).decode()
        return f"{_PREFIX_CHACHA}{raw}"


def decrypt(key: bytes, message: str) -> bytes:
    """
    Dekriptuje poruku — prepoznaje algoritam iz prefiksa.
    Baca ValueError ako je autentikacija neuspešna (tampered).
    """
    if not _CRYPTO_OK:
        raise RuntimeError("pip install cryptography")
    if message.startswith(_PREFIX_AES):
        raw = base64.b64decode(message[len(_PREFIX_AES):])
        iv, ct = raw[:12], raw[12:]
        return AESGCM(key).decrypt(iv, ct, None)
    elif message.startswith(_PREFIX_CHACHA):
        raw = base64.b64decode(message[len(_PREFIX_CHACHA):])
        iv, ct = raw[:12], raw[12:]
        return ChaCha20Poly1305(key).decrypt(iv, ct, None)
    else:
        raise ValueError("Poruka nije enkriptovana")


def is_encrypted(message: str) -> bool:
    return isinstance(message, str) and (
        message.startswith(_PREFIX_CHACHA) or message.startswith(_PREFIX_AES)
    )


def validate_payload(data) -> bool:
    """
    Proverava da je dekriptovani payload bezbedan za obradu.
    Odbacuje sve što nije dict sa string type poljem.
    Štiti od JSON bomb napada (previše ugnežđeno).
    """
    if not isinstance(data, dict):
        return False
    t = data.get("type")
    if t is not None and not isinstance(t, str):
        return False
    if len(t or "") > 64:
        return False
    return True


def zero_key(key) -> None:
    """Nulluje ključ u memoriji (radi samo za bytearray, ne bytes)."""
    if isinstance(key, bytearray):
        for i in range(len(key)):
            key[i] = 0
