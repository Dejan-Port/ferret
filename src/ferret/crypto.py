"""
Aplikativna enkripcija — ChaCha20-Poly1305 (AEAD).

Enkriptuje sve poruke posle handshake-a, nezavisno od TLS sloja.

Ključ sesije se izvodi iz:
    HKDF-SHA256(token + client_nonce + server_nonce)

Tako isti token na različitim konekcijama daje različite ključeve,
i svaka poruka ima jedinstven 12-bajtni IV.

Zavisnost: pip install cryptography
"""
import base64
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False


# Prefiks koji označava enkriptovanu poruku
_ENC_PREFIX = "ENC:"


def available() -> bool:
    return _CRYPTO_OK


def derive_session_key(token: str, client_nonce: bytes, server_nonce: bytes) -> bytes:
    """
    Izvodi 32-bajtni ključ sesije iz tokena i dve nasumične vrednosti.

    Obe strane (agent i server) mogu da izvedu isti ključ jer oba znaju:
    - token (deli se pri konektu)
    - client_nonce i server_nonce (razmenjuju se u handshake-u)
    """
    if not _CRYPTO_OK:
        raise RuntimeError("pip install cryptography")
    material = token.encode() + client_nonce + server_nonce
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ferret-v1",
    ).derive(material)


def encrypt(key: bytes, plaintext: bytes) -> str:
    """
    Enkriptuje bytes, vraća "ENC:<base64>" string spreman za slanje.

    Format: 12 bytes IV || ciphertext || 16 bytes auth tag
    """
    if not _CRYPTO_OK:
        raise RuntimeError("pip install cryptography")
    iv  = os.urandom(12)
    ct  = ChaCha20Poly1305(key).encrypt(iv, plaintext, None)
    raw = base64.b64encode(iv + ct).decode()
    return f"{_ENC_PREFIX}{raw}"


def decrypt(key: bytes, message: str) -> bytes:
    """
    Dekriptuje "ENC:<base64>" string, vraća originalne bytes.
    Baca ValueError ako je autentikacija neuspešna (tampered).
    """
    if not _CRYPTO_OK:
        raise RuntimeError("pip install cryptography")
    if not message.startswith(_ENC_PREFIX):
        raise ValueError("Poruka nije enkriptovana")
    raw  = base64.b64decode(message[len(_ENC_PREFIX):])
    iv, ct = raw[:12], raw[12:]
    return ChaCha20Poly1305(key).decrypt(iv, ct, None)


def is_encrypted(message: str) -> bool:
    return isinstance(message, str) and message.startswith(_ENC_PREFIX)
