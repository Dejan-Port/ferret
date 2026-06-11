"""
Interna CA (Certificate Authority) za ferret.

Server generiše sopstveni CA jednom pri pokretanju. Za svakog agenta
izdaje klijentski sertifikat potpisan tim CA.

Bezbednosni model:
  - CA privatni ključ ostaje na serveru (/etc/ferret/ca.key)
  - Klijentski privatni ključ se generiše i odmah vraća korisniku — ne čuva se
  - Agent koristi cert za mTLS i/ili CA fingerprint za pinning
  - Čak i ako napadač presretne TLS, bez CA-potpisanog certa ne može da se autentifikuje

Zahteva: pip install cryptography
"""
import datetime
import hashlib
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_CA_KEY_PATH  = "/etc/ferret/ca.key"
_CA_CERT_PATH = "/etc/ferret/ca.crt"
_CA_KEY_FALLBACK  = os.path.expanduser("~/.ferret/ca.key")
_CA_CERT_FALLBACK = os.path.expanduser("~/.ferret/ca.crt")


class CertAuthority:
    """
    Server CA — generiše se jednom, čuva lokalno.

    Upotreba:
        ca = CertAuthority()              # učitava ili kreira CA
        cert_pem, key_pem = ca.issue("Firma ABC", valid_days=365, jti="a1b2")
        fp = ca.fingerprint               # SHA-256 otisak CA sertifikata
    """

    def __init__(self):
        self._ca_key, self._ca_cert = _load_or_create_ca()

    # ── Izdavanje klijentskog sertifikata ─────────────────────────────────────

    def issue(
        self,
        name: str,
        valid_days: int = 365,
        jti: str = "",
    ) -> tuple[str, str]:
        """
        Generiše klijentski sertifikat za agenta.

        Vraća (cert_pem, key_pem) — privatni ključ se NE čuva na serveru.
        Ako korisnik izgubi bundle, mora se generisati novi token.

        name      - naziv agenta (CN u sertifikatu)
        valid_days - rok važenja (treba da odgovara roku tokena)
        jti       - jedinstveni ID tokena (ugrađuje se kao SAN URI)
        """
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ferret"),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=valid_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ), critical=True
            )
        )

        if jti:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(f"ferret:{jti}")
                ]),
                critical=False,
            )

        cert = builder.sign(self._ca_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem  = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()

        return cert_pem, key_pem

    # ── CA info ───────────────────────────────────────────────────────────────

    @property
    def ca_pem(self) -> str:
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def fingerprint(self) -> str:
        """SHA-256 otisak CA sertifikata — ugrađuje se u token za pinning."""
        der = self._ca_cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()


# ── Generisanje / učitavanje CA ───────────────────────────────────────────────

def _load_or_create_ca():
    key_path, cert_path = _ca_paths()

    if os.path.exists(key_path) and os.path.exists(cert_path):
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return key, cert

    # Generiši novi CA
    key  = ec.generate_private_key(ec.SECP256R1())
    now  = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ferret CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ferret"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ), critical=True
        )
        .sign(key, hashes.SHA256())
    )

    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    finally:
        os.close(fd)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key, cert


def _ca_paths() -> tuple[str, str]:
    if os.access(os.path.dirname(_CA_KEY_PATH) or "/etc", os.W_OK):
        return _CA_KEY_PATH, _CA_CERT_PATH
    return _CA_KEY_FALLBACK, _CA_CERT_FALLBACK
