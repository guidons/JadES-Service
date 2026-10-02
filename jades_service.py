import base64
import binascii
import datetime
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID

CSC_CLIENT_ID = os.environ.get("CSC_CLIENT_ID", "csc_demo_client")
CSC_CLIENT_SECRET = os.environ.get("CSC_CLIENT_SECRET", "csc_demo_client_secret")
CSC_CREDENTIAL_ID = os.environ.get("CSC_CREDENTIAL_ID", "jades_signing_credential")
HASH_ALGORITHM = "2.16.840.1.101.3.4.2.1"
SIGN_ALGORITHM = "1.2.840.113549.1.1.1"
ACCESS_TOKEN_TTL = 3600
SAD_TTL = 300
MAX_ACCESS_TOKENS = 1000
MAX_SAD_RECORDS = 1000
DEMO_CLIENT_ID = "csc_demo_client"
DEMO_CLIENT_SECRET = "csc_demo_client_secret"

BASE_DIR = Path(__file__).resolve().parent
SIGNING_DATA_DIR = Path(os.environ.get("SIGNING_DATA_DIR", BASE_DIR / "data"))
KEY_PATH = Path(os.environ.get("SIGNING_KEY_PATH", SIGNING_DATA_DIR / "signer_key.pem"))
CERT_PATH = Path(
    os.environ.get("SIGNING_CERT_PATH", SIGNING_DATA_DIR / "signer_cert.pem")
)
SIGNER_COMMON_NAME = os.environ.get("SIGNER_COMMON_NAME", "JAdES Signing Service")
SIGNER_ORGANIZATION = os.environ.get("SIGNER_ORGANIZATION", "Digital Signing Service")


@dataclass(frozen=True)
class SADRecord:
    credential_id: str
    hashes: tuple[str, ...]
    expires_at: float


@dataclass(frozen=True)
class AccessTokenRecord:
    client_id: str
    expires_at: float


_access_tokens: Dict[str, AccessTokenRecord] = {}
_sad_records: Dict[str, SADRecord] = {}
_state_lock = threading.RLock()


def validate_configuration() -> None:
    environment = os.environ.get("APP_ENV", "development").strip().lower()
    if environment in {"production", "prod"} and (
        CSC_CLIENT_ID == DEMO_CLIENT_ID
        or CSC_CLIENT_SECRET == DEMO_CLIENT_SECRET
        or len(CSC_CLIENT_SECRET) < 32
    ):
        raise RuntimeError(
            "Production requires a non-default CSC_CLIENT_ID and a CSC_CLIENT_SECRET of at least 32 characters"
        )
    if not SIGNER_COMMON_NAME.strip() or not SIGNER_ORGANIZATION.strip():
        raise RuntimeError("Signer common name and organization must not be empty")


def _purge_expired_records(now: float) -> None:
    expired_tokens = [
        token for token, record in _access_tokens.items() if record.expires_at <= now
    ]
    for token in expired_tokens:
        _access_tokens.pop(token, None)

    expired_sads = [
        sad for sad, record in _sad_records.items() if record.expires_at <= now
    ]
    for sad in expired_sads:
        _sad_records.pop(sad, None)


def issue_access_token(client_id: str = "") -> str:
    now = time.time()
    with _state_lock:
        _purge_expired_records(now)
        while len(_access_tokens) >= MAX_ACCESS_TOKENS:
            _access_tokens.pop(next(iter(_access_tokens)))

        token = secrets.token_urlsafe(32)
        _access_tokens[token] = AccessTokenRecord(
            client_id=client_id,
            expires_at=now + ACCESS_TOKEN_TTL,
        )
        return token


def is_valid_client(client_id: str, client_secret: str) -> bool:
    return hmac.compare_digest(client_id or "", CSC_CLIENT_ID) and hmac.compare_digest(
        client_secret or "", CSC_CLIENT_SECRET
    )


def is_valid_access_token(token: str) -> bool:
    if not token:
        return False
    with _state_lock:
        record = _access_tokens.get(token)
        if record is None:
            return False
        if record.expires_at <= time.time():
            _access_tokens.pop(token, None)
            return False
        return True


def decode_hash(hash_value: str) -> bytes:
    if not isinstance(hash_value, str) or not hash_value:
        raise ValueError("hash entries must be non-empty strings")
    if len(hash_value) > 128:
        raise ValueError("hash value is too long")

    try:
        decoded = bytes.fromhex(hash_value)
    except ValueError:
        try:
            decoded = base64.b64decode(hash_value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("hash must be SHA-256 hex or base64") from exc

    if len(decoded) != hashlib.sha256().digest_size:
        raise ValueError("hash must contain exactly 32 bytes")
    return decoded


def decode_csc_hash(hash_value: str) -> bytes:
    if not isinstance(hash_value, str) or not hash_value:
        raise ValueError("hashes must contain non-empty Base64 strings")
    try:
        decoded = base64.b64decode(hash_value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("hashes must contain Base64-encoded SHA-256 digests") from exc
    if len(decoded) != hashlib.sha256().digest_size:
        raise ValueError("hashes must contain exactly 32 bytes")
    return decoded


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def authorize_hashes(credential_id: str, hashes: List[str], num_signatures: int) -> str:
    if credential_id != CSC_CREDENTIAL_ID:
        raise ValueError("unknown credentialID")
    if num_signatures != 1 or len(hashes) != 1:
        raise ValueError("this credential authorizes exactly one signature")
    for hash_value in hashes:
        decode_hash(hash_value)

    with _state_lock:
        _purge_expired_records(time.time())
        while len(_sad_records) >= MAX_SAD_RECORDS:
            _sad_records.pop(next(iter(_sad_records)))

        sad = secrets.token_urlsafe(32)
        _sad_records[sad] = SADRecord(
            credential_id=credential_id,
            hashes=tuple(hashes),
            expires_at=time.time() + SAD_TTL,
        )
        return sad


def _consume_sad(sad: str, credential_id: str, hashes: List[str]) -> None:
    with _state_lock:
        record = _sad_records.get(sad)
        if record is None or record.expires_at < time.time():
            raise ValueError("invalid or expired SAD")
        if record.credential_id != credential_id or record.hashes != tuple(hashes):
            raise ValueError("SAD is not authorized for this credential and hash")
        _sad_records.pop(sad)


def ensure_signing_identity() -> tuple[Path, Path]:
    key_exists = KEY_PATH.exists()
    cert_exists = CERT_PATH.exists()
    if key_exists != cert_exists:
        raise RuntimeError(
            "Signing key and certificate must either both exist or both be absent"
        )

    if not key_exists:
        KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, SIGNER_COMMON_NAME),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, SIGNER_ORGANIZATION),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, crypto_hashes.SHA256())
        )

        KEY_PATH.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        try:
            os.chmod(KEY_PATH, 0o600)
        except OSError:
            pass
        CERT_PATH.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    try:
        private_key = serialization.load_pem_private_key(
            KEY_PATH.read_bytes(), password=None
        )
        certificate = x509.load_pem_x509_certificate(CERT_PATH.read_bytes())
    except (OSError, TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise RuntimeError("Unable to load signing key and certificate") from exc

    if not isinstance(private_key, rsa.RSAPrivateKey) or not isinstance(
        certificate.public_key(), rsa.RSAPublicKey
    ):
        raise RuntimeError("Signing key and certificate must use RSA")
    if (
        private_key.public_key().public_numbers()
        != certificate.public_key().public_numbers()
    ):
        raise RuntimeError("Signing key does not match signing certificate")

    now = datetime.datetime.now(datetime.timezone.utc)
    if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc <= now:
        raise RuntimeError("Signing certificate is not currently valid")

    return KEY_PATH, CERT_PATH


def sign_detached_jws(
    credential_id: str, sad: str, hashes: List[str], hash_algo: str, sign_algo: str
) -> str:
    if credential_id != CSC_CREDENTIAL_ID:
        raise ValueError("unknown credentialID")
    if hash_algo != HASH_ALGORITHM or sign_algo != SIGN_ALGORITHM:
        raise ValueError("unsupported hashAlgo or signAlgo")
    if len(hashes) != 1:
        raise ValueError("exactly one hash is required")

    hash_bytes = decode_hash(hashes[0])
    _consume_sad(sad, credential_id, hashes)
    ensure_signing_identity()

    with CERT_PATH.open("rb") as cert_file:
        certificate = x509.load_pem_x509_certificate(cert_file.read())
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    sig_t = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    protected_header = {
        "alg": "RS256",
        "sigT": sig_t,
        "x5c": [base64.b64encode(certificate_der).decode("ascii")],
    }
    protected = _base64url(
        json.dumps(protected_header, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{protected}.{_base64url(hash_bytes)}".encode("ascii")

    with KEY_PATH.open("rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    signature = private_key.sign(
        signing_input, padding.PKCS1v15(), crypto_hashes.SHA256()
    )
    return f"{protected}..{_base64url(signature)}"


def sign_hash_values(
    credential_id: str,
    sad: str,
    hashes: List[str],
    hash_algo: str,
    sign_algo: str,
) -> List[str]:
    if credential_id != CSC_CREDENTIAL_ID:
        raise ValueError("unknown credentialID")
    if hash_algo != HASH_ALGORITHM or sign_algo != SIGN_ALGORITHM:
        raise ValueError("unsupported hashAlgorithmOID or signAlgo")
    if len(hashes) != 1:
        raise ValueError("this credential authorizes exactly one signature")

    hash_bytes = decode_csc_hash(hashes[0])
    _consume_sad(sad, credential_id, hashes)
    ensure_signing_identity()

    with KEY_PATH.open("rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    signature = private_key.sign(
        hash_bytes,
        padding.PKCS1v15(),
        utils.Prehashed(crypto_hashes.SHA256()),
    )
    return [base64.b64encode(signature).decode("ascii")]
