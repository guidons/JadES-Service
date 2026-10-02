import base64
import hashlib
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from fastapi.testclient import TestClient

import jades_service
from app import app

client = TestClient(app)


def get_access_token():
    response = client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": jades_service.CSC_CLIENT_ID,
            "client_secret": jades_service.CSC_CLIENT_SECRET,
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_detached_jws_round_trip_and_sad_binding():
    document_hash = hashlib.sha256(b"canonical document").hexdigest()
    access_token = get_access_token()
    auth_headers = {"Authorization": f"Bearer {access_token}"}

    authorize_response = client.post(
        "/credentials/authorize",
        headers=auth_headers,
        json={
            "credentialID": jades_service.CSC_CREDENTIAL_ID,
            "numSignatures": 1,
            "hash": [document_hash],
            "hashAlgo": jades_service.HASH_ALGORITHM,
        },
    )
    assert authorize_response.status_code == 200
    sad = authorize_response.json()["SAD"]

    wrong_hash = hashlib.sha256(b"different document").hexdigest()
    mismatch_response = client.post(
        "/signatures/signHash",
        headers=auth_headers,
        json={
            "credentialID": jades_service.CSC_CREDENTIAL_ID,
            "SAD": sad,
            "hash": [wrong_hash],
            "hashAlgo": jades_service.HASH_ALGORITHM,
            "signAlgo": jades_service.SIGN_ALGORITHM,
        },
    )
    assert mismatch_response.status_code == 400

    sign_response = client.post(
        "/signatures/signHash",
        headers=auth_headers,
        json={
            "credentialID": jades_service.CSC_CREDENTIAL_ID,
            "SAD": sad,
            "hash": [document_hash],
            "hashAlgo": jades_service.HASH_ALGORITHM,
            "signAlgo": jades_service.SIGN_ALGORITHM,
        },
    )
    assert sign_response.status_code == 200
    protected_b64, detached, signature_b64 = sign_response.json()["signatures"][
        0
    ].split(".")
    assert detached == ""
    protected = json.loads(_decode_base64url(protected_b64))
    assert protected["alg"] == "RS256"
    assert "sigT" in protected

    certificate_der = base64.b64decode(protected["x5c"][0])
    certificate = x509.load_der_x509_certificate(certificate_der)
    assert (
        certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        == jades_service.SIGNER_COMMON_NAME
    )
    assert "piri" not in certificate.subject.rfc4514_string().lower()
    assert "feline" not in certificate.subject.rfc4514_string().lower()

    signature = _decode_base64url(signature_b64)
    hash_b64 = (
        base64.urlsafe_b64encode(bytes.fromhex(document_hash))
        .rstrip(b"=")
        .decode("ascii")
    )
    certificate.public_key().verify(
        signature,
        f"{protected_b64}.{hash_b64}".encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    replay_response = client.post(
        "/signatures/signHash",
        headers=auth_headers,
        json={
            "credentialID": jades_service.CSC_CREDENTIAL_ID,
            "SAD": sad,
            "hash": [document_hash],
            "hashAlgo": jades_service.HASH_ALGORITHM,
            "signAlgo": jades_service.SIGN_ALGORITHM,
        },
    )
    assert replay_response.status_code == 400


def test_csc_v2_authorize_and_sign_hash_returns_raw_base64_signature():
    digest = hashlib.sha256(b"CSC document").digest()
    encoded_digest = base64.b64encode(digest).decode("ascii")
    auth_headers = {"Authorization": f"Bearer {get_access_token()}"}

    authorize_response = client.post(
        "/csc/v2/credentials/authorize",
        headers=auth_headers,
        json={
            "credentialID": jades_service.CSC_CREDENTIAL_ID,
            "numSignatures": 1,
            "hashes": [encoded_digest],
            "hashAlgorithmOID": jades_service.HASH_ALGORITHM,
        },
    )
    assert authorize_response.status_code == 200
    authorize_body = authorize_response.json()
    assert authorize_body["expiresIn"] == jades_service.SAD_TTL

    sign_response = client.post(
        "/csc/v2/signatures/signHash",
        headers=auth_headers,
        json={
            "credentialID": jades_service.CSC_CREDENTIAL_ID,
            "SAD": authorize_body["SAD"],
            "hashes": [encoded_digest],
            "hashAlgorithmOID": jades_service.HASH_ALGORITHM,
            "signAlgo": jades_service.SIGN_ALGORITHM,
        },
    )
    assert sign_response.status_code == 200
    signatures = sign_response.json()["signatures"]
    assert len(signatures) == 1
    signature = base64.b64decode(signatures[0], validate=True)

    certificate = x509.load_pem_x509_certificate(jades_service.CERT_PATH.read_bytes())
    certificate.public_key().verify(
        signature,
        digest,
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA256()),
    )


def test_rejects_invalid_client_token_and_hash():
    invalid_client = client.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": jades_service.CSC_CLIENT_ID,
            "client_secret": "wrong",
        },
    )
    assert invalid_client.status_code == 401

    unauthorized = client.post(
        "/credentials/authorize",
        json={
            "credentialID": jades_service.CSC_CREDENTIAL_ID,
            "numSignatures": 1,
            "hash": [hashlib.sha256(b"document").hexdigest()],
            "hashAlgo": jades_service.HASH_ALGORITHM,
        },
    )
    assert unauthorized.status_code == 401

    token = get_access_token()
    invalid_hash = client.post(
        "/credentials/authorize",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "credentialID": jades_service.CSC_CREDENTIAL_ID,
            "numSignatures": 1,
            "hash": ["not-a-sha256-hash"],
            "hashAlgo": jades_service.HASH_ALGORITHM,
        },
    )
    assert invalid_hash.status_code == 400


def test_production_rejects_demo_credentials(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setattr(jades_service, "CSC_CLIENT_ID", jades_service.DEMO_CLIENT_ID)
    monkeypatch.setattr(
        jades_service, "CSC_CLIENT_SECRET", jades_service.DEMO_CLIENT_SECRET
    )
    with pytest.raises(RuntimeError, match="Production requires"):
        jades_service.validate_configuration()


def test_signer_certificate_is_independent_generic_identity(monkeypatch, tmp_path):
    key_path = tmp_path / "signer_key.pem"
    cert_path = tmp_path / "signer_cert.pem"
    monkeypatch.setattr(jades_service, "KEY_PATH", key_path)
    monkeypatch.setattr(jades_service, "CERT_PATH", cert_path)

    generated_key_path, generated_cert_path = jades_service.ensure_signing_identity()
    assert generated_key_path == key_path
    assert generated_cert_path == cert_path
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    subject = certificate.subject.rfc4514_string().lower()
    assert "piri" not in subject
    assert "cat" not in subject
    assert "feline" not in subject


def test_signing_identity_rejects_partial_files(monkeypatch, tmp_path):
    key_path = tmp_path / "signer_key.pem"
    cert_path = tmp_path / "signer_cert.pem"
    monkeypatch.setattr(jades_service, "KEY_PATH", key_path)
    monkeypatch.setattr(jades_service, "CERT_PATH", cert_path)
    key_path.write_bytes(b"existing private key")

    with pytest.raises(RuntimeError, match="both exist or both be absent"):
        jades_service.ensure_signing_identity()


def test_signing_identity_rejects_mismatched_key_and_certificate(monkeypatch, tmp_path):
    key_path = tmp_path / "signer_key.pem"
    cert_path = tmp_path / "signer_cert.pem"
    monkeypatch.setattr(jades_service, "KEY_PATH", key_path)
    monkeypatch.setattr(jades_service, "CERT_PATH", cert_path)
    jades_service.ensure_signing_identity()

    other_key_path = tmp_path / "other_key.pem"
    other_cert_path = tmp_path / "other_cert.pem"
    monkeypatch.setattr(jades_service, "KEY_PATH", other_key_path)
    monkeypatch.setattr(jades_service, "CERT_PATH", other_cert_path)
    jades_service.ensure_signing_identity()

    key_path.write_bytes(other_key_path.read_bytes())
    monkeypatch.setattr(jades_service, "KEY_PATH", key_path)
    monkeypatch.setattr(jades_service, "CERT_PATH", cert_path)

    with pytest.raises(RuntimeError, match="does not match"):
        jades_service.ensure_signing_identity()
