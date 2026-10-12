# JAdES Signing Service

A lightweight mock signing service for exercising a subset of the Cloud Signature Consortium (CSC) API v2 signing flow. It can authorize a SHA-256 digest and sign it with a local RSA key.

> **Evaluation and testing only — not for production use.** This service uses demo credentials, a self-signed signing certificate, in-memory tokens and SADs, and a local software key. It is not a complete CSC implementation or a production remote-signing service.

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Development credentials default to `csc_demo_client` / `csc_demo_client_secret`.

## API

- `GET /health`
- `POST /oauth2/token` accepts `grant_type=client_credentials`, `client_id`, and `client_secret` as form fields.
- `POST /csc/v2/credentials/authorize` requires a bearer token and authorizes one Base64-encoded SHA-256 digest, returning a single-use SAD valid for 300 seconds.
- `POST /csc/v2/signatures/signHash` requires a bearer token and that SAD, and returns a Base64-encoded RSA signature of the authorized digest.
- `POST /credentials/authorize` and `POST /signatures/signHash` provide legacy non-CSC routes; the latter returns a detached compact JWS.

## CSC compatibility limits

The CSC v2 routes cover only a narrow, synchronous, single-digest SHA-256/RSA happy path. They do not provide the full CSC protocol surface. In particular:

- Multiple hashes per authorization or signing request are not supported.
- CSC-standard error response bodies and status behavior are not fully implemented.
- Discovery and credential-information endpoints such as `/info`, `/credentials/list`, and `/credentials/info` are not implemented.
- Other CSC algorithms, authorization modes, and optional operations are outside this mock's scope.

Generic CSC clients that require these features will not interoperate without adaptation. The `/csc/v2` routes are an example/testing subset, not a claim of full CSC compatibility.

The default client credentials are for local testing. `CSC_CREDENTIAL_ID` configures the credential identifier; `SIGNING_DATA_DIR` chooses where the local key and certificate are stored, and `SIGNING_KEY_PATH` and `SIGNING_CERT_PATH` can override their paths. The generated certificate is self-signed. Tokens, SADs, and rate-limit state are held in memory.

## Postman

Import the [Postman collection and guide](postman/README.md) to mock the API or send requests to a local service. The saved mock signature is illustrative, not cryptographically valid.

## Tests

```powershell
pytest -q
```
