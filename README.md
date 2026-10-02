# JAdES Signing Service

A CSC-compatible API for authorizing SHA-256 hashes and signing them as detached JWS values.

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
- `POST /credentials/authorize` requires a bearer token, authorizes one SHA-256 hash, and returns a single-use SAD valid for 300 seconds.
- `POST /signatures/signHash` requires a bearer token and returns a detached compact JWS for the authorized hash.

## Production

Set `APP_ENV=production` and provide a non-default `CSC_CLIENT_ID` and `CSC_CLIENT_SECRET` of at least 32 characters. Persist and protect `SIGNING_DATA_DIR`; its generated self-signed certificate is not automatically trusted by clients. Tokens, SADs, and rate limits are held in memory, so use one worker and one replica.

Set `CSC_CREDENTIAL_ID` to configure the credential identifier. `SIGNING_KEY_PATH` and `SIGNING_CERT_PATH` can override the default files under `SIGNING_DATA_DIR`.

## Postman

Import the [Postman collection and guide](postman/README.md) to mock the API or send requests to a local service. The saved mock signature is illustrative, not cryptographically valid.

## Tests

```powershell
pytest -q
```
