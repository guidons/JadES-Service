import asyncio
import logging
import time
from collections import deque
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from jades_service import (
    ACCESS_TOKEN_TTL,
    HASH_ALGORITHM,
    SAD_TTL,
    authorize_hashes,
    decode_csc_hash,
    ensure_signing_identity,
    is_valid_access_token,
    is_valid_client,
    issue_access_token,
    sign_detached_jws,
    sign_hash_values,
    validate_configuration,
)

logger = logging.getLogger(__name__)
RATE_LIMIT_WINDOW = 60.0
MAX_RATE_LIMIT_KEYS = 10000
_rate_limit_events: dict[str, deque[float]] = {}


def _enforce_rate_limit(key: str, limit: int) -> None:
    now = time.time()
    if len(_rate_limit_events) >= MAX_RATE_LIMIT_KEYS and key not in _rate_limit_events:
        for old_key in list(_rate_limit_events)[
            : max(1, len(_rate_limit_events) // 10)
        ]:
            _rate_limit_events.pop(old_key, None)
    events = _rate_limit_events.setdefault(key, deque())
    while events and events[0] <= now - RATE_LIMIT_WINDOW:
        events.popleft()
    if len(events) >= limit:
        retry_after = max(1, int(RATE_LIMIT_WINDOW - (now - events[0])))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please retry later.",
            headers={"Retry-After": str(retry_after)},
        )
    events.append(now)


async def require_csc_token(
    request: Request, authorization: str = Header(default="")
) -> None:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not is_valid_access_token(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing bearer token",
        )
    _enforce_rate_limit(
        f"csc:{request.client.host if request.client else 'unknown'}", 60
    )


class AuthorizeRequest(BaseModel):
    credentialID: str = Field(max_length=128)
    numSignatures: int = Field(ge=1, le=1)
    hash: list[str] = Field(min_length=1, max_length=1)
    hashAlgo: str = Field(max_length=64)


class SignHashRequest(BaseModel):
    credentialID: str = Field(max_length=128)
    SAD: str = Field(max_length=256)
    hash: list[str] = Field(min_length=1, max_length=1)
    hashAlgo: str = Field(max_length=64)
    signAlgo: str = Field(max_length=64)


class CSCAuthorizeRequest(BaseModel):
    credentialID: str = Field(max_length=128)
    numSignatures: int = Field(ge=1, le=1)
    hashes: list[str] = Field(min_length=1, max_length=1)
    hashAlgorithmOID: str = Field(max_length=64)


class CSCSignHashRequest(BaseModel):
    credentialID: str = Field(max_length=128)
    SAD: str = Field(max_length=256)
    hashes: list[str] = Field(min_length=1, max_length=1)
    hashAlgorithmOID: str = Field(max_length=64)
    signAlgo: str = Field(max_length=64)


@asynccontextmanager
async def lifespan(_application: FastAPI):
    validate_configuration()
    ensure_signing_identity()
    yield


app = FastAPI(
    title="JAdES Signing Service",
    description="CSC-compatible remote signing service for detached JWS/JAdES signatures.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "JAdES Signing Service"}


@app.post("/oauth2/token")
async def oauth2_token(
    request: Request,
    grant_type: str = Form("", max_length=64),
    client_id: str = Form("", max_length=128),
    client_secret: str = Form("", max_length=256),
):
    _enforce_rate_limit(
        f"oauth:{request.client.host if request.client else 'unknown'}", 10
    )
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="grant_type must be client_credentials",
        )
    if not is_valid_client(client_id, client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )
    return {
        "access_token": issue_access_token(client_id),
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL,
    }


@app.post("/credentials/authorize", dependencies=[Depends(require_csc_token)])
async def credentials_authorize(payload: AuthorizeRequest):
    if payload.hashAlgo != HASH_ALGORITHM:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported hashAlgo"
        )
    try:
        sad = authorize_hashes(
            payload.credentialID, payload.hash, payload.numSignatures
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return {"SAD": sad, "expires_in": SAD_TTL}


@app.post("/signatures/signHash", dependencies=[Depends(require_csc_token)])
async def signatures_sign_hash(payload: SignHashRequest):
    try:
        signature = await asyncio.to_thread(
            sign_detached_jws,
            credential_id=payload.credentialID,
            sad=payload.SAD,
            hashes=payload.hash,
            hash_algo=payload.hashAlgo,
            sign_algo=payload.signAlgo,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Exception:
        logger.exception("JAdES signing failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Cryptographic signing failed.",
        ) from None
    return {"signatures": [signature]}


@app.post("/csc/v2/credentials/authorize", dependencies=[Depends(require_csc_token)])
async def csc_credentials_authorize(payload: CSCAuthorizeRequest):
    if payload.hashAlgorithmOID != HASH_ALGORITHM:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported hashAlgorithmOID",
        )
    try:
        for hash_value in payload.hashes:
            decode_csc_hash(hash_value)
        sad = authorize_hashes(
            payload.credentialID, payload.hashes, payload.numSignatures
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return {"SAD": sad, "expiresIn": SAD_TTL}


@app.post("/csc/v2/signatures/signHash", dependencies=[Depends(require_csc_token)])
async def csc_signatures_sign_hash(payload: CSCSignHashRequest):
    try:
        signatures = await asyncio.to_thread(
            sign_hash_values,
            credential_id=payload.credentialID,
            sad=payload.SAD,
            hashes=payload.hashes,
            hash_algo=payload.hashAlgorithmOID,
            sign_algo=payload.signAlgo,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Exception:
        logger.exception("CSC signature operation failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Cryptographic signing failed.",
        ) from None
    return {"signatures": signatures}
