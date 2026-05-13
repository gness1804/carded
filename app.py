"""Carded FastAPI application — Phase 4.

Routes:
    GET  /                   — index page (Jinja2 template)
    POST /session/key        — BYOK API key submission
    POST /process            — image upload + extraction
    GET  /download/vcf       — signed-token vCard download
    GET  /download/csv       — signed-token Google CSV download
    GET  /health             — liveness probe

Cookie model: carded_session contains a Fernet-encrypted API key. The
plaintext key never reaches the client. See session.py for encryption details.

Download tokens: short-lived signed UUIDs issued by /process and redeemed at
the download endpoints. Tokens are stored in an in-memory TokenStore with a
TTL enforced both server-side and by the itsdangerous signature.
"""

import logging
import os
import threading
import time
import uuid

from cryptography.fernet import Fernet  # noqa: F401 — used in tests via import
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from fastapi import FastAPI, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

import session as session_module
from main import (
    ExtractionError,
    ExtractionTimeout,
    Illegible,
    NotABusinessCard,
    UnsupportedMimeType,
    Valid,
    extract_card_from_bytes,
)
from vcard_builder import build_vcf, vcf_filename
from google_csv_builder import build_google_csv, csv_filename

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------

_DOWNLOAD_TOKEN_SECRET: str = os.environ.get("DOWNLOAD_TOKEN_SECRET", "")
if not _DOWNLOAD_TOKEN_SECRET:
    # Generate a random per-process secret rather than a guessable default.
    # The in-memory TokenStore is also per-process, so an ephemeral secret
    # is sound for dev/test; production must set DOWNLOAD_TOKEN_SECRET so
    # tokens survive process restarts.
    import secrets as _secrets
    _DOWNLOAD_TOKEN_SECRET = _secrets.token_urlsafe(32)
    logger.warning(
        "DOWNLOAD_TOKEN_SECRET not set — using a random per-process secret. "
        "Set DOWNLOAD_TOKEN_SECRET in .env so tokens survive restarts."
    )

_DOWNLOAD_TOKEN_TTL_SECONDS: int = int(
    os.environ.get("DOWNLOAD_TOKEN_TTL_SECONDS", "900")
)

_MAX_FILE_SIZE_MB: int = int(os.environ.get("MAX_FILE_SIZE_MB", "10"))
_MAX_FILE_SIZE_BYTES: int = _MAX_FILE_SIZE_MB * 1024 * 1024

# Secure cookie flag: True by default (prod HTTPS); allow override for local HTTP dev.
_COOKIE_SECURE: bool = os.environ.get("COOKIE_SECURE", "true").lower() == "true"

_SERIALIZER = URLSafeTimedSerializer(_DOWNLOAD_TOKEN_SECRET)

# ---------------------------------------------------------------------------
# TokenStore — in-memory, TTL-enforced, thread-safe
# ---------------------------------------------------------------------------


class TokenStore:
    """Thread-safe in-memory store for short-lived download tokens.

    Each entry is keyed by a UUID string and holds the card dict plus the
    insertion timestamp. Expired entries are lazily evicted on each ``get``
    call to keep memory bounded.
    """

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._store: dict[str, tuple[float, dict]] = {}
        self._lock = threading.Lock()

    def put(self, key: str, card: dict) -> None:
        """Store a card dict under ``key``, recording the current timestamp."""
        with self._lock:
            self._store[key] = (time.time(), card)

    def get(self, key: str) -> dict | None:
        """Retrieve a card dict by key, returning None if missing or expired.

        Opportunistically sweeps all expired entries on each call to prevent
        unbounded memory growth.
        """
        with self._lock:
            now = time.time()
            # Sweep expired entries before looking up the requested key.
            expired_keys = [
                k for k, (ts, _) in self._store.items()
                if now - ts >= self._ttl
            ]
            for k in expired_keys:
                self._store.pop(k, None)

            entry = self._store.get(key)
            if entry is None:
                return None
            _ts, card = entry
            # The sweep above already removed expired entries, so if we reach
            # here the entry is still valid.
            return card


_token_store = TokenStore(ttl_seconds=_DOWNLOAD_TOKEN_TTL_SECONDS)

# ---------------------------------------------------------------------------
# FastAPI app + static files + templates
# ---------------------------------------------------------------------------

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ---------------------------------------------------------------------------
# Pydantic request model
# ---------------------------------------------------------------------------


class KeySubmission(BaseModel):
    api_key: str

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def is_owner(api_key: str | None) -> bool:
    """True iff api_key matches OWNER_ANTHROPIC_API_KEY env var (and env is non-empty)."""
    if not api_key:
        return False
    owner = os.environ.get("OWNER_ANTHROPIC_API_KEY", "")
    return bool(owner) and api_key == owner


def _sanitize_detail(s: str, max_len: int = 200) -> str:
    """Strip control characters (ASCII < 0x20 except \\n/\\t) and cap length.

    Do NOT HTML-escape here — Jinja autoescape handles render-time escaping
    and JSON consumers should not receive double-escaped output.
    """
    cleaned = "".join(c for c in s if c == "\n" or c == "\t" or ord(c) >= 0x20)
    return cleaned[:max_len]


def _get_session_key(request: Request) -> str | None:
    """Read and decrypt the carded_session cookie. Returns None on any failure."""
    token = request.cookies.get("carded_session")
    if not token:
        return None
    return session_module.decrypt_api_key(token)


def _set_session_cookie(response: Response, token: str) -> None:
    """Attach the carded_session cookie to a response with correct security flags."""
    response.set_cookie(
        key="carded_session",
        value=token,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite="lax",
        max_age=86400,
        path="/",
    )

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/")
async def index(request: Request) -> Response:
    """Render the main page.

    Context vars for Jinja2:
        has_session (bool):    True if a valid carded_session cookie is present.
        masked_key (str|None): Masked API key display string, or None.
        is_owner (bool):       True if the stored key matches the owner key.
    """
    api_key = _get_session_key(request)
    has_session = api_key is not None
    masked_key = session_module.mask_api_key(api_key) if has_session else None
    owner_flag = is_owner(api_key) if has_session else False

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "has_session": has_session,
            "masked_key": masked_key,
            "is_owner": owner_flag,
        },
    )


@app.post("/session/key")
async def set_session_key(submission: KeySubmission) -> Response:
    """Accept a BYOK Anthropic API key, validate its format, and store in cookie.

    Returns:
        200 with JSON ``{"ok": true, "is_owner": <bool>, "masked_key": <str>}``
        and the Set-Cookie header on success.
        400 JSON error on invalid key format.
    """
    api_key = submission.api_key

    if not api_key.startswith("sk-ant-"):
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_api_key_format",
                "message": "API key must begin with 'sk-ant-'.",
            },
        )

    token = session_module.encrypt_api_key(api_key)
    masked = session_module.mask_api_key(api_key)
    owner_flag = is_owner(api_key)

    response = JSONResponse(
        status_code=200,
        content={"ok": True, "is_owner": owner_flag, "masked_key": masked},
    )
    _set_session_cookie(response, token)
    return response


@app.delete("/session/key")
async def clear_session_key() -> Response:
    """Clear the carded_session cookie so the next request has no API key.

    Mirrors Receipt Ranger's "Change Key" UX: the encrypted key is removed
    from server-side state (the cookie) before the user enters a new one.
    """
    response = JSONResponse(status_code=200, content={"ok": True})
    response.delete_cookie(key="carded_session", path="/")
    return response


@app.post("/process")
async def process(request: Request, file: UploadFile) -> Response:
    """Process an uploaded business-card image.

    Steps:
        1. Authenticate via carded_session cookie.
        2. Enforce MAX_FILE_SIZE_MB via Content-Length header (cheap path)
           and actual byte count after read.
        3. Call extract_card_from_bytes.
        4. On Valid: mint a signed download token, store card, return JSON.
        5. On failure: return the appropriate error code per the contract.

    Returns:
        200 ``{"token": "<signed>", "card": <card_dict>}`` on success.
        See interface contract for error shapes.
    """
    # 1. Auth
    api_key = _get_session_key(request)
    if api_key is None:
        return JSONResponse(
            status_code=401,
            content={
                "error": "missing_api_key",
                "message": "Please enter your Anthropic API key to continue.",
            },
        )

    # 2a. Cheap size check via Content-Length header (avoids reading the body).
    content_length_header = request.headers.get("content-length")
    if content_length_header is not None:
        try:
            if int(content_length_header) > _MAX_FILE_SIZE_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": "file_too_large",
                        "message": f"File exceeds the {_MAX_FILE_SIZE_MB} MB limit.",
                    },
                )
        except ValueError:
            pass  # Malformed header — defer to the byte-level check below.

    # 2b. Read bytes and enforce actual size limit.
    image_data = await file.read()
    if len(image_data) > _MAX_FILE_SIZE_BYTES:
        return JSONResponse(
            status_code=413,
            content={
                "error": "file_too_large",
                "message": f"File exceeds the {_MAX_FILE_SIZE_MB} MB limit.",
            },
        )

    # 3. Extract
    try:
        result = extract_card_from_bytes(
            image_data,
            file.content_type or "",
            api_key,
            filename=file.filename,
        )
    except UnsupportedMimeType:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_file_type",
                "message": "Unsupported file type. Please upload a JPEG, PNG, WebP, or HEIC image.",
            },
        )
    except (ExtractionTimeout, ExtractionError):
        logger.error("Extraction failed for file %r", file.filename)
        return JSONResponse(
            status_code=502,
            content={
                "error": "extraction_failed",
                "message": "AI extraction failed. Please try again.",
            },
        )

    # 4. Branch on result type
    if isinstance(result, Valid):
        card_dict = result.card.model_dump()
        token_id = str(uuid.uuid4())
        _token_store.put(token_id, card_dict)
        signed_token = _SERIALIZER.dumps(token_id)
        return JSONResponse(
            status_code=200,
            content={"token": signed_token, "card": card_dict},
        )

    if isinstance(result, NotABusinessCard):
        return JSONResponse(
            status_code=422,
            content={
                "error": "not_a_business_card",
                "message": "Please upload an image of a business card.",
                "detail": _sanitize_detail(result.message),
            },
        )

    # Illegible
    return JSONResponse(
        status_code=422,
        content={
            "error": "illegible",
            "message": "We couldn't read this card clearly. Please upload a sharper or higher-resolution copy.",
            "detail": _sanitize_detail(result.message),
        },
    )


@app.get("/download/vcf")
async def download_vcf(token: str) -> Response:
    """Download the extracted business card as a vCard 3.0 file.

    Args:
        token: Signed UUID issued by POST /process.

    Returns:
        200 with text/vcard body and Content-Disposition attachment header.
        400 if the signature is invalid (tampered token).
        404 if the token is unknown (never issued or already swept).
        410 if the token has expired.
    """
    token_id, error_response = _resolve_token(token)
    if error_response is not None:
        return error_response

    card_dict = _token_store.get(token_id)
    if card_dict is None:
        return Response(status_code=404)

    vcf = build_vcf(card_dict)
    filename = vcf_filename(card_dict)
    return Response(
        content=vcf,
        media_type="text/vcard; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/download/csv")
async def download_csv(token: str) -> Response:
    """Download the extracted business card as a Google Contacts CSV file.

    Args:
        token: Signed UUID issued by POST /process.

    Returns:
        200 with text/csv body and Content-Disposition attachment header.
        400 if the signature is invalid (tampered token).
        404 if the token is unknown.
        410 if the token has expired.
    """
    token_id, error_response = _resolve_token(token)
    if error_response is not None:
        return error_response

    card_dict = _token_store.get(token_id)
    if card_dict is None:
        return Response(status_code=404)

    csv_content = build_google_csv(card_dict)
    filename = csv_filename(card_dict)
    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/health")
async def health() -> dict:
    """Liveness probe for load-balancer / orchestrator health checks."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_token(token: str) -> tuple[str, Response | None]:
    """Unsign a download token and return (token_id, None) on success.

    On failure returns ("", error_response) where error_response is a
    ready-to-return Response with the appropriate status code.
    """
    try:
        token_id: str = _SERIALIZER.loads(
            token, max_age=_DOWNLOAD_TOKEN_TTL_SECONDS
        )
        return token_id, None
    except SignatureExpired:
        return "", Response(status_code=410)
    except BadSignature:
        return "", Response(status_code=400)
