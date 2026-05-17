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

import hashlib
import hmac
import logging
import os
import threading
import time
import unicodedata
import uuid
from collections import deque

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
    NotABusinessCard,
    UnsupportedMimeType,
    Valid,
    extract_card_from_bytes,
)
from vcard_builder import build_vcf, vcf_filename
from google_csv_builder import build_google_csv, csv_filename

# Keep in sync with pyproject.toml [project] version. Surfaced via /health.
__version__ = "0.3.1"

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

# Rate limiting — sliding-window, per-client-IP, in-process. Defaults are
# generous for a single-user BYOK app; tune via env in production. This is
# defense-in-depth abuse mitigation, not an authz control, and is not a
# substitute for an edge/proxy limiter at scale.
_RATE_LIMIT_WINDOW_SECONDS: int = int(
    os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60")
)
_RATE_LIMIT_PROCESS: int = int(os.environ.get("RATE_LIMIT_PROCESS", "15"))
_RATE_LIMIT_SESSION_KEY: int = int(
    os.environ.get("RATE_LIMIT_SESSION_KEY", "20")
)

# Number of trusted reverse proxies in front of the app. X-Forwarded-For is a
# left-to-right list "<client>, <proxy1>, <proxy2>, ..." where each hop appends
# the address that connected to it; only the right-most N entries are added by
# infrastructure we control. The real client is the entry N positions from the
# right. Render fronts the app with one proxy layer -> default 1. Set to 0 to
# ignore X-Forwarded-For entirely (direct-connection deployments).
_TRUSTED_PROXY_HOPS: int = int(os.environ.get("TRUSTED_PROXY_HOPS", "1"))

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
# RateLimiter — in-memory, sliding-window, thread-safe
# ---------------------------------------------------------------------------


class RateLimiter:
    """Thread-safe sliding-window rate limiter keyed by an arbitrary string.

    Tracks request timestamps per key in a bounded deque, evicting entries
    older than the window on each check. Memory is bounded by the number of
    distinct keys (client IPs) seen within a window — acceptable for an
    in-process, single-node MVP limiter.
    """

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Record a hit for ``key``; return False if it exceeds the limit."""
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            # Opportunistically sweep every key so the map cannot grow
            # unbounded as clients (or spoofed X-Forwarded-For values) churn.
            for existing_key in list(self._hits.keys()):
                bucket = self._hits[existing_key]
                while bucket and bucket[0] <= cutoff:
                    bucket.popleft()
                if not bucket:
                    del self._hits[existing_key]

            bucket = self._hits.get(key)
            if bucket is None:
                bucket = deque()
                self._hits[key] = bucket
            if len(bucket) >= self._max:
                return False
            bucket.append(now)
            return True


_session_key_limiter = RateLimiter(
    _RATE_LIMIT_SESSION_KEY, _RATE_LIMIT_WINDOW_SECONDS
)
_process_limiter = RateLimiter(_RATE_LIMIT_PROCESS, _RATE_LIMIT_WINDOW_SECONDS)

# ---------------------------------------------------------------------------
# FastAPI app + static files + templates
# ---------------------------------------------------------------------------

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
templates.env.globals["app_version"] = __version__

# ---------------------------------------------------------------------------
# Security headers middleware (L4)
# ---------------------------------------------------------------------------

# img-src allows blob:/data: for the client-side upload preview. No inline
# scripts or styles exist in the templates, so default-src 'self' is enough
# to cover script-src/style-src without 'unsafe-inline'.
_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' blob: data:; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


@app.middleware("http")
async def _security_headers_middleware(request: Request, call_next):
    """Attach hardening response headers to every response."""
    response = await call_next(request)
    for header, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response

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
    """Strip control / format characters and cap length on LLM-derived text.

    Removes every Unicode "Cc" (control — both ASCII C0 and the C1 range
    U+0080–U+009F) and "Cf" (format) character, keeping only ``\\n`` and
    ``\\t``. The "Cf" category covers bidi overrides/isolates (U+202A–U+202E,
    U+2066–U+2069), directional marks (U+200E/200F), zero-width characters
    (U+200B–U+200D), and the BOM (U+FEFF) — all usable for visual spoofing.

    Do NOT HTML-escape here — Jinja autoescape handles render-time escaping
    and JSON consumers should not receive double-escaped output.
    """
    cleaned = "".join(
        c
        for c in s
        if (c == "\n" or c == "\t")
        or unicodedata.category(c) not in ("Cc", "Cf")
    )
    return cleaned[:max_len]


def _get_session_key(request: Request) -> str | None:
    """Read and decrypt the carded_session cookie. Returns None on any failure."""
    token = request.cookies.get("carded_session")
    if not token:
        return None
    return session_module.decrypt_api_key(token)


def _client_key(request: Request) -> str:
    """Client identifier for rate limiting, resilient to X-Forwarded-For spoofing.

    The left-most X-Forwarded-For entries are attacker-controlled — a client
    can prepend arbitrary values. Only the right-most ``_TRUSTED_PROXY_HOPS``
    entries are appended by infrastructure we control, so the genuine client
    is the entry ``_TRUSTED_PROXY_HOPS`` positions from the right. If the
    header is missing, shorter than expected, or trust is disabled
    (hops == 0), fall back to the direct socket peer.
    """
    peer = request.client.host if request.client else "unknown"
    if _TRUSTED_PROXY_HOPS <= 0:
        return peer
    xff = request.headers.get("x-forwarded-for")
    if not xff:
        return peer
    parts = [p.strip() for p in xff.split(",") if p.strip()]
    if len(parts) >= _TRUSTED_PROXY_HOPS:
        return parts[-_TRUSTED_PROXY_HOPS]
    # Chain shorter than configured — header is malformed or spoofed; do not
    # trust it, fall back to the socket peer.
    return peer


def _rate_limited_response() -> JSONResponse:
    """Standard 429 response for rate-limited endpoints."""
    return JSONResponse(
        status_code=429,
        content={
            "error": "rate_limited",
            "message": "Too many requests. Please wait a moment and try again.",
        },
    )


def _session_binding(request: Request) -> str:
    """HMAC of the carded_session cookie value.

    Download tokens embed this so a leaked or shared token cannot be redeemed
    from a different session. An absent cookie hashes to a stable value, so a
    token minted without a session still only redeems without a session.
    """
    cookie_value = request.cookies.get("carded_session", "")
    return hmac.new(
        _DOWNLOAD_TOKEN_SECRET.encode(),
        cookie_value.encode(),
        hashlib.sha256,
    ).hexdigest()


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
async def set_session_key(request: Request, submission: KeySubmission) -> Response:
    """Accept a BYOK Anthropic API key, validate its format, and store in cookie.

    Returns:
        200 with JSON ``{"ok": true, "is_owner": <bool>, "masked_key": <str>}``
        and the Set-Cookie header on success.
        400 JSON error on invalid key format.
        429 JSON error when the per-client rate limit is exceeded.
    """
    if not _session_key_limiter.allow(_client_key(request)):
        return _rate_limited_response()

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
        429 when the per-client rate limit is exceeded.
        See interface contract for error shapes.
    """
    # 0. Rate limit (defense-in-depth abuse mitigation)
    if not _process_limiter.allow(_client_key(request)):
        return _rate_limited_response()

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
        # Bind the token to the issuing session (L3): the signed payload
        # carries an HMAC of the session cookie, verified again on download.
        signed_token = _SERIALIZER.dumps([token_id, _session_binding(request)])
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
async def download_vcf(request: Request, token: str) -> Response:
    """Download the extracted business card as a vCard 3.0 file.

    Args:
        token: Signed token issued by POST /process.

    Returns:
        200 with text/vcard body and Content-Disposition attachment header.
        400 if the signature is invalid or the token was issued to a
            different session (binding mismatch).
        404 if the token is unknown (never issued or already swept).
        410 if the token has expired.
    """
    token_id, error_response = _resolve_token(token, request)
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
async def download_csv(request: Request, token: str) -> Response:
    """Download the extracted business card as a Google Contacts CSV file.

    Args:
        token: Signed token issued by POST /process.

    Returns:
        200 with text/csv body and Content-Disposition attachment header.
        400 if the signature is invalid or the token was issued to a
            different session (binding mismatch).
        404 if the token is unknown.
        410 if the token has expired.
    """
    token_id, error_response = _resolve_token(token, request)
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
    """Liveness probe for load-balancer / orchestrator health checks.

    Also surfaces the runtime version so deployments can be verified
    without inspecting the commit hash.
    """
    return {"status": "ok", "version": __version__}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_token(token: str, request: Request) -> tuple[str, Response | None]:
    """Unsign a download token and verify it was issued to this session.

    The signed payload is a ``[token_id, session_binding]`` pair. The binding
    is re-derived from the request's session cookie and compared in constant
    time, so a token leaked to another client cannot be redeemed.

    Returns (token_id, None) on success. On failure returns ("", error_response):
        410 — signature valid but expired.
        400 — signature invalid, payload malformed, or binding mismatch.
    """
    try:
        payload = _SERIALIZER.loads(token, max_age=_DOWNLOAD_TOKEN_TTL_SECONDS)
    except SignatureExpired:
        return "", Response(status_code=410)
    except BadSignature:
        return "", Response(status_code=400)

    if (
        not isinstance(payload, list)
        or len(payload) != 2
        or not all(isinstance(part, str) for part in payload)
    ):
        return "", Response(status_code=400)

    token_id, bound = payload
    if not hmac.compare_digest(bound, _session_binding(request)):
        return "", Response(status_code=400)
    return token_id, None
