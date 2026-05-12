"""Carded extraction pipeline.

Entry point for the business-card extraction workflow. Accepts raw image
bytes plus a BYOK Anthropic API key and returns a tagged result
(Valid / NotABusinessCard / Illegible) or raises an exception that the
route layer maps to an appropriate HTTP status.

No owner-key fallback lives here. Key selection happens at the route layer
in Phase 4; this module only accepts a pre-selected key via the `api_key`
parameter and forwards it to BAML via `with_options`.
"""

import base64
import logging
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from typing import Union

import baml_py
import pillow_heif
from PIL import Image as PilImage
import io

from baml_client import b
from baml_client.types import BusinessCard, ValidationStatus
from validation import InputSanitizer

# Register the HEIF/HEIC opener once at module load so PIL can decode HEIC
# files. This is a no-op if the opener is already registered.
pillow_heif.register_heif_opener()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MIME allowlist
# ---------------------------------------------------------------------------

SUPPORTED_MIME_TYPES: frozenset[str] = frozenset(
    {
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/heic",
        "image/heif",
    }
)

_HEIC_MIME_TYPES: frozenset[str] = frozenset({"image/heic", "image/heif"})

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Valid:
    """The image was a valid, legible business card and fields were extracted."""

    card: BusinessCard


@dataclass(frozen=True)
class NotABusinessCard:
    """The image was not a business card (e.g. a photo of a dog, a receipt)."""

    message: str


@dataclass(frozen=True)
class Illegible:
    """The image appears to be a business card but text cannot be recovered."""

    message: str


ExtractionResult = Union[Valid, NotABusinessCard, Illegible]

# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------


class UnsupportedMimeType(Exception):
    """Raised when the uploaded file's MIME type is not in the allowlist.

    Callers should map this to HTTP 400 INVALID_FILE_TYPE.
    """


class ExtractionTimeout(Exception):
    """Raised when the BAML call exceeds the configured timeout.

    Callers should map this to HTTP 502 EXTRACTION_FAILED.
    """


class ExtractionError(Exception):
    """Wraps any unexpected BAML/runtime failure during extraction.

    Callers should map this to HTTP 502 EXTRACTION_FAILED.
    Internal error details are never surfaced to the client.
    """


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_card_from_bytes(
    image_data: bytes,
    mime_type: str,
    api_key: str,
    filename: str | None = None,
) -> ExtractionResult:
    """Extract business-card data from raw image bytes.

    Args:
        image_data: Raw bytes of the uploaded image.
        mime_type:  MIME type string from the upload (case-insensitive).
        api_key:    Anthropic API key supplied by the user (BYOK). Never
                    falls back to an env-level key — the caller is
                    responsible for providing a non-empty key.
        filename:   Original filename from the upload, if any. Sanitized
                    here as a defense-in-depth measure even though we do
                    not currently pass the filename to BAML — if we later
                    add filename metadata to the prompt, it is already safe.

    Returns:
        An ExtractionResult: Valid, NotABusinessCard, or Illegible.

    Raises:
        UnsupportedMimeType: If the MIME type is not in the allowlist.
        ExtractionTimeout:   If the BAML call exceeds the timeout.
        ExtractionError:     If any unexpected BAML/runtime error occurs.
    """
    # ------------------------------------------------------------------
    # 1. Sanitize filename (defense in depth — not sent to BAML currently)
    # ------------------------------------------------------------------
    if filename is not None:
        sanitizer = InputSanitizer()
        filename = sanitizer.sanitize(filename)  # noqa: F841  (safe for future use)

    # ------------------------------------------------------------------
    # 2. Validate MIME type
    # ------------------------------------------------------------------
    normalized_mime = mime_type.lower().strip()
    if normalized_mime not in SUPPORTED_MIME_TYPES:
        raise UnsupportedMimeType(
            f"Unsupported MIME type: {mime_type!r}. "
            f"Accepted: {sorted(SUPPORTED_MIME_TYPES)}"
        )

    # ------------------------------------------------------------------
    # 3. HEIC → JPEG conversion
    # ------------------------------------------------------------------
    if normalized_mime in _HEIC_MIME_TYPES:
        image_data, normalized_mime = _convert_heic_to_jpeg(image_data)

    # ------------------------------------------------------------------
    # 4. Build BAML Image and call ExtractBusinessCard
    # ------------------------------------------------------------------
    b64 = base64.b64encode(image_data).decode("ascii")
    img = baml_py.Image.from_base64(media_type=normalized_mime, base64=b64)

    card = _call_baml(img, api_key)

    # ------------------------------------------------------------------
    # 5. Branch on validationStatus
    # ------------------------------------------------------------------
    if card.validationStatus == ValidationStatus.VALID:
        return Valid(card=card)
    elif card.validationStatus == ValidationStatus.NOT_A_BUSINESS_CARD:
        return NotABusinessCard(message=card.validationMessage)
    else:
        # ValidationStatus.ILLEGIBLE
        return Illegible(message=card.validationMessage)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _convert_heic_to_jpeg(image_data: bytes) -> tuple[bytes, str]:
    """Convert HEIC/HEIF bytes to JPEG in-memory.

    Returns:
        Tuple of (jpeg_bytes, "image/jpeg").
    """
    buf_in = io.BytesIO(image_data)
    pil_img = PilImage.open(buf_in)
    # Convert to RGB to drop alpha channel if present; JPEG does not support it.
    pil_img = pil_img.convert("RGB")
    buf_out = io.BytesIO()
    pil_img.save(buf_out, format="JPEG")
    return buf_out.getvalue(), "image/jpeg"


def _call_baml(img: baml_py.Image, api_key: str) -> BusinessCard:
    """Invoke BAML ExtractBusinessCard with a per-call timeout.

    Uses a ThreadPoolExecutor so the sync BAML call can be interrupted
    via future.result(timeout=...). On timeout, raises ExtractionTimeout.
    On any other BAML/runtime error, wraps in ExtractionError.
    """
    timeout_seconds = float(
        os.environ.get("EXTRACTION_TIMEOUT_SECONDS", "60")
    )

    def _baml_call() -> BusinessCard:
        client = b.with_options(env={"ANTHROPIC_API_KEY": api_key})
        return client.ExtractBusinessCard(image=img)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_baml_call)
        try:
            return future.result(timeout=timeout_seconds)
        except FuturesTimeoutError:
            # Cancel best-effort (BAML sync thread may not be cancellable,
            # but we surface the timeout to the caller immediately).
            future.cancel()
            logger.error(
                "BAML ExtractBusinessCard timed out after %.0f seconds",
                timeout_seconds,
            )
            raise ExtractionTimeout(
                f"BAML call exceeded {timeout_seconds:.0f}s timeout"
            )
        except Exception as exc:
            logger.exception(
                "BAML ExtractBusinessCard raised an unexpected error: %s",
                type(exc).__name__,
            )
            raise ExtractionError(
                f"Unexpected error during extraction: {type(exc).__name__}"
            ) from exc
