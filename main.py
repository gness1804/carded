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

# ISO-BMFF 'ftyp' brands that indicate a HEIC/HEIF still image.
_HEIF_FTYP_BRANDS: frozenset[bytes] = frozenset(
    {
        b"heic", b"heix", b"heim", b"heis",
        b"hevc", b"hevx", b"hevm", b"hevs",
        b"mif1", b"msf1", b"heif",
    }
)


def _sniff_image_mime(data: bytes) -> str | None:
    """Detect the real image format from magic bytes.

    The client-supplied multipart Content-Type is fully attacker-controlled,
    so it cannot be trusted to decide how (or whether) to process an upload.
    This inspects the actual bytes and returns a normalized MIME type, or
    None if the bytes are not a recognized, supported image format.

    Returns one of: ``image/jpeg``, ``image/png``, ``image/webp``,
    ``image/heif`` (covers the whole HEIC/HEIF family), or None.
    """
    if len(data) < 12:
        return None
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    # HEIC/HEIF: ISO base media format — 'ftyp' box at offset 4, brand at 8.
    if data[4:8] == b"ftyp" and data[8:12] in _HEIF_FTYP_BRANDS:
        return "image/heif"
    return None

# Decompression-bomb guard for the HEIC -> JPEG re-encode. HEIC is highly
# compressed, so a small file can decode to an enormous raster and exhaust
# memory. ~50 MP comfortably covers any real phone camera (a 48 MP sensor is
# ~48 MP) while bounding the worst case. Only HEIC/HEIF inputs are decoded
# server-side; other formats are forwarded to BAML without a local decode.
_MAX_IMAGE_PIXELS: int = int(
    os.environ.get("MAX_IMAGE_PIXELS", str(50_000_000))
)

# JPEG quality for the HEIC -> JPEG re-encode. Business cards are dense small
# text and digit runs; Pillow's default (75, with 4:2:0 chroma subsampling)
# visibly degrades fine edges and is a likely contributor to OCR digit errors
# (see GitHub issue #1). 95 + no chroma subsampling keeps the re-encode near
# the visual quality of the HEIC source. Tunable via env.
_JPEG_QUALITY: int = int(os.environ.get("JPEG_QUALITY", "95"))

# Also bound Pillow's own global decompression-bomb guard so *any* Pillow
# decode (not just the hand-checked HEIC path) is capped, e.g. if a future
# code path opens a non-HEIC upload. Pillow raises DecompressionBombError
# above 2x this value and warns above 1x.
PilImage.MAX_IMAGE_PIXELS = _MAX_IMAGE_PIXELS

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
    # 2a. Cheap reject of an obviously-wrong declared Content-Type.
    normalized_mime = mime_type.lower().strip()
    if normalized_mime not in SUPPORTED_MIME_TYPES:
        raise UnsupportedMimeType(
            f"Unsupported MIME type: {mime_type!r}. "
            f"Accepted: {sorted(SUPPORTED_MIME_TYPES)}"
        )

    # 2b. The declared Content-Type is attacker-controlled — verify the actual
    # bytes and let the sniffed type drive routing (defends against non-image
    # uploads and polyglots disguised with a valid-looking Content-Type).
    sniffed_mime = _sniff_image_mime(image_data)
    if sniffed_mime is None:
        raise UnsupportedMimeType(
            f"Uploaded bytes are not a recognized image "
            f"(declared MIME type: {mime_type!r})."
        )
    normalized_mime = sniffed_mime

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
    try:
        pil_img = PilImage.open(buf_in)
    except Exception as exc:
        raise UnsupportedMimeType(
            f"Could not decode HEIC/HEIF image: {type(exc).__name__}"
        ) from exc

    # Decompression-bomb guard: reject before convert()/save() force a full
    # raster into memory.
    width, height = pil_img.size
    if width * height > _MAX_IMAGE_PIXELS:
        raise UnsupportedMimeType(
            f"Image resolution {width}x{height} exceeds the "
            f"{_MAX_IMAGE_PIXELS}-pixel processing limit."
        )

    # Convert to RGB to drop alpha channel if present; JPEG does not support it.
    pil_img = pil_img.convert("RGB")
    buf_out = io.BytesIO()
    # High quality + no chroma subsampling (4:4:4) preserves the fine text and
    # digit edges the extractor depends on. See GitHub issue #1.
    pil_img.save(
        buf_out,
        format="JPEG",
        quality=_JPEG_QUALITY,
        subsampling=0,
        optimize=True,
    )
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
