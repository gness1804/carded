"""Integration tests — real BAML/LLM extraction against fixture cards.

These tests call the live Anthropic API via BAML. They are gated behind
RUN_INTEGRATION_TESTS=1 so they never run in CI unless explicitly enabled.

Usage:
    RUN_INTEGRATION_TESTS=1 ANTHROPIC_API_KEY=sk-ant-... python -m pytest tests/test_integration.py -v

Requirements:
    - RUN_INTEGRATION_TESTS=1 must be set.
    - A valid Anthropic API key must be present in ANTHROPIC_API_KEY or
      OWNER_ANTHROPIC_API_KEY. The test is skipped if neither is set.
    - Fixture cards must exist under test-cards/.

Assertions are structural — not exact field values — because LLM output
can vary across model versions. Each test verifies that:
  * The result type is Valid (the image was recognised as a business card).
  * card.validationStatus is VALID.
  * At least one name field (full_name, first_name, or last_name) is non-empty.
  * At least one contact field (phones or emails) is non-empty on cards that
    visibly carry contact info.
"""

import os
import pathlib

import pytest

# ---------------------------------------------------------------------------
# Gate: skip the entire module unless RUN_INTEGRATION_TESTS=1
# ---------------------------------------------------------------------------

integration = pytest.mark.skipif(
    not os.getenv("RUN_INTEGRATION_TESTS"),
    reason="Set RUN_INTEGRATION_TESTS=1 to run live LLM tests",
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).parent.parent
_CARD_DIR = _REPO_ROOT / "test-cards"

_CARDS = {
    "graham_bexar_co_pol_card.JPG": "image/jpeg",
    "heather_mccarver-gchs.HEIC": "image/heic",
    "marc_skinner_toyota_boerne.HEIC": "image/heic",
}


@pytest.fixture(scope="module")
def api_key():
    """Return a usable Anthropic API key, or skip if neither env var is set."""
    key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get(
        "OWNER_ANTHROPIC_API_KEY"
    )
    if not key:
        pytest.skip(
            "No Anthropic API key found. Set ANTHROPIC_API_KEY or "
            "OWNER_ANTHROPIC_API_KEY to run integration tests."
        )
    return key


def _load_card(filename: str) -> bytes:
    path = _CARD_DIR / filename
    if not path.exists():
        pytest.skip(f"Fixture card not found: {path}")
    return path.read_bytes()


# ---------------------------------------------------------------------------
# Helpers — imported lazily to avoid polluting the skipped collection path
# ---------------------------------------------------------------------------


def _import_extraction():
    from main import extract_card_from_bytes, Valid  # noqa: PLC0415
    from baml_client.types import ValidationStatus  # noqa: PLC0415

    return extract_card_from_bytes, Valid, ValidationStatus


# ---------------------------------------------------------------------------
# Test: graham_bexar_co_pol_card.JPG  (JPEG political card)
# ---------------------------------------------------------------------------


@integration
def test_graham_bexar_co_jpeg_card_extracts_as_valid(api_key):
    """A real JPEG business card returns a Valid result with at least a name."""
    extract_card_from_bytes, Valid, ValidationStatus = _import_extraction()

    image_data = _load_card("graham_bexar_co_pol_card.JPG")
    result = extract_card_from_bytes(
        image_data=image_data,
        mime_type="image/jpeg",
        api_key=api_key,
        filename="graham_bexar_co_pol_card.JPG",
    )

    assert isinstance(result, Valid), (
        f"Expected Valid, got {type(result).__name__}: {getattr(result, 'message', '')}"
    )
    assert result.card.validationStatus == ValidationStatus.VALID

    # At least one name field must be populated
    has_name = any(
        [
            result.card.full_name,
            result.card.first_name,
            result.card.last_name,
        ]
    )
    assert has_name, "Expected at least one name field to be non-null"


@integration
def test_graham_bexar_co_jpeg_card_has_contact_info(api_key):
    """The Bexar County card should have a phone or email."""
    extract_card_from_bytes, Valid, _ = _import_extraction()

    image_data = _load_card("graham_bexar_co_pol_card.JPG")
    result = extract_card_from_bytes(
        image_data=image_data,
        mime_type="image/jpeg",
        api_key=api_key,
    )

    assert isinstance(result, Valid)
    has_contact = bool(result.card.phones) or bool(result.card.emails)
    assert has_contact, (
        "Expected at least one phone or email on the Bexar County card"
    )


# ---------------------------------------------------------------------------
# Test: heather_mccarver-gchs.HEIC  (HEIC card)
# ---------------------------------------------------------------------------


@integration
def test_heather_mccarver_heic_card_extracts_as_valid(api_key):
    """A real HEIC card is converted to JPEG and extracted successfully."""
    extract_card_from_bytes, Valid, ValidationStatus = _import_extraction()

    image_data = _load_card("heather_mccarver-gchs.HEIC")
    result = extract_card_from_bytes(
        image_data=image_data,
        mime_type="image/heic",
        api_key=api_key,
        filename="heather_mccarver-gchs.HEIC",
    )

    assert isinstance(result, Valid), (
        f"Expected Valid, got {type(result).__name__}: {getattr(result, 'message', '')}"
    )
    assert result.card.validationStatus == ValidationStatus.VALID

    has_name = any(
        [
            result.card.full_name,
            result.card.first_name,
            result.card.last_name,
        ]
    )
    assert has_name, "Expected at least one name field to be non-null"


@integration
def test_heather_mccarver_heic_card_has_organization_or_contact(api_key):
    """The Heather McCarver GCHS card should carry org or contact data."""
    extract_card_from_bytes, Valid, _ = _import_extraction()

    image_data = _load_card("heather_mccarver-gchs.HEIC")
    result = extract_card_from_bytes(
        image_data=image_data,
        mime_type="image/heic",
        api_key=api_key,
    )

    assert isinstance(result, Valid)
    has_org_or_contact = (
        result.card.organization
        or bool(result.card.phones)
        or bool(result.card.emails)
    )
    assert has_org_or_contact, (
        "Expected organization, phone, or email on the Heather McCarver card"
    )


# ---------------------------------------------------------------------------
# Test: marc_skinner_toyota_boerne.HEIC  (HEIC card)
# ---------------------------------------------------------------------------


@integration
def test_marc_skinner_toyota_heic_card_extracts_as_valid(api_key):
    """The Marc Skinner Toyota Boerne HEIC card extracts as Valid."""
    extract_card_from_bytes, Valid, ValidationStatus = _import_extraction()

    image_data = _load_card("marc_skinner_toyota_boerne.HEIC")
    result = extract_card_from_bytes(
        image_data=image_data,
        mime_type="image/heic",
        api_key=api_key,
        filename="marc_skinner_toyota_boerne.HEIC",
    )

    assert isinstance(result, Valid), (
        f"Expected Valid, got {type(result).__name__}: {getattr(result, 'message', '')}"
    )
    assert result.card.validationStatus == ValidationStatus.VALID

    has_name = any(
        [
            result.card.full_name,
            result.card.first_name,
            result.card.last_name,
        ]
    )
    assert has_name, "Expected at least one name field to be non-null"


@integration
def test_marc_skinner_toyota_heic_card_has_organization_or_contact(api_key):
    """The Marc Skinner Toyota Boerne card should have org or contact data."""
    extract_card_from_bytes, Valid, _ = _import_extraction()

    image_data = _load_card("marc_skinner_toyota_boerne.HEIC")
    result = extract_card_from_bytes(
        image_data=image_data,
        mime_type="image/heic",
        api_key=api_key,
    )

    assert isinstance(result, Valid)
    has_org_or_contact = (
        result.card.organization
        or bool(result.card.phones)
        or bool(result.card.emails)
    )
    assert has_org_or_contact, (
        "Expected organization, phone, or email on the Marc Skinner Toyota card"
    )


# ---------------------------------------------------------------------------
# Structural: result.card is always a proper BusinessCard with model_dump()
# ---------------------------------------------------------------------------


@integration
@pytest.mark.parametrize(
    "filename,mime_type",
    [
        ("graham_bexar_co_pol_card.JPG", "image/jpeg"),
        ("heather_mccarver-gchs.HEIC", "image/heic"),
        ("marc_skinner_toyota_boerne.HEIC", "image/heic"),
    ],
)
def test_valid_card_model_dump_has_expected_keys(api_key, filename, mime_type):
    """model_dump() on every Valid result must contain the full BusinessCard schema."""
    extract_card_from_bytes, Valid, _ = _import_extraction()

    image_data = _load_card(filename)
    result = extract_card_from_bytes(
        image_data=image_data,
        mime_type=mime_type,
        api_key=api_key,
        filename=filename,
    )

    assert isinstance(result, Valid)

    card_dict = result.card.model_dump()
    required_keys = {
        "validationStatus",
        "full_name",
        "first_name",
        "last_name",
        "phones",
        "emails",
        "urls",
    }
    for key in required_keys:
        assert key in card_dict, f"Expected key {key!r} in card_dict"

    # Phones and emails must be lists (even if empty — never None)
    assert isinstance(card_dict["phones"], list)
    assert isinstance(card_dict["emails"], list)
    assert isinstance(card_dict["urls"], list)
