"""Unit tests for vcard_builder.py.

Tests use plain dicts matching the BusinessCardJson shape from the interface
contract. No mocking needed — build_vcf and vcf_filename are pure functions.
"""

import pytest

from tests.fixtures_data import ALL_NULL, CHRIS_OKAFOR, JAMIE_PARK
from vcard_builder import build_vcf, vcf_filename


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _lines(vcf: str) -> list[str]:
    """Split a vCard string on CRLF, dropping the final empty element."""
    return vcf.split("\r\n")[:-1]


def _line_map(vcf: str) -> dict[str, list[str]]:
    """Return a dict mapping each property name prefix to all matching lines.

    e.g. {"TEL": ["TEL;TYPE=WORK,VOICE:(415) 555-0182", ...], ...}
    """
    result: dict[str, list[str]] = {}
    for line in _lines(vcf):
        key = line.split(";")[0].split(":")[0]
        result.setdefault(key, []).append(line)
    return result


# ---------------------------------------------------------------------------
# Full card — Jamie Park
# ---------------------------------------------------------------------------


def test_full_card_produces_valid_vcf():
    vcf = build_vcf(JAMIE_PARK)

    assert "BEGIN:VCARD\r\n" in vcf
    assert "VERSION:3.0\r\n" in vcf
    assert "END:VCARD\r\n" in vcf

    assert "FN:Jamie Park\r\n" in vcf
    assert "N:Park;Jamie;;;\r\n" in vcf
    assert "TITLE:Senior Designer\r\n" in vcf
    assert "ORG:Helio Studio;Brand & Experience\r\n" in vcf

    # Both phone lines with correct TYPE params
    assert "TEL;TYPE=WORK,VOICE:(415) 555-0182\r\n" in vcf
    assert "TEL;TYPE=CELL,VOICE:+1-415-555-0199\r\n" in vcf

    # Both email lines
    assert "EMAIL;TYPE=WORK,INTERNET:jamie@heliostudio.co\r\n" in vcf
    assert "EMAIL;TYPE=HOME,INTERNET:jamie.park@gmail.com\r\n" in vcf

    # Two URL lines
    assert "URL:https://heliostudio.co\r\n" in vcf
    assert "URL:https://jamiepark.design\r\n" in vcf

    # ADR: PO Box (empty); Extended (street2); Street; City; State; Postal; Country
    assert "ADR;TYPE=WORK:;Suite 800;340 Pine Street;San Francisco;CA;94104;USA\r\n" in vcf

    # Three social profile lines
    assert "X-SOCIALPROFILE;TYPE=linkedin:linkedin.com/in/jamiepark\r\n" in vcf
    assert "X-SOCIALPROFILE;TYPE=twitter:@jamiepark\r\n" in vcf
    assert "X-SOCIALPROFILE;TYPE=instagram:@heliostudio\r\n" in vcf

    # Note
    assert "NOTE:Pronouns: they/them\r\n" in vcf

    # Must end with END:VCARD\r\n
    assert vcf.endswith("END:VCARD\r\n")


# ---------------------------------------------------------------------------
# Sparse card — Chris Okafor
# ---------------------------------------------------------------------------


def test_sparse_card_omits_null_fields():
    vcf = build_vcf(CHRIS_OKAFOR)

    assert "TITLE:" not in vcf
    assert "EMAIL:" not in vcf
    assert "ADR" not in vcf
    assert "URL:" not in vcf
    assert "X-SOCIALPROFILE" not in vcf
    assert "NOTE:" not in vcf

    # CRITICAL: no cell should stringify as "None"
    assert "None" not in vcf

    # No empty TEL or EMAIL lines
    for line in _lines(vcf):
        if line.startswith("TEL") or line.startswith("EMAIL"):
            _, _, value = line.partition(":")
            assert value.strip() != ""


# ---------------------------------------------------------------------------
# Multiple phones
# ---------------------------------------------------------------------------


def test_multiple_phones_with_types():
    card = {
        **ALL_NULL,
        "full_name": "Test User",
        "phones": [
            {"number": "111-1111", "type": "MOBILE"},
            {"number": "222-2222", "type": "WORK"},
            {"number": "333-3333", "type": "FAX"},
        ],
    }
    vcf = build_vcf(card)
    assert "TEL;TYPE=CELL,VOICE:111-1111\r\n" in vcf
    assert "TEL;TYPE=WORK,VOICE:222-2222\r\n" in vcf
    assert "TEL;TYPE=FAX:333-3333\r\n" in vcf
    # Exactly three TEL lines
    assert vcf.count("TEL;") == 3


# ---------------------------------------------------------------------------
# Phone type mapping (parametrized)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "phone_type,expected_param",
    [
        ("MOBILE", "CELL,VOICE"),
        ("WORK", "WORK,VOICE"),
        ("HOME", "HOME,VOICE"),
        ("FAX", "FAX"),
        ("OTHER", "VOICE"),
    ],
)
def test_phone_type_mapping(phone_type: str, expected_param: str):
    card = {**ALL_NULL, "phones": [{"number": "555-0000", "type": phone_type}]}
    vcf = build_vcf(card)
    assert f"TEL;TYPE={expected_param}:555-0000\r\n" in vcf


# ---------------------------------------------------------------------------
# Email type mapping (parametrized)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "email_type,expected_param",
    [
        ("WORK", "WORK,INTERNET"),
        ("PERSONAL", "HOME,INTERNET"),
        ("OTHER", "INTERNET"),
    ],
)
def test_email_type_mapping(email_type: str, expected_param: str):
    card = {**ALL_NULL, "emails": [{"address": "test@example.com", "type": email_type}]}
    vcf = build_vcf(card)
    assert f"EMAIL;TYPE={expected_param}:test@example.com\r\n" in vcf


# ---------------------------------------------------------------------------
# Address with partial sub-fields
# ---------------------------------------------------------------------------


def test_address_partial_subfields():
    card = {
        **ALL_NULL,
        "address": {
            "street": None,
            "street2": None,
            "city": "Springfield",
            "state": "IL",
            "postal_code": None,
            "country": None,
        },
    }
    vcf = build_vcf(card)
    # ADR slots: PO Box; Extended; Street; Locality; Region; PostalCode; Country
    assert "ADR;TYPE=WORK:;;;Springfield;IL;;\r\n" in vcf


# ---------------------------------------------------------------------------
# Non-ASCII names
# ---------------------------------------------------------------------------


def test_non_ascii_name_encoding():
    name = "Renée Müller-中野"
    card = {**ALL_NULL, "full_name": name, "first_name": "Renée", "last_name": "Müller-中野"}
    vcf = build_vcf(card)
    # The function returns str; the name should survive the round-trip intact.
    assert name in vcf


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------


def test_escapes_commas_and_semicolons():
    card = {**ALL_NULL, "note": "Hello, world; foo"}
    vcf = build_vcf(card)
    # Both comma and semicolon should be backslash-escaped in the NOTE value
    assert r"NOTE:Hello\, world\; foo" + "\r\n" in vcf


def test_escapes_backslashes():
    card = {**ALL_NULL, "note": "path\\to\\file"}
    vcf = build_vcf(card)
    # Each backslash becomes double-backslash
    assert "NOTE:path\\\\to\\\\file\r\n" in vcf


def test_note_newlines_become_literal_backslash_n():
    card = {**ALL_NULL, "note": "line1\nline2"}
    vcf = build_vcf(card)
    # Real newline becomes literal \n (two chars: backslash + n), NOT a CRLF
    assert "NOTE:line1\\nline2\r\n" in vcf
    # No raw newline inside the NOTE value
    note_line = next(ln for ln in _lines(vcf) if ln.startswith("NOTE:"))
    value = note_line[len("NOTE:"):]
    assert "\n" not in value


# ---------------------------------------------------------------------------
# Filename generation
# ---------------------------------------------------------------------------


def test_filename_generation_with_first_and_last_name():
    card = {**ALL_NULL, "first_name": "Jamie", "last_name": "Park"}
    assert vcf_filename(card) == "park-jamie.vcf"


def test_filename_generation_with_only_full_name():
    card = {**ALL_NULL, "full_name": "Jamie Park"}
    assert vcf_filename(card) == "jamie-park.vcf"


def test_filename_fallback_for_nameless_card():
    assert vcf_filename(ALL_NULL) == "card.vcf"


def test_filename_strips_path_traversal():
    card = {**ALL_NULL, "first_name": "../etc", "last_name": "passwd"}
    filename = vcf_filename(card)
    assert "/" not in filename
    assert "\\" not in filename
    assert ".." not in filename
    assert filename.endswith(".vcf")


# ---------------------------------------------------------------------------
# Social profiles
# ---------------------------------------------------------------------------


def test_social_profile_x_properties():
    card = {
        **ALL_NULL,
        "linkedin": "linkedin.com/in/test",
        "twitter": "@testuser",
        "instagram": "@testgram",
    }
    vcf = build_vcf(card)
    assert "X-SOCIALPROFILE;TYPE=linkedin:linkedin.com/in/test\r\n" in vcf
    assert "X-SOCIALPROFILE;TYPE=twitter:@testuser\r\n" in vcf
    assert "X-SOCIALPROFILE;TYPE=instagram:@testgram\r\n" in vcf


# ---------------------------------------------------------------------------
# All-null card
# ---------------------------------------------------------------------------


def test_all_null_card_produces_minimal_vcf():
    vcf = build_vcf(ALL_NULL)
    assert "BEGIN:VCARD\r\n" in vcf
    assert "VERSION:3.0\r\n" in vcf
    assert "END:VCARD\r\n" in vcf

    # No name, contact, or social lines
    assert "FN:" not in vcf
    # Check for structured N: line start — avoid false match on "VERSION:3.0"
    assert not any(ln.startswith("N:") for ln in _lines(vcf))
    assert "TEL" not in vcf
    assert "EMAIL" not in vcf
    assert "URL:" not in vcf
    assert "ADR" not in vcf
    assert "NOTE:" not in vcf
    assert "X-SOCIALPROFILE" not in vcf

    # No invalid empty FN: line
    assert "FN:\r\n" not in vcf

    # CRITICAL: no "None" literal anywhere
    assert "None" not in vcf


# ---------------------------------------------------------------------------
# Org-only fallback for FN
# ---------------------------------------------------------------------------


def test_org_only_card_uses_org_as_fn_fallback():
    card = {**ALL_NULL, "organization": "Acme Co"}
    vcf = build_vcf(card)
    assert "FN:Acme Co\r\n" in vcf


# ---------------------------------------------------------------------------
# CRLF line endings
# ---------------------------------------------------------------------------


def test_line_endings_are_crlf():
    vcf = build_vcf(JAMIE_PARK)
    # Every line must end with \r\n, not bare \n
    lines_crlf = vcf.split("\r\n")
    # After splitting on \r\n the last element is empty (trailing \r\n)
    assert lines_crlf[-1] == ""
    # No bare \n remains
    assert "\n" not in vcf.replace("\r\n", "")
