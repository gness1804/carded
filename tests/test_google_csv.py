"""Unit tests for google_csv_builder.py.

All tests call the pure functions directly with fixture dicts — no mocking
needed. CSV output is parsed back through csv.DictReader for column-level
assertions to avoid brittle string comparisons.
"""

import csv
import io

import pytest

from google_csv_builder import build_google_csv, csv_filename
from tests.fixtures_data import ALL_NULL, CHRIS_OKAFOR, JAMIE_PARK

# The exact header row the builder must produce (copied from module _HEADERS).
_EXPECTED_HEADERS = (
    "Name,Given Name,Additional Name,Family Name,Yomi Name,Given Name Yomi,"
    "Additional Name Yomi,Family Name Yomi,Name Prefix,Name Suffix,Initials,"
    "Nickname,Short Name,Maiden Name,Birthday,Gender,Location,"
    "Billing Information,Directory Server,Mileage,Occupation,Hobby,"
    "Sensitivity,Priority,Subject,Notes,Language,Photo,Group Membership,"
    "E-mail 1 - Type,E-mail 1 - Value,E-mail 2 - Type,E-mail 2 - Value,"
    "Phone 1 - Type,Phone 1 - Value,Phone 2 - Type,Phone 2 - Value,"
    "Phone 3 - Type,Phone 3 - Value,Phone 4 - Type,Phone 4 - Value,"
    "Address 1 - Type,Address 1 - Formatted,Address 1 - Street,"
    "Address 1 - City,Address 1 - PO Box,Address 1 - Region,"
    "Address 1 - Postal Code,Address 1 - Country,Address 1 - Extended Address,"
    "Organization 1 - Type,Organization 1 - Name,Organization 1 - Yomi Name,"
    "Organization 1 - Title,Organization 1 - Department,"
    "Organization 1 - Symbol,Organization 1 - Location,"
    "Organization 1 - Job Description,"
    "Website 1 - Type,Website 1 - Value,Website 2 - Type,Website 2 - Value"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(csv_text: str) -> dict[str, str]:
    """Parse the single data row from the two-row CSV output."""
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 1, f"Expected 1 data row, got {len(rows)}"
    return rows[0]


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------


def test_full_card_csv_headers_complete():
    csv_text = build_google_csv(JAMIE_PARK)
    # First line is the header row (strip trailing \r\n before comparing)
    first_line = csv_text.split("\r\n")[0]
    assert first_line == _EXPECTED_HEADERS


# ---------------------------------------------------------------------------
# Full card — Jamie Park
# ---------------------------------------------------------------------------


def test_full_card_data_row_populated():
    row = _parse(build_google_csv(JAMIE_PARK))

    assert row["Name"] == "Jamie Park"
    assert row["Given Name"] == "Jamie"
    assert row["Family Name"] == "Park"
    assert row["Notes"] == "Pronouns: they/them"

    assert row["Organization 1 - Name"] == "Helio Studio"
    assert row["Organization 1 - Title"] == "Senior Designer"
    assert row["Organization 1 - Department"] == "Brand & Experience"
    assert row["Organization 1 - Type"] == "Work"

    # Phone slots: WORK first, MOBILE second (order from the fixture)
    assert row["Phone 1 - Type"] == "Work"
    assert row["Phone 1 - Value"] == "(415) 555-0182"
    assert row["Phone 2 - Type"] == "Mobile"
    assert row["Phone 2 - Value"] == "+1-415-555-0199"

    # Email slots: WORK first, PERSONAL second
    assert row["E-mail 1 - Type"] == "Work"
    assert row["E-mail 1 - Value"] == "jamie@heliostudio.co"
    assert row["E-mail 2 - Type"] == "Home"
    assert row["E-mail 2 - Value"] == "jamie.park@gmail.com"

    # Address
    assert row["Address 1 - Type"] == "Work"
    assert row["Address 1 - Street"] == "340 Pine Street"
    assert row["Address 1 - Extended Address"] == "Suite 800"
    assert row["Address 1 - City"] == "San Francisco"
    assert row["Address 1 - Region"] == "CA"
    assert row["Address 1 - Postal Code"] == "94104"
    assert row["Address 1 - Country"] == "USA"

    # Websites
    assert row["Website 1 - Value"] == "https://heliostudio.co"
    assert row["Website 2 - Value"] == "https://jamiepark.design"


# ---------------------------------------------------------------------------
# Null fields — Chris Okafor
# ---------------------------------------------------------------------------


def test_null_fields_become_empty_cells_not_None():
    row = _parse(build_google_csv(CHRIS_OKAFOR))

    # CRITICAL: no cell value is the string "None"
    for col, value in row.items():
        assert value != "None", f"Column '{col}' contains literal 'None'"

    # Absent fields are empty strings
    assert row["Notes"] == ""
    assert row["Organization 1 - Name"] == ""
    assert row["Organization 1 - Title"] == ""
    assert row["E-mail 1 - Value"] == ""
    assert row["E-mail 2 - Value"] == ""
    assert row["Website 1 - Value"] == ""
    assert row["Address 1 - Street"] == ""


# ---------------------------------------------------------------------------
# Email overflow
# ---------------------------------------------------------------------------


def test_multiple_emails_overflow_to_numbered_columns():
    card = {
        **ALL_NULL,
        "emails": [
            {"address": "a@example.com", "type": "WORK"},
            {"address": "b@example.com", "type": "PERSONAL"},
        ],
    }
    row = _parse(build_google_csv(card))
    assert row["E-mail 1 - Value"] == "a@example.com"
    assert row["E-mail 2 - Value"] == "b@example.com"


def test_emails_beyond_limit_dropped_with_warning(caplog):
    card = {
        **ALL_NULL,
        "emails": [
            {"address": "a@example.com", "type": "WORK"},
            {"address": "b@example.com", "type": "PERSONAL"},
            {"address": "c@example.com", "type": "OTHER"},  # overflow
        ],
    }
    import logging

    with caplog.at_level(logging.WARNING, logger="google_csv_builder"):
        row = _parse(build_google_csv(card))

    # Only first 2 in output
    assert row["E-mail 1 - Value"] == "a@example.com"
    assert row["E-mail 2 - Value"] == "b@example.com"
    # No third slot
    assert "E-mail 3 - Value" not in row or row.get("E-mail 3 - Value", "") == ""

    # A warning was logged
    assert any("email" in rec.message.lower() for rec in caplog.records)


# ---------------------------------------------------------------------------
# Phone type routing (parametrized)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "phone_type,expected_label",
    [
        ("MOBILE", "Mobile"),
        ("WORK", "Work"),
        ("HOME", "Home"),
        ("FAX", "Work Fax"),
        ("OTHER", "Other"),
    ],
)
def test_phone_type_routing(phone_type: str, expected_label: str):
    card = {**ALL_NULL, "phones": [{"number": "555-0000", "type": phone_type}]}
    row = _parse(build_google_csv(card))
    assert row["Phone 1 - Type"] == expected_label
    assert row["Phone 1 - Value"] == "555-0000"


# ---------------------------------------------------------------------------
# Phone overflow
# ---------------------------------------------------------------------------


def test_phones_beyond_4_are_dropped_with_warning(caplog):
    card = {
        **ALL_NULL,
        "phones": [
            {"number": f"555-000{i}", "type": "WORK"} for i in range(5)
        ],
    }
    import logging

    with caplog.at_level(logging.WARNING, logger="google_csv_builder"):
        row = _parse(build_google_csv(card))

    # First 4 present
    for slot in range(1, 5):
        assert row[f"Phone {slot} - Value"] != ""

    # A warning was logged
    assert any("phone" in rec.message.lower() for rec in caplog.records)


# ---------------------------------------------------------------------------
# CSV quoting
# ---------------------------------------------------------------------------


def test_csv_quoting_for_commas_and_quotes_in_fields():
    note_value = 'Hello, "world"'
    card = {**ALL_NULL, "note": note_value}
    csv_text = build_google_csv(card)
    # Round-trip through DictReader must preserve the exact string
    row = _parse(csv_text)
    assert row["Notes"] == note_value


# ---------------------------------------------------------------------------
# Address — partial sub-fields
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
    row = _parse(build_google_csv(card))
    assert row["Address 1 - City"] == "Springfield"
    assert row["Address 1 - Region"] == "IL"
    assert row["Address 1 - Street"] == ""
    assert row["Address 1 - Postal Code"] == ""
    assert row["Address 1 - Country"] == ""


def test_address_null_means_all_address_columns_empty():
    card = {**ALL_NULL, "address": None}
    row = _parse(build_google_csv(card))
    for col in [
        "Address 1 - Type",
        "Address 1 - Street",
        "Address 1 - City",
        "Address 1 - Region",
        "Address 1 - Postal Code",
        "Address 1 - Country",
        "Address 1 - Extended Address",
    ]:
        assert row[col] == "", f"Expected empty for '{col}', got '{row[col]}'"


# ---------------------------------------------------------------------------
# Non-ASCII
# ---------------------------------------------------------------------------


def test_non_ascii_in_csv():
    name = "Renée Müller-中野"
    card = {**ALL_NULL, "full_name": name, "first_name": "Renée", "last_name": "Müller-中野"}
    row = _parse(build_google_csv(card))
    assert row["Name"] == name
    assert row["Given Name"] == "Renée"


# ---------------------------------------------------------------------------
# Filename generation
# ---------------------------------------------------------------------------


def test_filename_generation_last_first():
    card = {**ALL_NULL, "first_name": "Jamie", "last_name": "Park"}
    assert csv_filename(card) == "park-jamie.csv"


def test_filename_generation_full_name():
    card = {**ALL_NULL, "full_name": "Jamie Park"}
    assert csv_filename(card) == "jamie-park.csv"


def test_filename_fallback_nameless():
    assert csv_filename(ALL_NULL) == "card.csv"


def test_filename_strips_path_traversal():
    card = {**ALL_NULL, "first_name": "../etc", "last_name": "passwd"}
    filename = csv_filename(card)
    assert "/" not in filename
    assert "\\" not in filename
    assert ".." not in filename
    assert filename.endswith(".csv")


# ---------------------------------------------------------------------------
# Organization type only when organization present
# ---------------------------------------------------------------------------


def test_organization_type_set_only_when_organization_present():
    card = {**ALL_NULL, "title": "Engineer"}  # title but no organization
    row = _parse(build_google_csv(card))
    assert row["Organization 1 - Type"] == ""
    assert row["Organization 1 - Title"] == "Engineer"


# ---------------------------------------------------------------------------
# CRLF line endings
# ---------------------------------------------------------------------------


def test_line_endings_are_crlf():
    csv_text = build_google_csv(JAMIE_PARK)
    # Split on \r\n — last element should be empty (trailing terminator)
    parts = csv_text.split("\r\n")
    assert parts[-1] == ""
    # No bare \n should remain
    assert "\n" not in csv_text.replace("\r\n", "")


# ---------------------------------------------------------------------------
# Minimal card — empty arrays
# ---------------------------------------------------------------------------


def test_minimal_card_empty_arrays():
    card = {**ALL_NULL}
    row = _parse(build_google_csv(card))

    for slot in range(1, 5):
        assert row.get(f"Phone {slot} - Value", "") == ""

    for slot in range(1, 3):
        assert row.get(f"E-mail {slot} - Value", "") == ""

    for slot in range(1, 3):
        assert row.get(f"Website {slot} - Value", "") == ""


# ---------------------------------------------------------------------------
# CSV / formula injection (L-3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", ["=HYPERLINK(\"http://evil\")", "@SUM(1)", "-2+3", "+2+3", "\tcmd", "\rcmd"])
def test_formula_injection_neutralized_in_note(payload: str):
    """Note values that a spreadsheet would evaluate as a formula are
    prefixed with a single quote in the exported CSV."""
    card = {**ALL_NULL, "note": payload}
    row = _parse(build_google_csv(card))
    assert row["Notes"] == "'" + payload


def test_formula_injection_neutralized_across_text_fields():
    card = {
        **ALL_NULL,
        "full_name": "=cmd|'/c calc'!A1",
        "organization": "@evil",
        "title": "-1",
    }
    row = _parse(build_google_csv(card))
    assert row["Name"].startswith("'=")
    assert row["Organization 1 - Name"].startswith("'@")
    assert row["Organization 1 - Title"].startswith("'-")


def test_benign_values_not_prefixed():
    """Ordinary contact data is never altered."""
    row = _parse(build_google_csv(JAMIE_PARK))
    assert row["Name"] == "Jamie Park"
    assert row["Notes"] == "Pronouns: they/them"
    assert not row["Name"].startswith("'")


def test_international_phone_plus_prefix_preserved():
    """A legitimate '+<country code>' phone number must NOT be quote-prefixed
    — it would corrupt the number on import into Google Contacts."""
    card = {**ALL_NULL, "phones": [{"number": "+1-415-555-0199", "type": "MOBILE"}]}
    row = _parse(build_google_csv(card))
    assert row["Phone 1 - Value"] == "+1-415-555-0199"


def test_formula_phone_value_still_neutralized():
    """A phone value that is actually a formula (=/@) is still neutralized;
    only the leading '+' is exempted for phone columns."""
    card = {**ALL_NULL, "phones": [{"number": "=2+2", "type": "WORK"}]}
    row = _parse(build_google_csv(card))
    assert row["Phone 1 - Value"] == "'=2+2"
