"""Google Contacts CSV builder for extracted business-card data.

Produces the structured column variant exported by the current Google Contacts
UI (e.g. "Phone 1 - Type" / "Phone 1 - Value") rather than the older
"Business Street"-style columns. This is the most reliable format for
re-import into Google Contacts.

Usage::

    from google_csv_builder import build_google_csv, csv_filename

    csv_text  = build_google_csv(card_dict)
    filename  = csv_filename(card_dict)
"""

import csv
import io
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Column definition (exact order Google Contacts expects on import)
# ---------------------------------------------------------------------------

_HEADERS: list[str] = [
    "Name",
    "Given Name",
    "Additional Name",
    "Family Name",
    "Yomi Name",
    "Given Name Yomi",
    "Additional Name Yomi",
    "Family Name Yomi",
    "Name Prefix",
    "Name Suffix",
    "Initials",
    "Nickname",
    "Short Name",
    "Maiden Name",
    "Birthday",
    "Gender",
    "Location",
    "Billing Information",
    "Directory Server",
    "Mileage",
    "Occupation",
    "Hobby",
    "Sensitivity",
    "Priority",
    "Subject",
    "Notes",
    "Language",
    "Photo",
    "Group Membership",
    "E-mail 1 - Type",
    "E-mail 1 - Value",
    "E-mail 2 - Type",
    "E-mail 2 - Value",
    "Phone 1 - Type",
    "Phone 1 - Value",
    "Phone 2 - Type",
    "Phone 2 - Value",
    "Phone 3 - Type",
    "Phone 3 - Value",
    "Phone 4 - Type",
    "Phone 4 - Value",
    "Address 1 - Type",
    "Address 1 - Formatted",
    "Address 1 - Street",
    "Address 1 - City",
    "Address 1 - PO Box",
    "Address 1 - Region",
    "Address 1 - Postal Code",
    "Address 1 - Country",
    "Address 1 - Extended Address",
    "Organization 1 - Type",
    "Organization 1 - Name",
    "Organization 1 - Yomi Name",
    "Organization 1 - Title",
    "Organization 1 - Department",
    "Organization 1 - Symbol",
    "Organization 1 - Location",
    "Organization 1 - Job Description",
    "Website 1 - Type",
    "Website 1 - Value",
    "Website 2 - Type",
    "Website 2 - Value",
]

# PhoneType → Google Contacts label
_PHONE_TYPE_LABEL: dict[str, str] = {
    "MOBILE": "Mobile",
    "WORK": "Work",
    "HOME": "Home",
    "FAX": "Work Fax",
    "OTHER": "Other",
}

# EmailType → Google Contacts label
_EMAIL_TYPE_LABEL: dict[str, str] = {
    "WORK": "Work",
    "PERSONAL": "Home",
    "OTHER": "Other",
}

_MAX_PHONES = 4
_MAX_EMAILS = 2
_MAX_URLS = 2

# The card dict shape mirrors BusinessCardJson from the interface contract.
CardDict = dict[str, Any]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_google_csv(card: CardDict) -> str:
    """Build a Google Contacts CSV string from a business-card dict.

    Output has exactly two rows: header + data. Null/missing fields become
    empty strings — never the literal string "None". Uses CRLF line
    terminators and QUOTE_MINIMAL quoting per the csv module defaults.

    Args:
        card: Dict matching the BusinessCardJson shape from the interface
              contract. All scalar values are strings or None (or lists/dicts).

    Returns:
        A Google Contacts-compatible CSV string with CRLF line endings.
    """
    row: dict[str, str] = {col: "" for col in _HEADERS}

    # ── Identity ─────────────────────────────────────────────────────────────
    row["Name"] = card.get("full_name") or ""
    row["Given Name"] = card.get("first_name") or ""
    row["Family Name"] = card.get("last_name") or ""
    row["Name Prefix"] = card.get("prefix") or ""
    row["Name Suffix"] = card.get("suffix") or ""

    # ── Notes ────────────────────────────────────────────────────────────────
    row["Notes"] = card.get("note") or ""

    # ── Organization ─────────────────────────────────────────────────────────
    org = card.get("organization") or ""
    row["Organization 1 - Name"] = org
    row["Organization 1 - Title"] = card.get("title") or ""
    row["Organization 1 - Department"] = card.get("department") or ""
    # Only set type when organization is present
    row["Organization 1 - Type"] = "Work" if org else ""

    # ── Phones (up to _MAX_PHONES slots) ─────────────────────────────────────
    phones = card.get("phones") or []
    if len(phones) > _MAX_PHONES:
        dropped = len(phones) - _MAX_PHONES
        logger.warning(
            "google_csv_builder: %d phone(s) beyond the %d-slot limit dropped",
            dropped,
            _MAX_PHONES,
        )
    for i, phone in enumerate(phones[:_MAX_PHONES]):
        slot = i + 1
        number = phone.get("number") or ""
        phone_type = (phone.get("type") or "WORK").upper()
        label = _PHONE_TYPE_LABEL.get(phone_type, "Other")
        if number:
            row[f"Phone {slot} - Type"] = label
            row[f"Phone {slot} - Value"] = number

    # ── Emails (up to _MAX_EMAILS slots) ─────────────────────────────────────
    emails = card.get("emails") or []
    if len(emails) > _MAX_EMAILS:
        dropped = len(emails) - _MAX_EMAILS
        logger.warning(
            "google_csv_builder: %d email(s) beyond the %d-slot limit dropped",
            dropped,
            _MAX_EMAILS,
        )
    for i, email in enumerate(emails[:_MAX_EMAILS]):
        slot = i + 1
        address = email.get("address") or ""
        email_type = (email.get("type") or "WORK").upper()
        label = _EMAIL_TYPE_LABEL.get(email_type, "Other")
        if address:
            row[f"E-mail {slot} - Type"] = label
            row[f"E-mail {slot} - Value"] = address

    # ── URLs (up to _MAX_URLS slots) ─────────────────────────────────────────
    urls = card.get("urls") or []
    if len(urls) > _MAX_URLS:
        dropped = len(urls) - _MAX_URLS
        logger.warning(
            "google_csv_builder: %d URL(s) beyond the %d-slot limit dropped",
            dropped,
            _MAX_URLS,
        )
    for i, url in enumerate(urls[:_MAX_URLS]):
        slot = i + 1
        if url:
            row[f"Website {slot} - Type"] = "Other"
            row[f"Website {slot} - Value"] = url

    # ── Address ──────────────────────────────────────────────────────────────
    addr = card.get("address")
    if addr:
        street = addr.get("street") or ""
        street2 = addr.get("street2") or ""
        city = addr.get("city") or ""
        state = addr.get("state") or ""
        postal = addr.get("postal_code") or ""
        country = addr.get("country") or ""

        if any([street, street2, city, state, postal, country]):
            row["Address 1 - Type"] = "Work"
            row["Address 1 - Street"] = street
            row["Address 1 - Extended Address"] = street2
            row["Address 1 - City"] = city
            row["Address 1 - Region"] = state
            row["Address 1 - Postal Code"] = postal
            row["Address 1 - Country"] = country

    # ── Serialise ─────────────────────────────────────────────────────────────
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=_HEADERS,
        quoting=csv.QUOTE_MINIMAL,
        lineterminator="\r\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerow(row)
    return buf.getvalue()


def csv_filename(card: CardDict) -> str:
    """Derive a safe, path-traversal-free filename for the CSV file.

    Uses the same priority logic as vcf_filename in vcard_builder.py:
    1. ``<last_name>-<first_name>.csv``
    2. ``<full_name>.csv``
    3. ``card.csv``

    Args:
        card: Business-card dict.

    Returns:
        A safe filename string ending in ``.csv``.
    """
    last = (card.get("last_name") or "").strip()
    first = (card.get("first_name") or "").strip()

    if last or first:
        parts = "-".join(p for p in [last, first] if p)
        return _safe_filename(parts) + ".csv"

    full = (card.get("full_name") or "").strip()
    if full:
        return _safe_filename(full) + ".csv"

    return "card.csv"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_filename(name: str) -> str:
    """Lowercase, replace spaces with hyphens, strip unsafe characters.

    Mirrors the logic in vcard_builder._safe_filename (duplicated here
    intentionally so this module has no import dependency on vcard_builder).
    """
    name = name.lower()
    name = name.replace(" ", "-")
    # Remove path-traversal characters before the regex strip
    name = name.replace("/", "").replace("\\", "").replace("..", "")
    # Keep only safe characters
    name = re.sub(r"[^a-z0-9\-]", "", name)
    # Collapse multiple hyphens
    name = re.sub(r"-{2,}", "-", name)
    name = name.strip("-")
    return name or "card"
