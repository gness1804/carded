"""vCard 3.0 builder for extracted business-card data.

Accepts a card dict (matching the BusinessCardJson shape from the interface
contract) and produces a compliant vCard 3.0 string with \\r\\n line endings
per RFC 2426.

Usage::

    from vcard_builder import build_vcf, vcf_filename

    vcf_text = build_vcf(card_dict)
    filename  = vcf_filename(card_dict)
"""

import re
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# Type hint for the card dict (informational; not enforced at runtime).
# ─────────────────────────────────────────────────────────────────────────────

# The dict shape mirrors BusinessCardJson from .cursor/docs/1-interface-contract.md.
# Keys: full_name, first_name, last_name, prefix, suffix, title, organization,
#       department, phones (list of {number, type}), emails (list of {address, type}),
#       urls (list of str), address ({street, street2, city, state, postal_code,
#       country} | None), linkedin, twitter, instagram, note.
CardDict = dict[str, Any]

# ─────────────────────────────────────────────────────────────────────────────
# Phone and email type → vCard TYPE parameter mappings (per plan §5)
# ─────────────────────────────────────────────────────────────────────────────

_PHONE_TYPE_MAP: dict[str, str] = {
    "MOBILE": "CELL,VOICE",
    "WORK": "WORK,VOICE",
    "HOME": "HOME,VOICE",
    "FAX": "FAX",
    "OTHER": "VOICE",
}

_EMAIL_TYPE_MAP: dict[str, str] = {
    "WORK": "WORK,INTERNET",
    "PERSONAL": "HOME,INTERNET",
    "OTHER": "INTERNET",
}

# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def build_vcf(card: CardDict) -> str:
    """Build a vCard 3.0 string from a business-card dict.

    Fields that are None or empty are omitted entirely — no empty TEL:,
    EMAIL:, or URL: lines are emitted.

    Args:
        card: Dict matching the BusinessCardJson shape from the interface
              contract. All values are strings or None (or lists/dicts).

    Returns:
        A vCard 3.0-compliant string with CRLF (\\r\\n) line endings.
    """
    lines: list[str] = ["BEGIN:VCARD", "VERSION:3.0"]

    # ── FN (full display name) ──────────────────────────────────────────────
    fn = _build_fn(card)
    if fn:
        lines.append(f"FN:{_escape_text(fn)}")
    else:
        # FN is technically required by vCard 3.0. If no name info at all,
        # fall back to organization so we don't emit an invalid empty FN:.
        org = card.get("organization")
        if org:
            lines.append(f"FN:{_escape_text(org)}")
        # If neither name nor org exists, we omit FN entirely rather than
        # emit FN: with an empty value, which is invalid per RFC 2426.

    # ── N (structured name) ─────────────────────────────────────────────────
    n_line = _build_n(card)
    if n_line:
        lines.append(n_line)

    # ── Professional ─────────────────────────────────────────────────────────
    title = card.get("title")
    if title:
        lines.append(f"TITLE:{_escape_text(title)}")

    org_line = _build_org(card)
    if org_line:
        lines.append(org_line)

    # ── Phones ───────────────────────────────────────────────────────────────
    for phone in card.get("phones") or []:
        number = phone.get("number") or ""
        phone_type = (phone.get("type") or "WORK").upper()
        type_param = _PHONE_TYPE_MAP.get(phone_type, "VOICE")
        if number:
            lines.append(f"TEL;TYPE={type_param}:{number}")

    # ── Emails ───────────────────────────────────────────────────────────────
    for email in card.get("emails") or []:
        address = email.get("address") or ""
        email_type = (email.get("type") or "WORK").upper()
        type_param = _EMAIL_TYPE_MAP.get(email_type, "INTERNET")
        if address:
            lines.append(f"EMAIL;TYPE={type_param}:{address}")

    # ── URLs ─────────────────────────────────────────────────────────────────
    for url in card.get("urls") or []:
        if url:
            lines.append(f"URL:{url}")

    # ── Address ──────────────────────────────────────────────────────────────
    adr_line = _build_adr(card)
    if adr_line:
        lines.append(adr_line)

    # ── Social profiles ───────────────────────────────────────────────────────
    for social_key in ("linkedin", "twitter", "instagram"):
        value = card.get(social_key)
        if value:
            lines.append(f"X-SOCIALPROFILE;TYPE={social_key}:{value}")

    # ── Note ─────────────────────────────────────────────────────────────────
    note = card.get("note")
    if note:
        lines.append(f"NOTE:{_escape_note(note)}")

    lines.append("END:VCARD")

    # vCard spec requires CRLF line endings (RFC 2426 §2.1).
    return "\r\n".join(lines) + "\r\n"


def vcf_filename(card: CardDict) -> str:
    """Derive a safe, path-traversal-free filename for the vCard file.

    Priority:
    1. ``<last_name>-<first_name>.vcf`` (lowercased, hyphenated)
    2. ``<full_name>.vcf`` (lowercased, spaces → hyphens, non-alnum stripped)
    3. ``card.vcf``

    Path-traversal characters (/, \\\\, ..) are always stripped.

    Args:
        card: Business-card dict.

    Returns:
        A safe filename string ending in ``.vcf``.
    """
    last = (card.get("last_name") or "").strip()
    first = (card.get("first_name") or "").strip()

    if last or first:
        parts = "-".join(p for p in [last, first] if p)
        return _safe_filename(parts) + ".vcf"

    full = (card.get("full_name") or "").strip()
    if full:
        return _safe_filename(full) + ".vcf"

    return "card.vcf"


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────


def _build_fn(card: CardDict) -> str:
    """Return the best available display name string, or empty string."""
    full = (card.get("full_name") or "").strip()
    if full:
        return full

    # Compose from parts if no full_name
    parts = [
        card.get("prefix"),
        card.get("first_name"),
        card.get("last_name"),
        card.get("suffix"),
    ]
    composed = " ".join(p for p in parts if p)
    return composed.strip()


def _build_n(card: CardDict) -> str:
    """Build the vCard N: property string, or empty string if no name parts."""
    last = card.get("last_name") or ""
    first = card.get("first_name") or ""
    prefix = card.get("prefix") or ""
    suffix = card.get("suffix") or ""

    if not any([last, first, prefix, suffix]):
        return ""

    # vCard N field order: Family;Given;Additional;Prefix;Suffix
    # We have no "Additional" (middle) name field, so that slot is empty.
    components = [last, first, "", prefix, suffix]
    escaped = [_escape_name_component(c) for c in components]
    return "N:" + ";".join(escaped)


def _build_org(card: CardDict) -> str:
    """Build the ORG: property, or empty string."""
    org = card.get("organization") or ""
    dept = card.get("department") or ""

    if not org:
        return ""

    if dept:
        return f"ORG:{_escape_text(org)};{_escape_text(dept)}"
    return f"ORG:{_escape_text(org)}"


def _build_adr(card: CardDict) -> str:
    """Build ADR;TYPE=WORK: if address is present with at least one sub-field."""
    addr = card.get("address")
    if not addr:
        return ""

    street = addr.get("street") or ""
    street2 = addr.get("street2") or ""  # → Extended Address slot
    city = addr.get("city") or ""
    state = addr.get("state") or ""
    postal = addr.get("postal_code") or ""
    country = addr.get("country") or ""

    if not any([street, street2, city, state, postal, country]):
        return ""

    # vCard ADR field order:
    # PO Box; Extended; Street; Locality; Region; PostalCode; Country
    components = ["", street2, street, city, state, postal, country]
    escaped = [_escape_text(c) for c in components]
    return "ADR;TYPE=WORK:" + ";".join(escaped)


def _escape_text(value: str) -> str:
    """Escape commas, semicolons, and backslashes per RFC 2426 §2.6."""
    value = value.replace("\\", "\\\\")
    value = value.replace(",", "\\,")
    value = value.replace(";", "\\;")
    return value


def _escape_name_component(value: str) -> str:
    """Escape a single N: component (commas, semicolons, backslashes)."""
    return _escape_text(value)


def _escape_note(value: str) -> str:
    """Escape a NOTE value per RFC 2426.

    Newlines in note text are represented as literal \\n in the vCard stream.
    Commas, semicolons, and backslashes are also escaped.
    """
    value = value.replace("\\", "\\\\")
    value = value.replace(",", "\\,")
    value = value.replace(";", "\\;")
    # Represent newlines as vCard literal \n (not CRLF — that would break folding)
    value = value.replace("\r\n", "\\n")
    value = value.replace("\n", "\\n")
    return value


def _safe_filename(name: str) -> str:
    """Lowercase, replace spaces with hyphens, strip unsafe characters.

    Removes path-traversal sequences (/, \\\\, ..) and any character that
    is not a-z, 0-9, or hyphen.
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
