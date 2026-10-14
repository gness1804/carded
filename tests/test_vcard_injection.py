"""Injection-hardening tests for vcard_builder (security review, 2026-10-13).

Card text is attacker-controllable: a crafted business card can steer the
LLM into returning field values that contain line breaks or control
characters. None of those may ever start a new vCard property line.
"""

import pytest

from tests.fixtures_data import ALL_NULL
from vcard_builder import build_vcf

# Every line-break variant a vCard parser (or Python's splitlines) might
# honour, plus a few dangerous non-break controls.
BREAKS = ["\r\n", "\n", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e",
          "\x85", "\u2028", "\u2029"]
INJECTED = "TEL:+19005550100"


def _property_lines(vcf: str) -> list[str]:
    """Split the way the most permissive parser would: on any line break."""
    return vcf.splitlines()


def _assert_no_injected_property(vcf: str) -> None:
    lines = _property_lines(vcf)
    assert not [ln for ln in lines if ln.startswith("TEL:")], lines
    assert lines[0] == "BEGIN:VCARD"
    assert lines[-1] == "END:VCARD"
    assert sum(ln == "END:VCARD" for ln in lines) == 1


@pytest.mark.parametrize("brk", BREAKS)
@pytest.mark.parametrize("field", ["full_name", "title", "organization",
                                   "department", "note", "first_name",
                                   "last_name", "prefix", "suffix"])
def test_text_fields_cannot_inject_properties(field, brk):
    card = {**ALL_NULL, "full_name": "Bob", "organization": "Acme",
            field: f"Bob{brk}{INJECTED}"}
    _assert_no_injected_property(build_vcf(card))


@pytest.mark.parametrize("brk", BREAKS)
def test_address_cannot_inject_properties(brk):
    card = {**ALL_NULL, "full_name": "Bob",
            "address": {"street": f"1 Main{brk}{INJECTED}", "street2": None,
                        "city": "Austin", "state": "TX",
                        "postal_code": "78701", "country": "US"}}
    _assert_no_injected_property(build_vcf(card))


@pytest.mark.parametrize("brk", BREAKS)
def test_non_text_fields_cannot_inject_properties(brk):
    card = {
        **ALL_NULL, "full_name": "Bob",
        "phones": [{"number": f"555-0100{brk}{INJECTED}", "type": "WORK"}],
        "emails": [{"address": f"bob@example.com{brk}{INJECTED}",
                    "type": "WORK"}],
        "urls": [f"example.com{brk}{INJECTED}"],
        "linkedin": f"linkedin.com/in/bob{brk}{INJECTED}",
        "twitter": None, "instagram": None,
    }
    _assert_no_injected_property(build_vcf(card))


def test_end_vcard_injection_is_neutralized():
    card = {**ALL_NULL, "full_name": "Bob\nEND:VCARD\nBEGIN:VCARD\nFN:Evil"}
    vcf = build_vcf(card)
    lines = _property_lines(vcf)
    assert lines.count("BEGIN:VCARD") == 1
    assert lines.count("END:VCARD") == 1
    assert "FN:Bob\\nEND:VCARD\\nBEGIN:VCARD\\nFN:Evil" in lines


def test_text_newline_becomes_literal_backslash_n():
    card = {**ALL_NULL, "title": "Founder\nCEO"}
    assert "TITLE:Founder\\nCEO\r\n" in build_vcf(card)


def test_existing_backslash_n_text_is_escaped_not_confused():
    # A literal backslash followed by n in the source must round-trip as
    # an escaped backslash, not become a newline marker.
    card = {**ALL_NULL, "title": "a\\nb"}
    assert "TITLE:a\\\\nb\r\n" in build_vcf(card)


def test_non_text_newline_becomes_space():
    card = {**ALL_NULL, "full_name": "Bob",
            "phones": [{"number": "555\n0100", "type": "WORK"}]}
    assert "TEL;TYPE=WORK,VOICE:555 0100\r\n" in build_vcf(card)


def test_escape_and_other_controls_are_stripped():
    card = {**ALL_NULL, "full_name": "Bob\x1b]52;c;ZXZpbA==\x07 Smith",
            "urls": ["exa\x00mple.com\x7f"]}
    vcf = build_vcf(card)
    assert "\x1b" not in vcf and "\x07" not in vcf
    assert "\x00" not in vcf and "\x7f" not in vcf
    assert "URL:example.com\r\n" in vcf


def test_tab_is_preserved():
    card = {**ALL_NULL, "title": "A\tB"}
    assert "TITLE:A\tB\r\n" in build_vcf(card)


def test_whitespace_only_non_text_value_is_omitted():
    card = {**ALL_NULL, "full_name": "Bob",
            "phones": [{"number": "\n\r\n", "type": "WORK"}],
            "urls": ["\x00\n"]}
    vcf = build_vcf(card)
    assert "TEL" not in vcf and "URL" not in vcf


def test_unicode_text_is_untouched():
    card = {**ALL_NULL, "full_name": "José Müller — Café"}
    assert "FN:José Müller — Café\r\n" in build_vcf(card)
