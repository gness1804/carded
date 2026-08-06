#!/usr/bin/env python3
"""
Cloud-identifier scanner. CANONICAL SOURCE — copied into repos by /pre-commit
and invoked by the cfs-guard shim. Keep SCANNER_VERSION in step with changes.

WHY PYTHON, AFTER THREE BASH VERSIONS
-------------------------------------
The bash/ERE implementations failed three times, each in the same way: they
mangled the line before matching. Stripping AWS example IDs spliced the text and
destroyed adjacent real matches; stripping UUIDs created clean false negatives.
Both are unavoidable in ERE, which has no lookaround, so exclusions had to be
done by editing the subject string.

Python matches first and filters PER MATCH, so an exclusion can never damage a
different match on the same line. It also lets all consumers share ONE file:
three hand-maintained bash copies had already drifted (the shim silently lost
its S3-ARN and PEM rules).

DETECTION MODEL
---------------
The account-ID rule is "any 12-digit run bounded by non-digits", NOT "12 digits
near the word account". The context-word requirement was the central defect: it
waved through `aws-cloudtrail-logs-<id>-us-east-2`, which is how AWS names its
own buckets, because that line never says "account". Requiring specific
bracketing instead was equally wrong — it missed ECR URIs, markdown backticks,
JSON quoting, trailing commas, and line-start IDs.

Bare 12-digit runs are rare in real prose: dates, versions, ports, byte counts
and git hashes are all other lengths; epoch-seconds is 10 and epoch-millis is 13.
The digit-boundary requirement (no adjacent digits) excludes longer runs, so a
13+ digit number is never mistaken for an account ID.

UUIDs are deliberately NOT excluded. A UUID's final segment is 12 hex chars and
is all-decimal roughly 0.5% of the time, so excluding them would be a false
negative for any account ID sitting in that position, while including them costs
only an occasional blocked commit that `allow-identifier` clears. In a security
control, the false negative is the expensive error.

WHAT --staged-diff SCANS, AND WHY IT IS THREE THINGS
----------------------------------------------------
Added diff lines alone were not enough. The 2026-08-03 review found two ways to
stage an identifier and have this scanner report clean, both verified:

  1. ADDED LINES of the staged diff — the original behaviour.

  2. STAGED PATHNAMES. A path is published exactly as a file body is, and AWS
     names its own buckets `aws-cloudtrail-logs-<account-id>-<region>`, so the
     identifier lands in the FILE NAME with a perfectly clean body. The diff
     parser skips the `+++ b/<path>` header by design, so nothing ever looked
     at the name. The sibling prepare-commit-msg hook already redacted this
     exact pattern out of its own output; the reasoning had simply never been
     applied to the staged path list.

  3. FILES THAT PRODUCE NO DIFF TEXT. `git diff` emits no `+` lines for a
     binary file, and none for any path marked `-diff` in `.gitattributes`.
     Zero lines scanned reads identically to zero findings, so an `.xlsx`
     billing export or a console screenshot passed untouched — and a single
     `*.md -diff` line disabled this control for every markdown file in the
     repo, silently and permanently. Those files are now read out of the INDEX
     with `git cat-file blob :<path>` (what is actually being committed, not
     what happens to be in the work tree) and scanned in full. A blob that
     cannot be decoded as text is reported as UNSCANNABLE and blocks, because
     "we could not look" must never resolve to "nothing there".

OUTPUT DISCIPLINE
-----------------
Reports FILE:LINE and a rule name. NEVER the matched text. Printing the match
would echo the identifier into terminal scrollback, CI logs, and agent
transcripts — the exact channels the house secrets rule governs.

Displayed PATHS are run through redact() for the same reason. Once pathnames
became scannable, the path could itself be the matched text, and a block message
that named the offending file verbatim would have re-published the identifier it
had just refused to let through.
"""

from __future__ import annotations

import argparse
import codecs
import itertools
import os
import re
import subprocess
import sys

SCANNER_VERSION = "5.2.0"

# AWS's own documentation example account IDs — never real.
EXAMPLE_ACCOUNT_IDS = frozenset(
    {"123456789012", "111122223333", "444455556666", "012345678901"}
)

# A twelve-digit run of ONE repeated digit is also an example ID. AWS's
# cross-account docs use 111111111111 / 222222222222 / 333333333333 for "account
# A, account B, account C", and that convention propagates into every script
# docstring and study note written against them — five of the fourteen hits
# measured on aws-security-specialty-exam were exactly this, in `Usage:` blocks
# alongside RFC 5737 documentation CIDRs.
#
# Expressed as a PREDICATE rather than ten more literals because the argument is
# structural: account IDs are assigned essentially at random, so the odds any
# real one is a repdigit are ~10 in 10^12. Enumerating them would invite the next
# reader to append a non-repdigit "obviously fake" ID to the same list, which is
# how an exemption list turns into a false negative. 000000000000 moved out of
# the literal set above for the same reason — it is a repdigit and was already
# covered twice.


def _is_example_account_id(value: str) -> bool:
    """
    True if this 12-digit string is a documentation placeholder, not an ID.

    The length is ASSERTED rather than assumed. Every caller feeds it exactly
    twelve digits today ([0-9]{12}, \\d{12}, or three groups of four joined),
    but `len(set(value)) == 1` is true of "1" and of an 11-digit repdigit too,
    so a future rule matching a different width would silently inherit an
    exemption nobody wrote. Cheap to pin; expensive to discover later.
    """
    if len(value) != 12:
        return False
    if value in EXAMPLE_ACCOUNT_IDS:
        return True
    return len(set(value)) == 1

# AWS's documented example unique IDs all END in "EXAMPLE" — it is their
# convention across the IAM docs, and the suffix is reserved for exactly this.
# Needed because scoping the escape hatch away from aws-unique-id (so one
# marker could not mute an access key) also made it impossible to WRITE about
# an example key at all, in docs or in this scanner's own comments.
EXAMPLE_ID_SUFFIX = "EXAMPLE"

# Per-line escape hatch.
ALLOW_MARKER = "allow-identifier"

# Acknowledgement for staged files this scanner cannot read as text. Deliberately
# an env var rather than a config file or a committed allowlist: it is a
# per-invocation, per-file-set decision made by a human who has just been shown
# which files are unscannable, and it leaves no lasting weakening behind.
ALLOW_UNSCANNABLE_ENV = "SCAN_ALLOW_UNSCANNABLE"

# Only these enable it. A bare truthiness test made SCAN_ALLOW_UNSCANNABLE=0 and
# =false switch the bypass ON, which is the opposite of what anyone typing them
# intends.
TRUTHY = frozenset({"1", "true", "yes", "on"})

# --- rules -------------------------------------------------------------------

# AWS unique ID prefixes: access keys, roles, users, groups, managed policies.
#
# The suffix is {16,17}, not {16}. Access key IDs are prefix + 16 characters
# (20 total), but every OTHER IAM unique ID — roles, users, groups, managed
# policies — is prefix + 17 (21 total). The example values are deliberately NOT
# written out here: there is no exemption for example KEY ids the way there is
# for example ACCOUNT ids, so spelling them out makes this file unstageable
# under its own rule. With a flat {16} and a trailing \b, the 21-character forms
# could never match: the boundary assertion failed on the 17th character. So six
# of the eight prefixes listed here were decorative and every role and user ID
# scanned clean. Found by this scanner's own regression suite on 2026-08-04,
# which is the entire argument for having written one.
RE_AWS_UNIQUE_ID = re.compile(
    r"\b(?:AKIA|ASIA|AROA|AIDA|APKA|ANPA|AGPA|AIPA)[0-9A-Z]{16,17}\b"
)

# ARNs. Partition is [a-z-]* so aws-cn and aws-us-gov are covered. Matched on a
# URL-decoded copy of the line too, so percent-encoded ARNs cannot slip past.
#
# The account ID is CAPTURED rather than just matched, so a documentation-example
# ARN (arn:aws:iam::111122223333:root, which AWS's own docs are full of) is not
# reported. Without the capture this rule fired on every pasted example policy —
# exactly the noise that trains people to reach for --no-verify.
RE_ARN_ACCOUNT = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:([0-9]{12}):")
# S3 ARNs. The bucket segment is CAPTURED, not just matched, for the same
# reason RE_ARN_ACCOUNT captures the account ID: the rule exists to catch a real
# internal BUCKET NAME, and `arn:aws:s3:::<bucket>` is the opposite of that.
# Matching the prefix alone blocked every placeholder ARN — which is the
# documented house convention, so every policy example and every study note
# tripped it. The capture runs THROUGH '/' and _bucket_segment picks the first
# non-empty segment, so `arn:aws:s3:::<bucket>/AWSLogs/...` still yields
# "<bucket>". Stopping the regex at '/' instead — which is what it did until
# 5.2.0 — meant an ARN written with a LEADING SLASH where the bucket belongs
# captured the empty string, and the empty string is a placeholder, so the name
# after that slash was never examined at all. (Spelled out in prose because a
# literal example of it would make this file unstageable under its own rule; the
# case is pinned in the test suite instead.)
RE_ARN_S3 = re.compile(r"arn:aws[a-z-]*:s3:::([^\s\"\'`,\]\)}]*)")

# Bucket names that are obviously stand-ins. Exact matches only for the generic
# words — a prefix test would exempt a real "my-bucket-prod".
PLACEHOLDER_BUCKETS = frozenset(
    {"", "*", "-", "bucket", "bucket-name", "example-bucket", "my-bucket",
     "your-bucket", "some-bucket", "bucketname"}
)

# AWS's own documentation bucket conventions, which ARE prefix-matched because
# both are reserved naming schemes rather than plausible real names.
PLACEHOLDER_BUCKET_PREFIXES = ("doc-example-bucket", "amzn-s3-demo-")

# Template and substitution syntax: <bucket>, ${BUCKET}, $BUCKET, {{ bucket }}.
#
# '%' is NOT here, though it used to be. A leading '%' was meant to cover the
# Windows-style %BUCKET% template, but it also exempted every PERCENT-ENCODED
# bucket name — and _url_decoded deliberately handles only %3A and %2F, so
# nothing else in the pipeline decoded them back. A real name whose first
# character was written as a percent-escape therefore scanned clean (verified
# 2026-08-05). The template form is matched exactly instead, which is what was
# actually intended. (Prose, not a literal example: an example that blocks would
# make this file unstageable under its own rule. Pinned in the test suite.)
PLACEHOLDER_BUCKET_STARTS = ("<", "$", "{", "[")

# %BUCKET%, %BUCKET_NAME% — Windows/CMD substitution. Anchored at both ends so
# it cannot be satisfied by a percent-escape, whose two hex digits are never
# followed by a closing '%'.
RE_PERCENT_TEMPLATE = re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*%$")

# Undecorated SHOUTING placeholders: arn:aws:s3:::BUCKET,
# arn:aws:s3:::BUCKET/AWSLogs/ACCOUNT_ID/*. This is the convention AWS's own
# CloudTrail and Config bucket-policy examples use, so it is what gets pasted
# into policy JSON, and six of the fourteen hits measured on
# aws-security-specialty-exam were this shape.
#
# Exempted on a naming-rule argument rather than a "looks fake" one: since March
# 2018 S3 has rejected bucket names containing an uppercase letter or an
# underscore in EVERY region, so a segment made only of those characters cannot
# name a bucket that anyone could create today. Requiring the WHOLE segment to
# match is what keeps this tight — a legacy mixed-case us-east-1 bucket from
# before that change (`MyCompanyLogs`) contains lowercase, so it still blocks.
#
# At least one uppercase letter or underscore is REQUIRED, so this cannot be
# satisfied by digits alone: an all-digit segment such as a datestamp is a legal
# bucket name and has to keep blocking. (Written as prose rather than as a
# literal ARN on purpose — an example that blocks would make this very file
# unstageable under its own rule, the same reason the example key IDs above are
# not spelled out. The case itself is pinned in the test suite instead.)
RE_SHOUTING_PLACEHOLDER = re.compile(r"^[A-Z0-9_]*[A-Z_][A-Z0-9_]*$")


def _is_placeholder_bucket(name: str) -> bool:
    """True if this bucket segment is a stand-in rather than a real name."""
    if name in PLACEHOLDER_BUCKETS:
        return True
    if name.startswith(PLACEHOLDER_BUCKET_STARTS):
        return True
    if RE_PERCENT_TEMPLATE.match(name):
        return True
    if RE_SHOUTING_PLACEHOLDER.match(name):
        return True
    return name.lower().startswith(PLACEHOLDER_BUCKET_PREFIXES)

RE_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

# A 12-digit run with no digit on either side. (?<!\d) / (?!\d) are what make
# 11- and 13-digit numbers safe, and are precisely what ERE could not express.
RE_TWELVE = re.compile(r"(?<!\d)(\d{12})(?!\d)")

# The console renders account IDs hyphenated in some views.
RE_TWELVE_HYPHENATED = re.compile(r"(?<!\d)(\d{4})-(\d{4})-(\d{4})(?!\d)")

# S3 ARNs are redacted as a unit: the bucket NAME is the sensitive part, and
# masking only the arn: prefix would leave it printed in full. The name is
# captured as well as the prefix so redact() can apply the SAME placeholder test
# scan_line uses — otherwise the two disagree, and a path containing
# `arn:aws:s3:::BUCKET` gets masked in a block message about a finding that this
# scanner never raised.
RE_ARN_S3_BUCKET = re.compile(r"(arn:aws[a-z-]*:s3:::)([^\s]*)")

# Zero-width and invisible characters. Pasting from a console or a rich-text
# editor can thread these through an identifier, splitting a 12-digit run into
# two shorter ones that no rule matches while it still reads as an account ID to
# every human and renders as one on GitHub. Stripped before the digit rules run.
RE_INVISIBLE = re.compile(r"[\u200b-\u200f\u2060\u2061\u2062\u2063\ufeff\u00ad]")


def _url_decoded(text: str) -> str:
    """
    Cheap, dependency-free percent-decode of the delimiters that matter for ARNs.
    Full unquote() would also decode %25 chains; this only needs ':' and '/'.
    """
    for enc, dec in (("%3A", ":"), ("%3a", ":"), ("%2F", "/"), ("%2f", "/")):
        text = text.replace(enc, dec)
    return text


def _readings(line: str) -> tuple[str, ...]:
    """
    Every form of `line` a rule must be tried against, deduplicated.

    Order is irrelevant — a hit in any reading blocks — so this only needs to be
    exhaustive. Both transforms are applied together as well as separately: a
    percent-encoded ARN with a zero-width space threaded through it is defeated
    by neither pass alone.
    """
    out: list[str] = []
    for text in (line, _url_decoded(line)):
        for form in (text, RE_INVISIBLE.sub("", text)):
            if form not in out:
                out.append(form)
    return tuple(out)


def _bucket_segment(captured: str) -> str:
    """
    The bucket NAME out of a captured S3 ARN resource, or "" if there is none.

    The capture now runs through '/' so that the first segment can be chosen
    here rather than by the regex. It used to stop at '/', so an ARN written
    with a LEADING SLASH where the bucket belongs captured the empty string —
    and the empty string is a placeholder, so the ARN scanned clean and the name
    after that slash was never looked at (verified 2026-08-05). Leading empty
    segments are skipped for that reason; an ARN with no segments at all is a
    bare truncated prefix and correctly yields "".
    """
    for segment in captured.split("/"):
        if segment:
            return segment
    return ""


def scan_line(line: str, honor_allow_marker: bool = True) -> str | None:
    """
    Return a rule name if the line discloses an identifier, else None.

    Order matters only for which label is reported; any single hit blocks.

    `honor_allow_marker` is False when the subject is a PATHNAME. The marker is
    designed as a per-line escape hatch a human types next to one specific false
    positive; in a filename it would instead be a permanent, committed exemption
    that travels with the file, and `notes-allow-identifier-<id>.md` would
    disable the check on the very name carrying the identifier.
    """
    allowed = honor_allow_marker and ALLOW_MARKER in line

    # EVERY reading of the line: as written, percent-decoded, and each of those
    # with invisible characters removed.
    #
    # The invisible-character strip used to be applied to the DIGIT rules only,
    # which quietly made it the weakest of the three defences it looked like.
    # A zero-width space inside `arn:aws:s3:​::` defeats RE_ARN_S3 outright, and
    # unlike an account ID a bucket name has no second rule behind it, so a real
    # private bucket scanned rc 0 (verified 2026-08-05). The same hole existed
    # for RE_AWS_UNIQUE_ID and RE_PEM: one soft hyphen inside an AKIA token and
    # nothing matched. Threading the strip through every rule costs one extra
    # pass and closes all three at once.
    subjects = _readings(line)

    # The escape hatch does NOT cover these two. It exists for the documented
    # false positive — a UUID whose tail is 12 digits, a non-AWS 12-digit number
    # — and was an unqualified whole-line mute, so one marker also waved through
    # an access-key ID and a private-key header on the same line. There is no
    # legitimate false positive for either: an AKIA-prefixed 20-character token
    # and a PEM header are what they look like.
    for subject in subjects:
        for match in RE_AWS_UNIQUE_ID.finditer(subject):
            if not match.group(0).endswith(EXAMPLE_ID_SUFFIX):
                return "aws-unique-id"

        if RE_PEM.search(subject):
            return "private-key-header"

    if allowed:
        return None

    # Per-match again: an example-ID ARN must not block, but a real-ID ARN on the
    # same line still must.
    for subject in subjects:
        for match in RE_ARN_ACCOUNT.finditer(subject):
            if not _is_example_account_id(match.group(1)):
                return "arn-with-account"

    # Per match, so a placeholder ARN cannot launder a real bucket name sitting
    # on the same line — the failure that killed version 3 of this scanner.
    for subject in subjects:
        for match in RE_ARN_S3.finditer(subject):
            if not _is_placeholder_bucket(_bucket_segment(match.group(1))):
                return "s3-arn"

    # Filter PER MATCH. A documentation example ID on the line must not suppress
    # a real ID elsewhere on that same line — the bug that killed version 3.
    #
    # Checked against the line with invisible characters removed as well as the
    # line as written, so a zero-width space threaded through the digits cannot
    # split the run past the regex.
    for subject in subjects:
        for match in RE_TWELVE.finditer(subject):
            if not _is_example_account_id(match.group(1)):
                return "account-id"

        for match in RE_TWELVE_HYPHENATED.finditer(subject):
            if not _is_example_account_id("".join(match.groups())):
                return "account-id"

    return None


# Substituted for a string that still discloses something after _mask() has done
# everything it can. See redact().
FULLY_REDACTED = "<redacted-path>"


def redact(text: str) -> str:
    """
    Mask identifiers in text that is about to be PRINTED.

    Only used for pathnames in block messages. Documentation example IDs are
    left intact: masking them would make the output misleading about which
    files are actually a problem.

    TWO STAGES, because targeted masking cannot cover everything scan_line sees.
    _mask() rewrites the identifiers it can find IN THE TEXT AS WRITTEN, which
    keeps the path recognisable. But scan_line matches over every READING of the
    line — percent-decoded, invisible-characters-stripped — and a hit that
    exists only in a derived reading has no span in the original to mask. That
    gap was opened by 5.2.0's own hardening: before it, the rules and the
    redactor both looked at raw text only and therefore agreed, and widening
    detection alone silently un-synced them. A staged pathname holding a
    percent-encoded S3 ARN, or an account ID split by a zero-width space, was
    refused as an identifier and printed verbatim in the same breath (verified
    2026-08-05).

    So the masked result is re-scanned, and anything still dirty is replaced
    WHOLESALE. Losing the filename in that case is the correct trade: the whole
    point of this function is that a block message must never be the thing that
    publishes the identifier.
    """
    masked = _mask(text)
    if scan_line(masked, honor_allow_marker=False) is not None:
        return FULLY_REDACTED
    return masked


def _mask(text: str) -> str:
    """Targeted substitution of identifiers appearing literally in `text`."""

    def _twelve(match: re.Match[str]) -> str:
        value = match.group(1)
        return value if _is_example_account_id(value) else "<redacted-account-id>"

    def _hyphenated(match: re.Match[str]) -> str:
        joined = "".join(match.groups())
        return match.group(0) if _is_example_account_id(joined) else "<redacted-account-id>"

    # Every rule scan_line can report must have a counterpart here, or a path
    # that blocks under that rule gets printed verbatim in the block message.
    # s3-arn and private-key-header were missing: an internal bucket name was
    # refused as an identifier and then echoed to stderr in the same breath.
    def _bucket(match: re.Match[str]) -> str:
        # Only the first non-empty segment is replaced, so the rest of a path
        # survives and the file stays findable — the same reason
        # redact() masks the ID inside a bucket-shaped filename rather than the
        # whole name.
        segments = match.group(2).split("/")
        for i, segment in enumerate(segments):
            if not segment:
                continue
            if _is_placeholder_bucket(segment):
                return match.group(0)
            segments[i] = "<redacted-bucket>"
            break
        return match.group(1) + "/".join(segments)

    text = RE_PEM.sub("<redacted-key-header>", text)
    text = RE_ARN_S3_BUCKET.sub(_bucket, text)
    text = RE_AWS_UNIQUE_ID.sub("<redacted-key-id>", text)
    text = RE_TWELVE.sub(_twelve, text)
    text = RE_TWELVE_HYPHENATED.sub(_hyphenated, text)
    return text


# Byte-order marks, WIDEST FIRST. BOM_UTF32_LE is b"\xff\xfe\x00\x00", whose
# first two bytes ARE BOM_UTF16_LE — so testing UTF-16 first captures every
# UTF-32-LE file and decodes it into rubbish.
BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
    (codecs.BOM_UTF8, "utf-8"),
)

# A wide decode must be mostly ASCII to count as text; a single-byte decode must
# be mostly free of control characters. The two tests are different on purpose —
# see _is_plausible_text.
MIN_ASCII_RATIO = 0.80
MAX_CONTROL_RATIO = 0.05

# Ceiling on bytes decoded six ways. See _iter_decoded_lines.
MAX_DECODE_BYTES = 10 * 1024 * 1024

# Control characters that DO occur in ordinary text.
TEXT_CONTROLS = frozenset("\t\n\r\f\v")

CANDIDATE_ENCODINGS = (
    ("utf-8", "single"),
    ("utf-16-le", "wide"),
    ("utf-16-be", "wide"),
    ("utf-32-le", "wide"),
    ("utf-32-be", "wide"),
    # Always last and always succeeds: latin-1 is a 1:1 byte mapping, so it is
    # the reading in which a raw-ASCII identifier can never fail to appear.
    ("latin-1", "single"),
)


def _is_plausible_text(text: str, kind: str) -> bool:
    """
    Positive evidence that a decode produced text rather than rubbish.

    Used ONLY to decide whether a file is opaque enough to need human review.
    It does not decide what gets scanned — everything gets scanned.

    A successful decode proves almost nothing: utf-16 accepts very nearly any
    even-length byte string, so binary "decodes" into CJK mojibake without
    raising. The test differs by encoding family because a single rule cannot
    separate both failure modes:

      * SINGLE-BYTE readings are judged on control characters. Real prose in any
        script — Cyrillic in cp1251, Greek in cp1253, accented Latin — decodes
        through latin-1 into printable characters, while binary decodes into
        control bytes. An ASCII-ratio test here would reject every non-Latin
        document, which is what an earlier version of this did.
      * WIDE readings are judged on ASCII share, because mojibake from binary is
        perfectly "printable" CJK and control characters would not catch it.
    """
    if not text:
        return True
    if kind == "wide":
        if "\x00" in text:
            return False
        return sum(1 for ch in text if ch < "\x80") / len(text) >= MIN_ASCII_RATIO
    controls = sum(
        1 for ch in text if ch not in TEXT_CONTROLS and (ch < " " or ch == "\x7f")
    )
    return controls / len(text) <= MAX_CONTROL_RATIO


def _decode(data: bytes, encoding: str) -> str | None:
    try:
        return data.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        return None


def _decode_candidates(data: bytes) -> list[tuple[str, str]]:
    """
    EVERY plausible reading of these bytes, as (text, kind) pairs.

    Returning one chosen reading was itself a bypass. Anything not expressible
    in the winning encoding became invisible: pad a file with UTF-16 text so the
    UTF-16 reading wins and reads as clean prose, append an account ID as raw
    UTF-8 bytes, and the ID is shredded into CJK in the only view ever examined.
    It scanned rc 0 with no finding and no acknowledgement (verified 2026-08-04).

    The flaw was structural, not a threshold that needed tightening, so every
    candidate is scanned and the hits are unioned. latin-1 is always among them
    and is lossless for ASCII, so an ASCII identifier present anywhere in the
    bytes surfaces in at least one reading.
    """
    if not data:
        return [("", "single")]

    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(text: str | None, kind: str) -> None:
        if text is not None and text not in seen:
            seen.add(text)
            out.append((text, kind))

    # A declared BOM wins the "is this text" question, so it is offered first.
    for bom, encoding in BOMS:
        if data.startswith(bom):
            add(_decode(data[len(bom):], encoding), _bom_kind(encoding))
            break

    for encoding, kind in CANDIDATE_ENCODINGS:
        add(_decode(data, encoding), kind)
    return out


def _bom_kind(encoding: str) -> str:
    return "wide" if encoding.startswith(("utf-16", "utf-32")) else "single"


def _iter_decoded_lines(path: str, data: bytes, unscannable: list[str]):
    """
    Yield (path, lineno, content) for every candidate reading of `data`.

    A file whose readings are ALL implausible is recorded as unscannable — but
    it is still scanned, so an identifier that happens to be findable is
    reported as a finding rather than as the weaker "review this yourself".

    Oversized input is refused rather than decoded. Reading one blob six ways
    holds every candidate in memory at once, roughly 11x the file size: a 50 MB
    artifact peaked at ~571 MB RSS in testing, and a 200 MB one would approach
    2 GB inside a pre-commit hook. Recording it unscannable costs nothing here —
    nobody audits a 10 MB opaque file by reading it, which is exactly what the
    acknowledgement is asking them to confirm they have done.
    """
    if len(data) > MAX_DECODE_BYTES:
        unscannable.append(path)
        return

    candidates = _decode_candidates(data)
    if not any(_is_plausible_text(text, kind) for text, kind in candidates):
        unscannable.append(path)
    for text, _kind in candidates:
        for n, line in enumerate(text.splitlines(), 1):
            yield path, n, line


# --- git plumbing ------------------------------------------------------------

# Repo config must not be able to decide what this control sees. `diff.external`
# replaces git's diff machinery wholesale, and a `diff=<driver>` attribute with a
# textconv filter rewrites file content before it is diffed — either one makes an
# identifier-bearing file emit no '+' lines at all, which reads as a clean scan.
# This is the same failure as the `.gitattributes -diff` hole, reached through a
# different setting: config that is convenient for humans reading diffs must not
# also be config that silently disarms the scanner. numstat is unaffected by
# them, so the undiffed-file fallback never fires either.
NO_CUSTOM_DIFF = ("--no-ext-diff", "--no-textconv")


def _git(args: list[str], purpose: str) -> bytes:
    """
    Run a git command, or BLOCK.

    FAIL CLOSED. Reading only stdout and ignoring the exit status meant a failed
    git invocation produced an empty string, which yields zero lines, which scans
    clean and lets the commit through with this control silently off. That is the
    opposite of the posture the pre-commit hook already takes for a MISSING
    scanner, where it blocks — so the two disagreed about the same question. A
    scan that cannot run must block, full stop.

    `purpose` is a fixed English phrase and never interpolates a pathname: a path
    can itself be the identifier, and this text goes to stderr.
    """
    proc = subprocess.run(["git", *args], capture_output=True, check=False)
    if proc.returncode != 0:
        # Only the first couple of stderr lines: git answers a bad invocation
        # with its full usage text, which would bury the actual message.
        stderr = proc.stderr.decode("utf-8", errors="replace")
        detail = "\n".join(f"  {ln}" for ln in stderr.strip().splitlines()[:2])
        sys.stderr.write(
            f"scan-identifiers: BLOCKED — a git command failed (exit "
            f"{proc.returncode}), so {purpose} could not be scanned.\n"
            f"{detail}\n"
            "  Refusing the commit rather than proceeding unscanned.\n"
        )
        sys.exit(2)
    return proc.stdout


def _git_text(args: list[str], purpose: str) -> str:
    return _git(args, purpose).decode("utf-8", errors="replace")


def _git_blob(path: str) -> bytes | None:
    """
    Read a staged blob, or None if it cannot be read.

    Unlike _git this does NOT exit on failure; the caller records the path as
    unscannable, which still blocks but with an accurate message and an
    acknowledgement path rather than a bare exit 2.

    No specific reachable case is claimed for this. An earlier version of this
    comment asserted it covered staged submodules; that was wrong — a gitlink
    reports a normal "1\\t1" numstat row, never the "-\\t-" that gets here — and
    an untested rationale for a fallback is worse than none. It stays as
    defence in depth for whatever else `git cat-file` can refuse.
    """
    proc = subprocess.run(
        ["git", "cat-file", "blob", f":{path}"], capture_output=True, check=False
    )
    return proc.stdout if proc.returncode == 0 else None


# --- input modes -------------------------------------------------------------


def iter_staged_diff_lines():
    """
    Yield (path, lineno, content) for lines ADDED in the staged diff.

    The '+++ ' file header is only honoured when the preceding line was '--- ',
    which is how git always emits it. Without that guard, an added line whose
    own content begins '++ b/' appears as '+++ b/...' and would be swallowed as
    a header, skipping the scan for that line.
    """
    out = _git_text(
        ["diff", "--cached", "--unified=0", "--no-color", *NO_CUSTOM_DIFF],
        "the staged diff",
    )

    path, lineno, prev = None, 0, ""
    for raw in out.splitlines():
        if raw.startswith("+++ ") and prev.startswith("--- "):
            target = raw[4:]
            path = target[2:] if target.startswith("b/") else target
            prev = raw
            continue
        if raw.startswith("@@"):
            m = re.match(r"^@@ -[0-9,]+ \+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
            prev = raw
            continue
        if raw.startswith("+"):
            yield path, lineno, raw[1:]
            lineno += 1
        prev = raw


def iter_staged_paths():
    """
    Yield (path, None, path) for every staged pathname.

    Deletions are excluded (--diff-filter=ACMR): that path is already in
    history, and refusing the commit that removes it helps nobody. For a rename
    only the new name is checked, for the same reason.
    """
    out = _git_text(
        ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z", *NO_CUSTOM_DIFF],
        "the staged path list",
    )
    for path in out.split("\0"):
        if path:
            yield path, None, path


def _staged_numstat():
    """
    Yield (added, deleted, path) for staged changes.

    Uses -z, so pathnames are emitted verbatim rather than C-quoted. In that
    format a normal record is "<add>\\t<del>\\t<path>\\0", while a rename or copy
    is "<add>\\t<del>\\t\\0<preimage>\\0<postimage>\\0" — the trailing empty
    field after the second tab is what marks it.
    """
    out = _git_text(
        ["diff", "--cached", "--numstat", "--diff-filter=ACMR", "-z", *NO_CUSTOM_DIFF],
        "the staged file list",
    )
    fields = out.split("\0")
    i = 0
    while i < len(fields):
        record = fields[i]
        if not record:
            i += 1
            continue
        parts = record.split("\t", 2)
        if len(parts) < 3:
            i += 1
            continue
        added, deleted, rest = parts
        if rest == "":
            if i + 2 < len(fields):
                yield added, deleted, fields[i + 2]
            i += 3
        else:
            yield added, deleted, rest
            i += 1


def iter_undiffed_file_lines(unscannable: list[str]):
    """
    Yield (path, lineno, content) for staged files that produced no diff text.

    A numstat row of "-\\t-\\t<path>" is git's marker for "no text diff": either
    a genuine binary, or a path whose .gitattributes say `-diff`. Both reach the
    line-based scan as zero lines, which is indistinguishable from a clean file.

    Reads the INDEX, not the work tree, so what is scanned is what is being
    committed. Whole-file rather than added-lines-only, because for these paths
    there is no diff to take added lines from; a pre-existing identifier in an
    untouched line of such a file is being committed too.
    """
    for added, deleted, path in _staged_numstat():
        if added != "-" or deleted != "-":
            continue
        blob = _git_blob(path)
        if blob is None:
            unscannable.append(path)
            continue
        yield from _iter_decoded_lines(path, blob, unscannable)


def iter_file_lines(paths, unscannable: list[str]):
    """
    Yield (path, lineno, content) for full file contents.

    FAILS CLOSED, like every other mode. This used to swallow OSError and move
    on, so a missing path, an unreadable path and a directory each scanned as
    rc 0 — and this is the mode the cfs-guard shim uses on CFS documents, the
    2026-07-18 sink. The staged-diff path had already been hardened to exit
    rather than proceed unscanned; the two modes disagreed about the same
    question, which is exactly the contradiction that produced the original bug.
    """
    for p in paths:
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            unscannable.append(p)
            continue
        yield from _iter_decoded_lines(p, data, unscannable)


def iter_stdin_lines(label):
    """
    Yield (label, lineno, content) for text piped on stdin.

    Exists so ephemeral text that never becomes a file on disk can still be
    scanned — principally COMMIT MESSAGES. A commit message is a third
    publication sink alongside committed files and third-party trackers: it is
    pushed to GitHub verbatim and is exactly as public as the repo, but neither
    --staged-diff (which sees only staged file content) nor --files covers it.

    NOTHING is stripped here — not comment lines, not git's scissors region.
    Both were tried and both were the same mistake: git removes them only for
    EDITOR-driven commits, while `-m` and `-F` use cleanup mode `whitespace` and
    store the text verbatim. So in each case the input the caller most needed
    scanned was precisely the input being discarded. Verified on git 2.49.0: an
    account ID below a scissors marker, committed with -F, is in the stored
    message. A commit-msg hook cannot see the cleanup mode, so it cannot know
    which case it is in, and the only safe answer is to scan the whole thing.
    """
    for n, line in enumerate(sys.stdin.read().splitlines(), 1):
        yield label, n, line


# --- reporting ---------------------------------------------------------------

BLOCK_HEADER = {
    "diff": "BLOCKED — staged changes introduce cloud identifiers.",
    "files": "BLOCKED — these documents contain cloud identifiers.",
    "stdin": "BLOCKED — this text contains cloud identifiers.",
}


def _report_hits(hits) -> None:
    e = sys.stderr
    print("", file=e)
    for location, rule in hits:
        print(f"  {location}  [{rule}]", file=e)
    print("", file=e)
    print("  (locations only — matched values are deliberately not printed)", file=e)
    print("", file=e)
    print("  Use a placeholder such as <AWS_ACCOUNT_ID> and resolve at runtime:", file=e)
    print("    aws sts get-caller-identity --query Account --output text", file=e)
    print("", file=e)
    print("  CFS docs sync into GitHub issues, which are exactly as public as the", file=e)
    print("  repo. Check with: gh repo view --json visibility", file=e)
    print("", file=e)
    print("  If a line is genuinely fine — a real UUID whose tail is 12 digits, or a", file=e)
    print(f"  non-AWS 12-digit number — append '{ALLOW_MARKER}' to that line.", file=e)
    print("  A hit marked (pathname) is in the FILE NAME; rename the file instead.", file=e)
    print("  Do not blanket-bypass with --no-verify.", file=e)


def _report_unscannable(paths: list[str]) -> None:
    e = sys.stderr
    print("scan-identifiers: BLOCKED — some files could not be scanned.", file=e)
    print("", file=e)
    for path in paths:
        print(f"  {redact(path)}", file=e)
    print("", file=e)
    print("  These are binary, unreadable, or not decodable as text, so not one", file=e)
    print("  line of them was checked. A", file=e)
    print("  spreadsheet export or a console screenshot carries account IDs, ARNs", file=e)
    print("  and bucket names exactly as a text file does — the difference is only", file=e)
    print("  that nothing here can look. Silently passing them would make this", file=e)
    print("  control report clean on the files it understands least.", file=e)
    print("", file=e)
    print("  Review them yourself, then acknowledge for this commit only:", file=e)
    print(f"    {ALLOW_UNSCANNABLE_ENV}=1 git commit ...", file=e)


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan for AWS cloud identifiers.")
    # Not required at parse time so that --version works on its own; enforced
    # below instead. Previously the group was required=True, which made
    # `--version` unusable — it always died on "one of the arguments ... is
    # required" before reaching the version branch.
    mode = ap.add_mutually_exclusive_group(required=False)
    mode.add_argument("--staged-diff", action="store_true",
                      help="Scan staged content, pathnames and undiffed files.")
    mode.add_argument("--files", nargs="+", metavar="PATH",
                      help="Scan full contents of these files.")
    mode.add_argument("--stdin", action="store_true",
                      help="Scan text piped on stdin (e.g. a commit message).")
    ap.add_argument("--label", default="<stdin>", metavar="NAME",
                    help="Name to report for --stdin hits (default: <stdin>).")
    ap.add_argument("--version", action="store_true",
                    help="Print scanner version and exit.")
    args = ap.parse_args()

    if args.version:
        print(SCANNER_VERSION)
        return 0

    if not (args.staged_diff or args.stdin or args.files):
        ap.error("one of the arguments --staged-diff --files --stdin is required")

    unscannable: list[str] = []

    # Whether a subject is a PATHNAME is tagged HERE, where the generators are
    # composed and the answer is known, rather than inferred downstream from
    # `lineno is None`. The two failure directions are not symmetric: a content
    # generator that forgot to set the flag only makes the scan stricter, but a
    # pathname generator that forgot it silently restores the bug where
    # `notes-allow-identifier-<id>.md` exempts itself.
    def _tag(source, is_pathname):
        for path, lineno, content in source:
            yield path, lineno, content, is_pathname

    if args.staged_diff:
        source = itertools.chain(
            _tag(iter_staged_diff_lines(), False),
            _tag(iter_staged_paths(), True),
            _tag(iter_undiffed_file_lines(unscannable), False),
        )
        kind = "diff"
    elif args.stdin:
        source = _tag(iter_stdin_lines(args.label), False)
        kind = "stdin"
    else:
        source = _tag(iter_file_lines(args.files, unscannable), False)
        kind = "files"

    # Deduplicated: a file is now read through several candidate encodings, and
    # for ASCII content those readings are identical, so the same finding would
    # otherwise be printed once per encoding.
    hits: list[tuple[str, str]] = []
    seen_hits: set[tuple[str, str]] = set()
    for path, lineno, content, is_pathname in source:
        rule = scan_line(content, honor_allow_marker=not is_pathname)
        if rule:
            shown = redact(path or "<unknown>")
            location = f"{shown} (pathname)" if is_pathname else f"{shown}:{lineno}"
            if (location, rule) not in seen_hits:
                seen_hits.add((location, rule))
                hits.append((location, rule))

    if hits:
        print(f"scan-identifiers: {BLOCK_HEADER[kind]}", file=sys.stderr)
        _report_hits(hits)
        return 1

    # Checked only after a clean content scan, so a real identifier is always the
    # reported reason when both apply.
    acknowledged = os.environ.get(ALLOW_UNSCANNABLE_ENV, "").strip().lower() in TRUTHY
    if unscannable and not acknowledged:
        _report_unscannable(unscannable)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
