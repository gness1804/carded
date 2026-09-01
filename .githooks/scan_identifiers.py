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
import unicodedata

SCANNER_VERSION = "5.5.1"

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
#
# The boundaries are explicit character-class lookarounds, not \b, since 5.3.0.
# \b treats '_' as a word character, so the shapes these IDs most often appear
# in — `creds_AKIA…_old`, an env var name, a filename — put an underscore either
# side and the boundary assertion failed. Underscore now delimits like any other
# punctuation. A key butted directly against MORE alphanumerics still does not
# match, which is intended: that is not a well-formed ID.
RE_AWS_UNIQUE_ID = re.compile(
    r"(?<![0-9A-Za-z])(?:AKIA|ASIA|AROA|AIDA|APKA|ANPA|AGPA|AIPA)"
    r"[0-9A-Z]{16,17}(?![0-9A-Za-z])"
)

# ARNs. Partition is [a-z-]* so aws-cn and aws-us-gov are covered. Matched on a
# URL-decoded copy of the line too, so percent-encoded ARNs cannot slip past.
#
# The account ID is CAPTURED rather than just matched, so a documentation-example
# ARN (arn:aws:iam::111122223333:root, which AWS's own docs are full of) is not
# reported. Without the capture this rule fired on every pasted example policy —
# exactly the noise that trains people to reach for --no-verify.
#
# IGNORECASE since 5.3.0: `ARN:AWS:S3:::<bucket>` scanned clean end to end. An
# uppercase IAM ARN was still caught by RE_TWELVE on its account digits, but a
# bucket ARN has no second rule behind it, so that casing was a total miss.
RE_ARN_ACCOUNT = re.compile(
    r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:([0-9]{12}):", re.IGNORECASE
)
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
RE_ARN_S3 = re.compile(r"arn:aws[a-z-]*:s3:::([^\s\"\'`,\]\)}]*)", re.IGNORECASE)

# The SAME bucket name, written the three other ways people actually write it.
#
# Until 5.3.0 a bucket name was only recognised inside `arn:aws:s3:::`, which is
# the LEAST common form: nobody types an ARN to copy a file. `s3://<bucket>`,
# a virtual-hosted URL and a path-style URL all scanned clean, and unlike an
# account ID a bucket name has no second rule behind it, so the miss was total.
# The 2026-07-18 incident's leaked item was a bucket name holding personal data.
#
# All three capture the bucket and run through the same _is_placeholder_bucket
# filter as the ARN rule, so `s3://my-bucket` stays as waivable as
# `arn:aws:s3:::my-bucket` — the house placeholder convention keeps working.
# The `s3:` and `//` halves are concatenated rather than written whole, for the
# same reason the s3-arn fixtures in the test suite are split: written as one
# literal, this line matches its OWN rule and makes the scanner unstageable
# under itself. Caught by running the new rule over the repo, which is the
# cheapest possible way to find out.
RE_S3_URI = re.compile(
    r"(?<![0-9A-Za-z])" + r"s3:" + r"//([^\s\"\'`,\]\)}]*)", re.IGNORECASE
)
RE_S3_VHOST = re.compile(
    r"https?://([a-z0-9][a-z0-9.\-]*)\.s3[.-][a-z0-9.\-]*amazonaws\.com",
    re.IGNORECASE,
)
RE_S3_PATH_STYLE = re.compile(
    r"https?://s3[.-][a-z0-9.\-]*amazonaws\.com/([^\s\"\'`,\]\)}]*)",
    re.IGNORECASE,
)

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


def _is_placeholder_bucket(name: str, dns_form: bool = False) -> bool:
    """
    True if this bucket segment is a stand-in rather than a real name.

    `dns_form` marks a name that came out of a HOSTNAME rather than an ARN or
    an s3 URI. DNS is case-insensitive, so a virtual-hosted URL written with the
    bucket label in CAPITALS still resolves to the real, lowercase bucket —
    which means the all-caps "obviously a placeholder" test must NOT apply
    there. (Spelled out in prose rather than shown: a literal example would
    make this file unstageable under its own rule.) It is sound for ARNs,
    where the name is case-sensitive and an all-caps one genuinely cannot be
    the real bucket. Applying it to both was a false negative introduced by
    5.3.0's own IGNORECASE change and caught only on re-review.
    """
    # S3 bucket names are 3-63 characters, so anything shorter is not a name
    # that could exist — it is someone's shorthand. `aws s3 cp s3://b s3://b`
    # in a runbook is the common shape. Length is a property of the naming
    # rules rather than a guess, so this cannot exempt a real bucket.
    #
    # Known, accepted narrowing: `s3://ab/real-bucket` blocked in 5.2.0 and does
    # not now, because the first segment is what gets tested. Disclosure needs
    # the bucket in first position, so the loss is small — and the alternative
    # (walking past a short first segment) would start reporting ordinary KEY
    # names as buckets, which is a worse trade.
    if len(name) < 3:
        return True
    if name in PLACEHOLDER_BUCKETS:
        return True
    if name.startswith(PLACEHOLDER_BUCKET_STARTS):
        return True
    if RE_PERCENT_TEMPLATE.match(name):
        return True
    if not dns_form and RE_SHOUTING_PLACEHOLDER.match(name):
        return True
    return name.lower().startswith(PLACEHOLDER_BUCKET_PREFIXES)

RE_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

# A 12-digit run with no digit on either side. (?<!\d) / (?!\d) are what make
# 11- and 13-digit numbers safe, and are precisely what ERE could not express.
RE_TWELVE = re.compile(r"(?<!\d)(\d{12})(?!\d)")

# The console renders account IDs hyphenated in some views.
#
# 5.3.0 tried to generalise the separator and ended up back at HYPHEN ONLY,
# which is where master already was. Recording the attempt because the reasoning
# is the useful part, and because the next person will have the same idea.
#
# Attempt 1, [-._ ]: `chmod 0644 0755 0700`, `Ports 8080 9090 3000 are open` and
# `latency ms: 1200 1450 1600` all blocked as account IDs. Any three
# space-separated 4-digit numbers did. Dot brought Cisco-format MAC addresses
# (0011.2233.4455) with it.
#
# Attempt 2, [-_]: underscore looked near-costless and is not. Timestamped
# filenames are exactly this shape — `backup_2026_0812_1530.log`,
# `release_1024_2048_4096.bin` — and PATHNAMES are scanned with
# honor_allow_marker=False, by design, because a marker in a filename would be a
# permanent committed exemption. So there is no way to waive it: the only remedy
# is renaming the file. An unwaivable false positive is the worst kind.
#
# A THIRD review, 2026-08-31, reached the same conclusion and recorded it as
# WON'T-FIX rather than reopening it. If you are the fourth: the two attempts
# below are the entire argument, and nothing about them has changed. The gap is
# non-hyphen-separated account IDs; the price of closing it is a rule that fires
# on `chmod 0644 0755 0700` or on `backup_2026_0812_1530.log`, and the second of
# those cannot be waived at all because pathnames ignore the allow-marker.
#
# A rule that fires on `chmod` output or on a log filename is worse than the gap
# it closes, because it is the rule that teaches someone to reach for
# --no-verify, and after that nothing in this file works. Non-hyphen separated
# IDs are a real residual miss, accepted knowingly and pinned in the test suite
# so nobody "fixes" it back a third time.
#
# The separator is still captured and back-referenced. With a one-member class
# that is redundant, and it is kept so the shape survives if the class ever
# widens again — but note it only rejects MIXED separators, which was never what
# kept prose safe. An earlier comment claiming otherwise was simply wrong.
RE_TWELVE_HYPHENATED = re.compile(
    r"(?<!\d)(\d{4})([-])(\d{4})\2(\d{4})(?!\d)"
)


def _separated_digits(match: re.Match[str]) -> str:
    """The 12 digits of a RE_TWELVE_HYPHENATED match, separators dropped."""
    return match.group(1) + match.group(3) + match.group(4)

# S3 ARNs are redacted as a unit: the bucket NAME is the sensitive part, and
# masking only the arn: prefix would leave it printed in full. The name is
# captured as well as the prefix so redact() can apply the SAME placeholder test
# scan_line uses — otherwise the two disagree, and a path containing
# `arn:aws:s3:::BUCKET` gets masked in a block message about a finding that this
# scanner never raised.
RE_ARN_S3_BUCKET = re.compile(r"(arn:aws[a-z-]*:s3:::)([^\s]*)", re.IGNORECASE)

# redact() counterparts for the three non-ARN bucket forms. Every rule scan_line
# can report needs one of these, or a path blocked under that rule is echoed
# verbatim in the very message announcing that it was blocked.
RE_S3_URI_BUCKET = re.compile(
    r"(?<![0-9A-Za-z])" + r"(s3:" + r"//)([^\s]*)", re.IGNORECASE
)
RE_S3_PATH_STYLE_BUCKET = re.compile(
    r"(https?://s3[.-][a-z0-9.\-]*amazonaws\.com/)([^\s]*)", re.IGNORECASE
)

# Zero-width and invisible characters. Pasting from a console or a rich-text
# editor can thread these through an identifier, splitting a 12-digit run into
# two shorter ones that no rule matches while it still reads as an account ID to
# every human and renders as one on GitHub. Stripped before the digit rules run.
#
# 5.2.0 pinned a LITERAL LIST of ten codepoints, which made this the weakest
# defence in the file for exactly as long as nobody looked past that list. A
# 2026-08-12 review demonstrated bypasses for account-id, aws-unique-id, s3-arn
# AND private-key-header \u2014 all four at once, and redact() with them \u2014 using
# bidi controls (U+202A-202E, U+2066-2069), variation selectors (U+FE00-FE0F),
# tag characters (U+E0000-E007F) and combining marks. Every one of those renders
# identically on GitHub and in every editor.
#
# So the test is now the Unicode CATEGORY, not membership of a list: Cf (format,
# which covers zero-width spaces, bidi controls, tag characters and the soft
# hyphen), Mn (nonspacing marks, which covers variation selectors and combining
# marks), and Cc (controls) minus the three that are real text. A list can be
# walked around by the next codepoint someone finds; a category cannot.
#
# This is an ADDITIONAL reading, never a replacement \u2014 the line as written is
# still scanned \u2014 so a too-aggressive strip can only produce a false positive,
# which a human can see and waive. A too-narrow one produces a silent miss.
RE_INVISIBLE = re.compile(r"[\u200b-\u200f\u2060\u2061\u2062\u2063\ufeff\u00ad]")

# Kept literal because they are real text, not formatting: stripping these would
# join adjacent lines and columns into runs that were never adjacent.
#
# NAMED _STRIP_PRESERVED, not TEXT_CONTROLS. The first version of this constant
# WAS called TEXT_CONTROLS, and a second, unrelated TEXT_CONTROLS defined ~270
# lines further down for _is_plausible_text silently won at runtime. That one
# includes \v and \f, so _strip_invisible preserved them \u2014 and both are Cc and
# bypass every rule in this file. A module-level name collision, invisible to
# every test, in the function whose entire job is catching invisible things.
# \r is NOT preserved: it is no longer treated as a terminator (see
# RE_LINE_BREAK), so a mid-line \r is exactly the kind of invisible splitter
# this function exists to remove. \t and \n are real text.
_STRIP_PRESERVED = frozenset("\t\n")

# Invisible codepoints that are NOT Cf/Mn/Cc and so escape the category test.
# These render as nothing at all while belonging to Lo or So:
#   U+3164 HANGUL FILLER, U+115F/U+1160 hangul choseong/jungseong fillers (Lo)
#   U+2800 BRAILLE PATTERN BLANK (So)
# U+180E is Cf now but was Zs before Unicode 6.3.0, so it is named rather than
# left to the host's unicodedata vintage.
#
# THE Zs FAMILY IS DELIBERATELY EXCLUDED, and so is the ASCII space. A space-like
# character is treated as a space, not as nothing. The first cut of this set
# included NBSP, U+2007 FIGURE SPACE and the rest of Zs, and every one of them
# fused `chmod 0644<sp>0755<sp>0700` into a 12-digit run — the same false
# positive that forced the separator class back to hyphen-only, arriving by a
# different door. NBSP is what you get pasting from a web page, and FIGURE SPACE
# is what aligns columns of numbers, so both are common in exactly the numeric
# text that would misfire. Worse, in a PATHNAME scan the allow marker is not
# honoured, so that false positive would be unwaivable.
#
# The cost is a real miss: an ID split by NBSP scans clean. Accepted for the
# same reason as the separator narrowing — a control nobody trusts is worse than
# a control with a documented gap.
EXTRA_INVISIBLE = frozenset(
    "\u180e"      # mongolian vowel separator
    "\u3164"      # hangul filler
    "\u115f"      # hangul choseong filler
    "\u1160"      # hangul jungseong filler
    "\u2800"      # braille pattern blank
    # U+2028/U+2029 are Zl/Zp line separators, and they are stripped rather than
    # split on. Splitting would not help: an ID broken across the two halves is
    # not 12 digits on either side, so it would still pass. They are treated
    # differently from the Zs spaces above because they are not used to separate
    # NUMBERS in ordinary text — the NBSP false positive came from columns of
    # figures, a shape a line separator does not appear in. Fusing two lines can
    # only misfire if one ends with exactly 4 or 8 digits and the next begins
    # with the complement, which is far rarer.
    "\u2028"      # line separator
    "\u2029"      # paragraph separator
)

_STRIPPABLE_CATEGORIES = frozenset({"Cf", "Mn", "Cc"})

# Fast path: ASCII text with nothing strippable in it, which is the
# overwhelming majority of every line this scanner ever sees.
#
# DERIVED from _STRIP_PRESERVED and _STRIPPABLE_CATEGORIES rather than written
# out as a character class. The hand-written version listed \x0b, \x0c and
# \x0e-\x1f but skipped \x0d, which was right while \r was preserved and wrong
# the moment it stopped being — the fast path then returned every \r-bearing
# line untouched and the strip never ran. A derived set cannot drift from the
# rule it is meant to shortcut.
_ASCII_STRIPPABLE = frozenset(
    ch
    for ch in map(chr, range(128))
    if ch not in _STRIP_PRESERVED and unicodedata.category(ch) in _STRIPPABLE_CATEGORIES
)


def _strip_invisible(text: str) -> str:
    """
    Remove every formatting, combining and control character that can be
    threaded through an identifier without changing how it reads.
    """
    if text.isascii() and not _ASCII_STRIPPABLE.intersection(text):
        return text
    out = []
    for ch in text:
        if ch in _STRIP_PRESERVED:
            out.append(ch)
            continue
        if ch in EXTRA_INVISIBLE:
            continue
        if unicodedata.category(ch) in _STRIPPABLE_CATEGORIES:
            continue
        out.append(ch)
    return "".join(out)


# Line splitting for SCANNING. Deliberately not str.splitlines().
#
# splitlines() breaks on \v, \f, \x1c, \x1d, \x1e, \x85, U+2028 and U+2029 as
# well as the real newlines. Every one of those is a character _strip_invisible
# removes precisely because it can be threaded through an identifier — but the
# split happens FIRST, so the two halves reached scan_line as separate lines and
# no rule ever saw the whole ID. Rc 0 in --staged-diff, --files and --stdin
# alike, and in the diff path the second half no longer began with '+', so it
# was dropped entirely rather than merely split.
#
# Found on the third review pass, after two earlier passes had signed off on the
# _strip_invisible fix that this quietly defeated: the function was correct and
# unreachable. Only the three real line terminators split here.
# \r\n and \n ONLY. A BARE \r IS CONTENT, NOT A TERMINATOR.
#
# The third pass fixed this for splitlines() and the fourth pass found the same
# defect surviving in \r, which the replacement still split on. In the staged
# diff, git's record terminator is \n; a bare \r inside a line is data. Split
# there and the fragment after it no longer begins with '+', so the diff parser
# DISCARDS it — an identifier following a mid-line \r scanned rc 0 through
# --staged-diff, which is the only mode the pre-commit hook ever calls.
#
# The cost is that a CR-only file (classic Mac line endings) reads as a single
# long line. Every rule still matches — they are per-string, not per-line — so
# nothing is MISSED; the reported line number degrades to 1.
#
# It does change detection in the other direction, though, and an earlier
# version of this comment wrongly claimed it did not: fusing the lines can also
# create a match that was never there, e.g. a CR-separated column of 4-digit
# numbers reading as one 12-digit run. That is a false positive, waivable with
# the marker in content, and the trade is still clearly right — a wrong line
# number or an over-eager block beats a silent miss.
RE_LINE_BREAK = re.compile(r"\r\n|\n")


def split_lines(text: str) -> list[str]:
    """Split on real line terminators only, never on in-line control chars."""
    return RE_LINE_BREAK.split(text)


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
        for form in (text, RE_INVISIBLE.sub("", text), _strip_invisible(text)):
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

        # The same bucket name in the forms people actually write. Reported
        # under their own rule name rather than "s3-arn" so a block message
        # names the syntax the author used and is actionable without guessing.
        for rule, pattern, dns_form in (
            ("s3-uri", RE_S3_URI, False),
            ("s3-url", RE_S3_VHOST, True),
            ("s3-url", RE_S3_PATH_STYLE, False),
        ):
            for match in pattern.finditer(subject):
                segment = _bucket_segment(match.group(1))
                if not _is_placeholder_bucket(segment, dns_form=dns_form):
                    return rule

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
            if not _is_example_account_id(_separated_digits(match)):
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

    THE RE-SCAN ALSO STRIPS U+FFFD, which is a PARTIAL BACKSTOP and not the real
    control. Say so plainly, because the first version of it was mistaken for
    one: a display string has already been through an escaping transform, and
    each transform splits a digit run its own way — utf-8/replace inserts U+FFFD,
    git's `core.quotePath` (ON BY DEFAULT) inserts a literal `\\377`. Stripping
    U+FFFD closed the first and left the second printing twelve digits of an
    account ID. Enumerating splitters is a list where a category is needed.

    Stripping U+FFFD is sufficient ONLY because every path reaching print is now
    decoded exactly once, utf-8/replace, from the true bytes — see
    _unquote_c_path, which converts git's C-quoted header form back to bytes
    before that decode. One transform means one artifact. If a caller ever prints
    a path that took a different route, this guard no longer covers it and the
    fix is to normalise the route, not to add another escape to the list.

    U+FFFD is category So, so _strip_invisible leaves it; it is removed here
    rather than added to EXTRA_INVISIBLE because doing that globally would fuse
    unrelated digit groups in ordinary content, which is the false positive that
    got NBSP rejected.
    """
    masked = _mask(text)
    for candidate in (masked, masked.replace("�", "")):
        if scan_line(candidate, honor_allow_marker=False) is not None:
            return FULLY_REDACTED
    return masked


def _mask(text: str) -> str:
    """Targeted substitution of identifiers appearing literally in `text`."""

    def _twelve(match: re.Match[str]) -> str:
        value = match.group(1)
        return value if _is_example_account_id(value) else "<redacted-account-id>"

    def _hyphenated(match: re.Match[str]) -> str:
        # _separated_digits, not "".join(groups): group 2 is the separator, and
        # folding it into the digits would make a real ID fail the example test
        # and an example ID pass it — inverted in both directions.
        joined = _separated_digits(match)
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

    def _vhost(match: re.Match[str]) -> str:
        # The bucket sits in the SUBDOMAIN here, so _bucket's prefix/path shape
        # does not apply. Only the leading label is replaced; the rest of the
        # host survives so the region stays readable.
        #
        # Spliced by SPAN, not by str.replace. replace() rewrites the first
        # occurrence anywhere in the match, so a bucket whose name happens to be
        # a substring of the URL SCHEME (a bucket named after the scheme itself)
        # masked the scheme and printed the bucket name in full — and redact()'s
        # re-scan could not see it, because the mangled text no longer matched.
        # Pinned in the test suite, where the literal URL can live safely.
        if _is_placeholder_bucket(match.group(1), dns_form=True):
            return match.group(0)
        whole = match.group(0)
        start = match.start(1) - match.start(0)
        end = match.end(1) - match.start(0)
        return whole[:start] + "<redacted-bucket>" + whole[end:]

    text = RE_PEM.sub("<redacted-key-header>", text)
    text = RE_ARN_S3_BUCKET.sub(_bucket, text)
    # Same three forms scan_line now blocks on, redacted with the same filter.
    text = RE_S3_VHOST.sub(_vhost, text)
    text = RE_S3_PATH_STYLE_BUCKET.sub(_bucket, text)
    text = RE_S3_URI_BUCKET.sub(_bucket, text)
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

# Container formats whose payload is COMPRESSED. Nothing in this file
# decompresses anything, so every candidate reading of one of these is a reading
# of the deflated byte stream — the identifier inside is not obscured, it is
# simply not present in any view this scanner ever looks at.
#
# The failure that motivates this is not theoretical. Deflate output is usually
# high-entropy enough to fail _is_plausible_text on its own, which is why most
# archives already reported unscannable — but a MIXED archive does not. Verified
# 2026-08-31 against 5.4.0: a zip holding one bulky ZIP_STORED member of ASCII
# prose plus one small ZIP_DEFLATED member containing an account ID scanned rc 0,
# no finding, no acknowledgement. The stored member's clean ASCII dominates the
# control-character ratio, so the whole file reads as plausible text, and the
# deflated member is simply absent from every reading. That is the one outcome
# this control must never produce — a confident "no findings" on a file it did
# not read. An opaque blob honestly reported as unscannable is strictly better
# than a clean bill of health. Same repro now returns rc 1 as unscannable.
#
# Matched on MAGIC BYTES, not on the file extension. The extension is whatever
# the author typed; the magic is what an unzipper will actually act on, and a
# renamed .docx is still a zip.
#
# PK\x03\x04 covers .zip and every OOXML/OpenDocument format built on it
# (.docx, .xlsx, .pptx, .odt, .ods) plus .jar and .epub. The OLE2 signature
# covers legacy .doc/.xls/.ppt/.msg, which are not compressed but are equally
# unparsed here. Uncompressed .tar is deliberately ABSENT: its members are
# stored as plain bytes, so it scans correctly today and marking it unscannable
# would cost a real capability for nothing.
#
# These are recorded UNSCANNABLE rather than blocked outright, so
# SCAN_ALLOW_UNSCANNABLE=1 remains the route for "I opened it and looked." A
# control that made committing any archive impossible would be replaced by
# --no-verify within a week, and --no-verify disables every check at once.
# Signatures trusted ANYWHERE in the file, not only at offset 0.
#
# Checking only the first bytes was the rule's own bypass, and a cheap one:
# `cat banner.sh mixed.zip > file` scanned rc 0 clean while `unzip -l` still
# listed every member. That is not an exotic attack — the zip format is read
# from its TAIL, which is exactly why self-extracting archives, appended-ZIP
# payloads and shebang-prefixed .jar files all work, and why a stray `cat` or a
# concatenated download produces the same shape by accident.
#
# Safe to search the whole buffer because every signature here contains a
# control or high byte, so none of them occurs in ordinary prose. The two that
# would have — bzip2's printable "BZh" and the 2-byte gzip header — are given
# their FULL magic instead: bzip2 carries the six-byte "1AY&SY" block header
# after the level digit, and gzip's method byte 0x08 (deflate) is the
# only one anything emits. A 2-byte "\x1f\x8b" alone is too weak to hunt for.
ARCHIVE_MAGIC_EMBEDDED = (
    b"PK\x03\x04",                        # zip, docx/xlsx/pptx, odt, jar, epub
    b"PK\x05\x06",                        # zip end-of-central-directory
    b"PK\x07\x08",                        # spanned zip
    b"\x1f\x8b\x08",                       # gzip (deflate), .tgz
    *(b"BZh" + bytes([d]) + b"\x31\x41\x59\x26\x53\x59"
      for d in range(ord("1"), ord("9") + 1)),          # bzip2, levels 1-9
    b"\xfd7zXZ\x00",                       # xz
    b"7z\xbc\xaf\x27\x1c",                 # 7-zip
    b"Rar!\x1a\x07",                       # rar
    b"\x04\x22\x4d\x18",                   # lz4 frame
    b"\x28\xb5\x2f\xfd",                   # zstd
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",       # OLE2: legacy .doc/.xls/.ppt/.msg
    b"SQLite format 3\x00",                # sqlite database
)

# Signatures that are printable ASCII, and therefore believed ONLY at offset 0.
# Hunting for these anywhere would fire on any document that merely QUOTES them
# — a README explaining that PDFs begin "%PDF-" is not a PDF — and a rule that
# blocks prose about the rule is how this control gets bypassed wholesale.
ARCHIVE_MAGIC_PREFIX_ONLY = (
    b"%PDF-",                              # pdf
    b"!<arch>\n",                          # ar: .deb, static libraries
    b"xar!",                               # xar: .pkg installers
    b"MSCF",                               # cab
)

# PDF deserves its own note, because it is the likeliest of all of these to
# carry a real leak and it was MISSED by the first version of this rule. A PDF
# is a mixed container in exactly the sense that defeated the plausibility test:
# ASCII object structure surrounding /FlateDecode content streams. Verified
# against 5.5.0 — a 6 KB PDF whose only account ID lived inside a compressed
# stream returned rc 0, no finding, no acknowledgement. Signed contracts,
# invoices and console exports are all PDFs, and one of those is already on this
# machine's incident list.


def _is_archive(data: bytes) -> bool:
    """True if these bytes are, or contain, a known container format."""
    if data.startswith(ARCHIVE_MAGIC_PREFIX_ONLY):
        return True
    return any(sig in data for sig in ARCHIVE_MAGIC_EMBEDDED)

# Control characters that DO occur in ordinary text.
TEXT_CONTROLS = frozenset("\t\n\r\f\v")

CANDIDATE_ENCODINGS = (
    ("utf-8", "single"),
    ("utf-16-le", "wide"),
    ("utf-16-be", "wide"),
    ("utf-32-le", "wide"),
    ("utf-32-be", "wide"),
    # latin-1 is a 1:1 byte mapping, so it is the reading in which a raw-ASCII
    # identifier can never fail to appear.
    ("latin-1", "single"),
    # EBCDIC family. These render digits as 0xF0-0xF9, which no reading above
    # reproduces as digits — an account ID in cp500 surfaces ONLY here. See
    # _EBCDIC_DIGIT_BYTES for why adding them was necessary but not sufficient.
    ("cp037", "ebcdic"),
    ("cp500", "ebcdic"),
    ("cp1026", "ebcdic"),
    ("cp424", "ebcdic"),
)

# Readings that are scanned but never count as evidence that a blob is text.
#
# _is_plausible_text decides whether a file is opaque enough to need human
# review, and it takes ANY plausible reading as a yes. Both kinds here decode
# almost anything into almost-printable output: the EBCDIC codecs map nearly the
# whole byte range, and a byte-dropping lossy decode discards exactly the
# undecodable bytes that made a blob look binary in the first place. Counting
# either as evidence would let a genuinely opaque file stop being reported as
# unscannable — the scan would get STRICTER and the fail-closed report would get
# weaker in the same change, which is the wrong trade in both directions.
NON_EVIDENCE_KINDS = frozenset({"ebcdic", "lossy"})


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
    if kind in NON_EVIDENCE_KINDS:
        return False
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

    # A byte-DROPPING reading, added last so a strict utf-8 decode wins the dedup
    # and keeps its "single" kind.
    #
    # One invalid byte parked inside a digit run defeats every reading above, and
    # not because any of them is lossy — it survives a lossless one too. latin-1
    # renders \xff as 'ÿ', errors="replace" renders it as U+FFFD (category So, so
    # _strip_invisible leaves it), and either way the run is SPLIT into 7 digits
    # and 5. Preserving the byte faithfully is exactly what breaks the match.
    # Dropping it re-joins the run. Verified: '9876543\xff21098' scans clean in
    # latin-1 and in replace, and reports account-id here.
    add(data.decode("utf-8", errors="ignore"), "lossy")
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
    # An archive is unscannable BY CONSTRUCTION, whatever the plausibility test
    # says about its compressed bytes — see ARCHIVE_MAGIC. It is still scanned
    # below, for the same reason every other unscannable file is: a STORED (that
    # is, uncompressed) zip member leaves its text in the clear, and a real
    # finding beats the weaker "go and review this yourself".
    if _is_archive(data) or not any(
        _is_plausible_text(text, kind) for text, kind in candidates
    ):
        unscannable.append(path)
    for text, _kind in candidates:
        for n, line in enumerate(split_lines(text), 1):
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
    can itself be the identifier, and this text goes to stderr. That guarantee
    covered `purpose` and NOT git's own stderr, which was written through raw —
    and git quotes the offending pathname back at you in most of its failure
    messages. Now redacted, like every other path this file displays.
    """
    proc = subprocess.run(["git", *args], capture_output=True, check=False)
    if proc.returncode != 0:
        # Only the first couple of stderr lines: git answers a bad invocation
        # with its full usage text, which would bury the actual message.
        stderr = proc.stderr.decode("utf-8", errors="replace")
        detail = "\n".join(f"  {redact(ln)}" for ln in stderr.strip().splitlines()[:2])
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
    # `:./{path}`, NOT `:{path}`. A bare `:name` is a REVSPEC, and `:0:notes.md`
    # means "stage 0 of notes.md" — so a staged file literally named
    # `0:notes.md` resolved to a DIFFERENT blob, which scanned clean while the
    # real one carried the identifier. The `:./` form is documented in
    # gitrevisions as path-relative-to-cwd and cannot be reinterpreted as a
    # stage number. Hooks run at the top level, so cwd is the repo root.
    proc = subprocess.run(
        ["git", "cat-file", "blob", f":./{path}"], capture_output=True, check=False
    )
    return proc.stdout if proc.returncode == 0 else None


# --- input modes -------------------------------------------------------------

_C_QUOTE_SIMPLE = {
    "a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92,
}


def _unquote_c_path(text: str) -> bytes:
    """
    The BYTES of a pathname git printed in its `+++ ` header.

    `core.quotePath` is ON BY DEFAULT, so git wraps any non-ASCII path in quotes
    and renders each byte outside ASCII as an octal escape — `\\377` — plus the
    usual `\\n`, `\\t`, `\\"` and `\\\\`. Recovering the bytes is what lets the
    display be built and vetted the same way iter_staged_paths does it, instead
    of guessing which escapes a display string might be hiding.

    An unquoted path is already its own bytes under latin-1, which is how the
    diff was decoded.
    """
    if not (len(text) >= 2 and text.startswith('"') and text.endswith('"')):
        return text.encode("latin-1")

    body, out, i = text[1:-1], bytearray(), 0
    while i < len(body):
        if body[i] != "\\":
            out.extend(body[i].encode("latin-1"))
            i += 1
            continue
        i += 1
        if i >= len(body):            # trailing backslash: literal
            out.append(92)
            break
        ch = body[i]
        if ch in _C_QUOTE_SIMPLE:
            out.append(_C_QUOTE_SIMPLE[ch])
            i += 1
        elif ch in "01234567":
            digits = ""
            while i < len(body) and len(digits) < 3 and body[i] in "01234567":
                digits += body[i]
                i += 1
            out.append(int(digits, 8) & 0xFF)
        else:                          # unknown escape: keep both characters
            out.append(92)
            out.extend(ch.encode("latin-1"))
            i += 1
    return bytes(out)


def _line_readings(data: bytes, allow_lossy: bool = True) -> tuple[str, ...]:
    """
    Every reading of ONE line's raw bytes that a rule must be tried against.

    `allow_lossy` is False for PATHNAMES, and that asymmetry is deliberate. The
    byte-dropping reading finds an identifier split by an undecodable byte, but
    it finds it by JOINING what the byte separated — and joining is exactly how
    a false positive is manufactured. `rapport-2026\\xb40812\\xb41530.txt`,
    `photo-2026\\xe90812\\xe91530.jpg` and `backup_1024\\xff2048\\xff4096.bin` all
    collapse into a twelve-digit run and block.

    In CONTENT that is an acceptable trade, because the allow marker can waive it
    on the offending line. Pathnames are scanned with honor_allow_marker=False by
    design — a marker in a filename would be a permanent committed exemption —
    so there the same false positive is UNWAIVABLE, and the only remedy is
    renaming the file. This file's own comments already call an unwaivable false
    positive the worst kind; it is why underscore was dropped from the separator
    class after `backup_2026_0812_1530.log` was blocked.

    What that costs is recorded as an accepted gap: an identifier split by an
    undecodable byte inside a FILENAME is not detected. Reaching it needs a
    hand-crafted git index — macOS refuses to create such a name (Errno 92) — and
    it is pinned by test_a_split_identifier_in_a_pathname_is_an_accepted_gap.

    The blob path gets this from _decode_candidates, which reads a whole file six
    ways. A diff line cannot use that: the readings are per-file there, and
    decoding a diff as utf-16 or cp500 would shred git's own '+' and '@@'
    framing along with the content. So the framing is parsed once in latin-1 —
    lossless, and git emits it as ASCII — and each added line's bytes are re-read
    here instead.

    Deliberately NARROWER than _decode_candidates: the wide encodings are
    omitted. A utf-16 or utf-32 identifier reaching this path still blocks, but
    NOT for the reason an earlier version of this comment gave. It claimed the
    NUL bytes make git call the file binary and route it to the blob path; that
    holds only when the NULs fall inside git's first-8000-byte window, so a file
    with clean ASCII first and utf-16 later is TEXT and does arrive here.

    The actual protection is that those NUL bytes are ASCII, so the line takes
    the fast path below and _strip_invisible removes them as category Cc, leaving
    the identifier contiguous. Verified for utf-16-be, utf-16-le and utf-32-be.
    Recorded precisely because the two rationales fail differently: if the Cc
    strip is ever narrowed, this opens silently.
    """
    # The common case by an enormous margin, and identical to the old behaviour:
    # one reading, no extra work.
    #
    # This is the ONLY gate, and it is exact rather than a threshold. Every
    # letter and digit encodes to a byte >= 0x80 in all four EBCDIC codecs
    # (asserted by test_every_ebcdic_alphanumeric_is_a_high_byte), and every rule
    # this scanner has needs at least one letter or digit to match. So an ASCII
    # line cannot hide an EBCDIC identifier, and skipping the extra readings for
    # it narrows cost only.
    #
    # An earlier version gated on a byte in 0xF0-0xF9 — EBCDIC's digits — which
    # was a REAL BYPASS, caught in QA review: it reasoned from account IDs, which
    # need twelve digits, and generalised to identifiers that need none. A PEM
    # header has no digits at all, and an access key need not have any, so both
    # scanned clean in cp500 through --staged-diff while --files caught them. Two
    # modes disagreeing about the same question is the shape of nearly every bug
    # ever found in this file.
    if data.isascii():
        return (data.decode("ascii"),)

    out: list[str] = []

    def add(text: str | None) -> None:
        if text is not None and text not in out:
            out.append(text)

    strict = _decode(data, "utf-8")
    add(strict)
    if strict is None:
        # Only reachable for a line that is not valid UTF-8, which is exactly
        # when the two disagree — see the lossy-reading note in
        # _decode_candidates for why dropping bytes finds what preserving them
        # cannot. Withheld from pathnames; see this function's docstring.
        if allow_lossy:
            add(data.decode("utf-8", errors="ignore"))
        # LOAD-BEARING, and not for the reason first supposed. An earlier comment
        # here reasoned that dropping bytes can never swallow a character of an
        # ASCII identifier — true, and beside the point. Dropping does not need
        # to swallow the identifier to destroy the match; it only needs to JOIN
        # it to what sits next to it:
        #
        #   "9" \xff <12-digit id>  -> dropped: a 13-digit run, and RE_TWELVE is
        #                              anchored (?<!\d)...(?!\d), so it misses.
        #   "keyX" \xff <access key> -> dropped: the (?<![0-9A-Za-z]) lookbehind
        #                              now sees 'X', so aws-unique-id misses.
        #
        # latin-1 preserves the byte as a character, which keeps the boundary
        # intact and matches both. The two readings fail in opposite directions,
        # which is exactly why both are here. Pinned by
        # test_byte_dropping_can_fuse_an_identifier_and_latin_1_catches_it.
        add(data.decode("latin-1"))
    # ALL FOUR EBCDIC codecs, matching _decode_candidates exactly.
    #
    # An earlier version decoded only cp037, on the argument that the four agree
    # on every character an identifier can be built from — which is true, and
    # insufficient. Detection is not the only thing a reading decides: it also
    # decides EXEMPTION. The codecs disagree on punctuation (cp500 on 5
    # characters, cp1026 on 14), and some of those characters are exactly the
    # ones that make a bucket capture read as a placeholder rather than a name.
    #
    # Byte 0xBA is '[' in cp037 and '¬' in cp500. A bucket segment beginning with
    # it reads as '[realbucketname' under cp037 — a PLACEHOLDER_BUCKET_STARTS
    # prefix, so exempt — and as '¬realbucketname' under cp500, which is a hit.
    # Keeping only the exempting reading loses the finding outright. Twelve more
    # such bytes exist across the family, some truncating a capture at a
    # terminator instead. Verified: rc 0 through --staged-diff, rc 1 through
    # --files, which is the two-modes-disagree shape again.
    #
    # No realistic bucket name can begin with those characters, so this was not a
    # demonstrated disclosure — but the invariant is load-bearing for any future
    # rule, and three extra decodes on non-ASCII lines only is a small price for
    # not having to re-derive it. The isascii() fast path above carries the whole
    # perf argument on its own.
    for encoding, kind in CANDIDATE_ENCODINGS:
        if kind == "ebcdic":
            add(_decode(data, encoding))
    return tuple(out)


def iter_staged_diff_lines():
    """
    Yield (path, lineno, content) for lines ADDED in the staged diff.

    Header detection is POSITIONAL, not content-based: a '--- ' or '+++ ' line
    is a header only when we are not inside a hunk.

    The previous guard honoured '+++ ' whenever the preceding line began '--- ',
    "which is how git always emits it". That is true of headers and also
    reproducible by CONTENT: a removed line whose text starts '-- ' renders as
    '--- ', and an added line whose text starts '++ ' renders as '+++ '. Put
    those adjacent and the added line is consumed as a header and never
    scanned. Verified to drop account IDs, bucket URIs, access-key IDs and PEM
    headers alike — including the two rules `allow-identifier` cannot waive —
    through --staged-diff, which is the only mode the pre-commit hook calls.

    Position is unambiguous where content is not. Inside a hunk every line
    carries a +/-/space/backslash prefix, so a bare '@@' or 'diff --git ' can
    only be structure; outside a hunk there is no content to confuse.

    THE DIFF IS PARSED AS LATIN-1, NOT UTF-8. This used to go through _git_text,
    which decodes with errors="replace", and that single reading was the whole
    of two separate holes:

      * A file in an EBCDIC encoding (cp037/cp500/cp1026/cp424) contains no NUL
        byte, so git classifies it as TEXT and it arrives here rather than at the
        blob path — the only place that reads a file more than one way. Its
        digits, bytes 0xF0-0xF9, became U+FFFD and no rule matched. bugs/1 is
        worth correcting on this point: it concluded that adding cp500 to
        CANDIDATE_ENCODINGS "would change nothing" because the gap is the code
        path. The code path is a gap, but the encodings were missing too — the
        candidate union produced exactly one surviving reading for a cp500 blob
        (latin-1) and it missed. Both had to change.
      * One invalid byte inside a digit run became U+FFFD and split it, while
        numstat still reported an ordinary '1\\t0' row, so the undiffed-file
        fallback that exists to catch a file the diff cannot show never fired.

    latin-1 is a 1:1 byte mapping, so decoding here loses nothing and each added
    line can be handed back to _line_readings as its original bytes. git's own
    framing — 'diff --git ', '+++ ', '@@', the +/- prefixes — is ASCII, so it
    survives this reading intact; content that is not ASCII is not framing.

    The displayed PATH is decoded as utf-8 separately, since latin-1 would render
    a non-ASCII pathname as mojibake in the block message.
    """
    out = _git(
        ["diff", "--cached", "--unified=0", "--no-color", *NO_CUSTOM_DIFF],
        "the staged diff",
    ).decode("latin-1")

    path, lineno, in_hunk = None, 0, False
    for raw in split_lines(out):
        # Starts a new file's header block, and ends any hunk in progress.
        if raw.startswith("diff --git "):
            in_hunk = False
            continue
        if not in_hunk:
            if raw.startswith("+++ "):
                # Un-quote FIRST: with core.quotePath on, the 'b/' prefix sits
                # inside the quotes, so testing for it on the quoted string
                # never matched and the prefix was reported as part of the name.
                target = _unquote_c_path(raw[4:])
                if target.startswith(b"b/"):
                    target = target[2:]
                path = target.decode("utf-8", errors="replace")
                continue
            if raw.startswith("--- "):
                continue
        if raw.startswith("@@"):
            m = re.match(r"^@@ -[0-9,]+ \+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
            in_hunk = True
            continue
        if raw.startswith("+"):
            # One line number per LINE, not per reading.
            for content in _line_readings(raw[1:].encode("latin-1")):
                yield path, lineno, content
            lineno += 1


def iter_staged_paths():
    """
    Yield (path, None, path) for every staged pathname.

    Deletions are excluded (--diff-filter=ACMRT): that path is already in
    history, and refusing the commit that removes it helps nobody. For a rename
    only the new name is checked, for the same reason.

    READ AS BYTES, for the same reason iter_staged_diff_lines is. A pathname is a
    publication sink exactly as a file body is — that is why this iterator
    exists — but the invalid-byte and EBCDIC fixes originally landed only in the
    content iterator, leaving this one on a single utf-8/replace reading. With
    `--name-only -z` git does no C-quoting, so raw bytes arrived here and one
    undecodable byte inside a digit run mangled the name into U+FFFD and split
    it. Verified rc 0 for `aws-cloudtrail-logs-9876543\\xff21098-us-east-2.md`
    and for an access key split the same way, while both block without the byte.

    macOS refuses to CREATE such a filename, but the git index accepts it, so it
    arrives via a Linux-authored branch, a cherry-pick, `git apply`, or a crafted
    index — and this scanner is installed in repos that see CI.

    The display name keeps its own utf-8/replace decode: it is what gets printed,
    and it is what redact() then masks.
    """
    out = _git(
    # T (typechange) was missing until 2026-08-12, and its absence hid a file
    # from EVERY iterator at once. A path that flips blob type — symlink to
    # regular file — and whose new content yields no diff text (binary, or
    # `-diff` in .gitattributes) produced no '+' lines here AND no "-\t-"
    # numstat row, so the undiffed-file fallback that exists to catch exactly
    # that case never fired. Silent rc 0, defeating both the content scan and
    # the unscannable fail-closed report. Pre-existing on master.
        ["diff", "--cached", "--name-only", "--diff-filter=ACMRT", "-z", *NO_CUSTOM_DIFF],
        "the staged path list",
    )
    for raw in out.split(b"\0"):
        if raw:
            # Display is decoded ONCE, here, from the true bytes. Every
            # printed path goes through redact() in main(), and redact() can
            # only reason about the artifacts this one transform produces —
            # which is why the diff header is un-quoted to bytes first rather
            # than printed in git's C-quoted form. See _unquote_c_path.
            shown = raw.decode("utf-8", errors="replace")
            for reading in _line_readings(raw, allow_lossy=False):
                yield shown, None, reading


def _staged_numstat():
    """
    Yield (added, deleted, path) for staged changes.

    Uses -z, so pathnames are emitted verbatim rather than C-quoted. In that
    format a normal record is "<add>\\t<del>\\t<path>\\0", while a rename or copy
    is "<add>\\t<del>\\t\\0<preimage>\\0<postimage>\\0" — the trailing empty
    field after the second tab is what marks it.
    """
    out = _git_text(
        ["diff", "--cached", "--numstat", "--diff-filter=ACMRT", "-z", *NO_CUSTOM_DIFF],
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
        # THE THIRD DISPLAY ROUTE, and the one that broke the claim that there is
        # only one. The git-sourced iterators were normalised to decode a path
        # exactly once, utf-8/replace, so redact()'s U+FFFD handling covers them.
        # An argv path never went through that: CPython decodes sys.argv with
        # surrogateescape, so an undecodable byte arrives as a LONE SURROGATE
        # (U+DCFF), stderr renders it as a backslash escape, and the digit run is
        # split by something redact() has never heard of. Verified: `--files` on
        # a name holding one \xff printed twelve digits of an account ID, while
        # the same name without the byte masked correctly.
        #
        # Re-encoding through surrogateescape recovers the original bytes, and
        # decoding them utf-8/replace puts this route on the same single
        # transform as the other two. Normalising the route, not extending the
        # strip — the alternative is a list where a category is needed, which is
        # how the C-quoted form was missed one round earlier.
        #
        # `p` itself is still what gets opened: only the DISPLAY is normalised.
        shown = p.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            unscannable.append(shown)
            continue
        yield from _iter_decoded_lines(shown, data, unscannable)


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
    # Normalised for the same reason as iter_file_lines: --label is argv too, so
    # it reaches here with surrogates rather than U+FFFD. The pre-commit hook
    # passes a fixed ASCII label, which is why this has never mattered — but the
    # route is what is being guaranteed, not the current caller's good behaviour.
    label = label.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    for n, line in enumerate(split_lines(sys.stdin.read()), 1):
        yield label, n, line


# --- reporting ---------------------------------------------------------------

BLOCK_HEADER = {
    "diff": "BLOCKED — staged changes introduce cloud identifiers.",
    "files": "BLOCKED — these documents contain cloud identifiers.",
    "stdin": "BLOCKED — this text contains cloud identifiers.",
}


def _report_hits(hits, allow_marker_usable: bool = True) -> None:
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
    if allow_marker_usable:
        print("  If a line is genuinely fine — a real UUID whose tail is 12 digits, or a", file=e)
        print(f"  non-AWS 12-digit number — append '{ALLOW_MARKER}' to that line.", file=e)
    else:
        # Saying "append the marker" here would be advice that does not work, and
        # worse, advice whose only effect is to put the marker NEXT TO the
        # identifier in the published text. Name the real remedy instead.
        print(f"  '{ALLOW_MARKER}' does NOT apply here (--no-allow-marker): this text is", file=e)
        print("  itself the published artifact, so a marker would ship alongside the", file=e)
        print("  identifier rather than excusing it. Edit the text.", file=e)
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
    # A name is withheld when the name ITSELF could reassemble into an
    # identifier. That is the safe error, but it leaves this list unactionable
    # for exactly the file the reader has to go and look at — so point at the
    # one command that will name it without this control being the thing that
    # prints it.
    if any(redact(p) == FULLY_REDACTED for p in paths):
        print("", file=e)
        print(f"  A path shown as {FULLY_REDACTED} was withheld because the NAME", file=e)
        print("  itself may carry an identifier. List them yourself with:", file=e)
        print("    git diff --cached --name-only", file=e)


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
    # The allow-marker is a per-line escape hatch a human types beside one
    # specific false positive in a FILE, where the marker is a note to the next
    # reader and the file can be edited afterwards. Neither holds for a commit
    # message: it is pushed verbatim, cannot be corrected without rewriting
    # history, and the marker would be published in the same breath as the
    # identifier it excused. `git commit -m "... 9876...  allow-identifier"`
    # therefore committed clean — the escape hatch disarming the control in the
    # one sink that has no undo. Same shape as the pathname case, which is why
    # honor_allow_marker already existed; this exposes it to callers.
    ap.add_argument("--no-allow-marker", action="store_true",
                    help="Ignore the per-line allow-identifier marker entirely.")
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
        honor = not is_pathname and not args.no_allow_marker
        rule = scan_line(content, honor_allow_marker=honor)
        if rule:
            shown = redact(path or "<unknown>")
            location = f"{shown} (pathname)" if is_pathname else f"{shown}:{lineno}"
            if (location, rule) not in seen_hits:
                seen_hits.add((location, rule))
                hits.append((location, rule))

    if hits:
        print(f"scan-identifiers: {BLOCK_HEADER[kind]}", file=sys.stderr)
        _report_hits(hits, allow_marker_usable=not args.no_allow_marker)
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
