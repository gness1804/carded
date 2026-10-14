#!/usr/bin/env python3
"""Turn a business-card photo into a .vcf file from the command line.

Runs the same local pipeline as the web app -- ``extract_card_from_bytes()``
from ``main.py`` and ``build_vcf()`` from ``vcard_builder.py`` -- without
starting the server or touching session cookies.

The Anthropic API key is read from the repo's ``.env``
(``OWNER_ANTHROPIC_API_KEY``), falling back to an ``ANTHROPIC_API_KEY``
environment variable. The key is never printed or logged.

Usage::

    python3 scripts/card_to_vcf.py path/to/card.heic
    python3 scripts/card_to_vcf.py card.jpg --out-dir ~/Downloads
    python3 scripts/card_to_vcf.py card.jpg --json

Exit codes:
    0  success -- .vcf written
    1  configuration or file error (no API key, bad path, too large, I/O)
    2  command-line usage error (argparse)
    3  image is not a business card
    4  business card is illegible
    5  unsupported or unreadable image format
    6  extraction failed (timeout or upstream error)
  130  interrupted (Ctrl-C)
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_USAGE = 2  # argparse's own exit code for bad arguments
EXIT_NOT_A_CARD = 3
EXIT_ILLEGIBLE = 4
EXIT_UNSUPPORTED = 5
EXIT_EXTRACTION_FAILED = 6
EXIT_INTERRUPTED = 130  # conventional 128 + SIGINT

KEY_NAMES = ("OWNER_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")
DEFAULT_MAX_FILE_SIZE_MB = 10.0
MAX_ALLOWED_FILE_SIZE_MB = 1024.0  # hard ceiling; card photos are ~1-10 MB
MAX_NAME_ATTEMPTS = 1000


class ConfigError(Exception):
    """Raised for user-fixable setup problems (missing key, bad path)."""


def load_api_key(env_file: Path) -> str:
    """Return the Anthropic API key without mutating ``os.environ``.

    Order: ``.env`` OWNER_ANTHROPIC_API_KEY, ``.env`` ANTHROPIC_API_KEY,
    then the same two names from the process environment.
    """
    from dotenv import dotenv_values

    file_values = dotenv_values(env_file) if env_file.is_file() else {}
    for source in (file_values, os.environ):
        for name in KEY_NAMES:
            value = (source.get(name) or "").strip()
            if value:
                return value
    raise ConfigError(
        f"No Anthropic API key found. Set OWNER_ANTHROPIC_API_KEY in "
        f"{env_file} or export ANTHROPIC_API_KEY."
    )


def max_file_size_bytes(env_file: Path) -> int:
    """Read MAX_FILE_SIZE_MB from .env/environment, defaulting to 10 MB.

    Non-numeric, non-finite (inf/nan), zero, or negative values fall back
    to the default rather than crashing or disabling the limit. Values
    above ``MAX_ALLOWED_FILE_SIZE_MB`` are capped (a huge finite value
    like 1e308 would otherwise overflow when converted to bytes).
    """
    from dotenv import dotenv_values

    file_values = dotenv_values(env_file) if env_file.is_file() else {}
    raw = file_values.get("MAX_FILE_SIZE_MB") or os.environ.get(
        "MAX_FILE_SIZE_MB"
    )
    try:
        mb = float(raw) if raw else DEFAULT_MAX_FILE_SIZE_MB
    except (ValueError, OverflowError):
        mb = DEFAULT_MAX_FILE_SIZE_MB
    if not math.isfinite(mb) or mb <= 0:
        mb = DEFAULT_MAX_FILE_SIZE_MB
    mb = min(mb, MAX_ALLOWED_FILE_SIZE_MB)
    return int(mb * 1024 * 1024)


def write_new_file(directory: Path, filename: str, content: str) -> Path:
    """Create a brand-new file in ``directory`` and write ``content`` to it.

    Never overwrites, and never follows a symlink at the target filename:
    ``O_CREAT | O_EXCL`` fails if anything (file, directory, or symlink,
    even a dangling one) already exists at the path, so there is no
    check-then-open race. ``directory`` itself is used as given (a
    symlinked directory is followed). On collision, tries ``name-2.vcf``,
    ``name-3.vcf``, ... If the write fails part-way (e.g. disk full), the
    partial file is removed before the error propagates.
    """
    stem, suffix = os.path.splitext(filename)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for attempt in range(1, MAX_NAME_ATTEMPTS + 1):
        path = directory / (
            filename if attempt == 1 else f"{stem}-{attempt}{suffix}"
        )
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            continue
        try:
            # newline="" keeps the CRLF line endings vCard 3.0 requires.
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)
        except BaseException:
            # We created this path ourselves (O_EXCL), so removing it
            # cannot clobber anything that existed before.
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        return path
    raise FileExistsError(
        f"No free filename for {filename} after {MAX_NAME_ATTEMPTS} tries"
    )


def read_capped(path: Path, limit: int) -> bytes:
    """Read at most ``limit`` bytes; raise ConfigError if the file is larger.

    Reads ``limit + 1`` bytes so a file that grew after an earlier size
    check is still caught, without ever loading more than the cap.
    """
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ConfigError(f"Image is larger than {limit / (1024 * 1024):g} MB.")
    return data


#: Format characters (Unicode category Cf) that legitimate names need:
#: ZWNJ (U+200C) and ZWJ (U+200D) are used in Persian/Indic scripts and emoji
#: sequences. Every other non-printable character -- C0/C1 controls (ESC,
#: BEL), bidi overrides (U+202A-U+202E, U+2066-U+2069), etc. -- stays blocked.
_TERMINAL_ALLOWED_FORMAT_CHARS = frozenset("\u200c\u200d")


def terminal_safe(text: str) -> str:
    """Neutralize control characters before printing LLM-derived text.

    Card text is attacker-controllable (prompt injection via the image), so
    an extracted field could carry ANSI/OSC escape sequences -- e.g. OSC 52
    to write the clipboard, or OSC 8 to plant a disguised hyperlink. Every
    non-printable character except the newlines we insert ourselves (and
    the joiners in ``_TERMINAL_ALLOWED_FORMAT_CHARS``) is replaced with
    U+FFFD, so the sequence is visible but inert. Newlines *inside* field
    values are flattened earlier, by :func:`summarize`.
    """
    return "\n".join(
        "".join(
            ch if ch.isprintable() or ch in _TERMINAL_ALLOWED_FORMAT_CHARS
            else "\ufffd"
            for ch in line
        )
        for line in text.split("\n")
    )


def _one_display_line(value: Any) -> str:
    """Collapse any line break in a field value to a visible ``⏎`` marker.

    Without this, a card field like ``"X\\n  Email (work): evil@example"``
    would print as two lines and fake an extra field in the summary.
    ``str.splitlines`` honours every Unicode line-break variant.
    """
    return " \u23ce ".join(str(value).splitlines())


def summarize(card: dict[str, Any]) -> list[str]:
    """Human-readable lines describing the extracted fields.

    Each field is guaranteed to occupy exactly one output line.
    """
    lines: list[str] = []

    def add(label: str, value: Any) -> None:
        if value:
            lines.append(f"{label}: {_one_display_line(value)}")

    add("Name", card.get("full_name"))
    add("Title", card.get("title"))
    add("Organization", card.get("organization"))
    add("Department", card.get("department"))
    for phone in card.get("phones") or []:
        add(f"Phone ({(phone.get('type') or 'work').lower()})",
            phone.get("number"))
    for email in card.get("emails") or []:
        add(f"Email ({(email.get('type') or 'work').lower()})",
            email.get("address"))
    for url in card.get("urls") or []:
        add("URL", url)
    address = card.get("address") or {}
    if address:
        parts = [
            address.get(k)
            for k in ("street", "street2", "city", "state",
                      "postal_code", "country")
        ]
        add("Address", ", ".join(p for p in parts if p))
    for social in ("linkedin", "twitter", "instagram"):
        add(social.capitalize(), card.get(social))
    add("Note", card.get("note"))
    return lines


def configure_baml_logging(verbose: bool) -> None:
    """Quiet BAML's prompt/response log unless --verbose.

    BAML logs the full prompt and LLM reply at INFO on success, and again
    at WARN when a call fails -- either way every extracted field (and on
    failure the HTTP error body) lands on stderr. So the quiet level is
    ``error``, not ``warn`` (verified live: ``warn`` still dumped the prompt
    on a 401). Without --verbose this is forced even if the shell already
    sets BAML_LOG, so a stray ``BAML_LOG=info`` cannot leak card data. Must
    run before ``baml_client`` is imported.
    """
    if verbose:
        os.environ.setdefault("BAML_LOG", "info")
    else:
        os.environ["BAML_LOG"] = "error"


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract a business card photo into a .vcf file."
    )
    parser.add_argument("image", type=Path, help="Path to the card image")
    parser.add_argument(
        "--out-dir", type=Path, default=Path.cwd(),
        help="Directory to write the .vcf into (default: current directory)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print a JSON result (path + fields) instead of plain text",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Show BAML's prompt/response log and full error tracebacks "
             "(may contain card data)",
    )
    parser.add_argument(
        "--env-file", type=Path, default=REPO_ROOT / ".env",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)

    configure_baml_logging(args.verbose)

    def emit(status: str, message: str, **extra: Any) -> None:
        if args.json:
            # json.dumps escapes every control character, so this is safe.
            print(json.dumps({"status": status, "message": message, **extra}))
        else:
            stream = sys.stdout if status == "ok" else sys.stderr
            print(terminal_safe(message), file=stream)

    try:
        image_path = args.image.expanduser()
        if not image_path.is_file():
            raise ConfigError(f"Image not found: {image_path}")
        out_dir = args.out_dir.expanduser()
        if not out_dir.is_dir():
            raise ConfigError(f"Output directory not found: {out_dir}")
        limit = max_file_size_bytes(args.env_file)
        if image_path.stat().st_size > limit:
            raise ConfigError(
                f"Image is larger than {limit / (1024 * 1024):g} MB."
            )
        api_key = load_api_key(args.env_file)
        # Capped read: a file that grew after the stat() above is still
        # rejected, and never more than limit + 1 bytes is loaded.
        image_data = read_capped(image_path, limit)
    except ConfigError as exc:
        emit("config_error", str(exc))
        return EXIT_CONFIG
    except OSError as exc:
        emit("config_error", f"Could not read input: {type(exc).__name__}: "
             f"{exc.strerror or exc}")
        return EXIT_CONFIG

    # Imported late so --help and config errors skip BAML start-up cost, and
    # so BAML_LOG (set above) is in place before baml_client first loads.
    from main import (
        ExtractionError, ExtractionTimeout, Illegible, NotABusinessCard,
        UnsupportedMimeType, Valid, _sniff_image_mime, extract_card_from_bytes,
    )
    from vcard_builder import build_vcf, vcf_filename

    # main.py re-sniffs the bytes itself; the declared type only has to be
    # on the allowlist, so pass the sniffed one (or a value that will fail).
    mime = _sniff_image_mime(image_data) or "application/octet-stream"

    # main.py calls logger.exception() on BAML failures. With no handler
    # configured, Python's last-resort handler prints the full traceback to
    # stderr, and an upstream exception message could carry request details.
    # Silence that logger unless --verbose; we print a clean message instead.
    main_logger = logging.getLogger("main")
    previously_disabled = main_logger.disabled
    main_logger.disabled = not args.verbose
    try:
        result = extract_card_from_bytes(
            image_data, mime, api_key, filename=image_path.name
        )
    except UnsupportedMimeType:
        emit("unsupported", "Unsupported or unreadable image. "
             "Use JPEG, PNG, WebP, or HEIC.")
        return EXIT_UNSUPPORTED
    except ExtractionTimeout:
        emit("extraction_failed", "Extraction timed out. Try again.")
        return EXIT_EXTRACTION_FAILED
    except ExtractionError as exc:
        # ExtractionError messages carry only the underlying type name.
        emit("extraction_failed", f"Extraction failed: {exc}")
        return EXIT_EXTRACTION_FAILED
    except Exception as exc:  # noqa: BLE001 -- deliberate catch-all
        # Anything main.py doesn't wrap: a truncated HEIC failing in
        # Pillow, a non-numeric EXTRACTION_TIMEOUT_SECONDS, etc. Report the
        # type name only -- the message could carry request details.
        if args.verbose:
            raise
        emit("extraction_failed",
             f"Extraction failed: {type(exc).__name__} "
             "(re-run with --verbose for details)")
        return EXIT_EXTRACTION_FAILED
    finally:
        main_logger.disabled = previously_disabled

    # result.message is LLM output: flatten it so it can't fake extra lines.
    if isinstance(result, NotABusinessCard):
        emit("not_a_card",
             f"Not a business card: {_one_display_line(result.message)}")
        return EXIT_NOT_A_CARD
    if isinstance(result, Illegible):
        emit("illegible",
             f"Card is illegible: {_one_display_line(result.message)}")
        return EXIT_ILLEGIBLE
    if not isinstance(result, Valid):
        emit("extraction_failed",
             f"Unexpected extraction result: {type(result).__name__}")
        return EXIT_EXTRACTION_FAILED

    card = result.card.model_dump()
    try:
        filename = vcf_filename(card)
        vcf_text = build_vcf(card)
    except Exception as exc:  # noqa: BLE001 -- deliberate catch-all
        if args.verbose:
            raise
        emit("extraction_failed",
             f"Could not build vCard: {type(exc).__name__} "
             "(re-run with --verbose for details)")
        return EXIT_EXTRACTION_FAILED
    try:
        vcf_path = write_new_file(out_dir, filename, vcf_text)
    except OSError as exc:
        emit("config_error", f"Could not write vCard: {type(exc).__name__}: "
             f"{exc.strerror or exc}")
        return EXIT_CONFIG

    fields = summarize(card)
    if args.json:
        emit("ok", "vCard written", path=str(vcf_path), fields=fields)
    else:
        emit("ok", f"Wrote {vcf_path}\n" + "\n".join(f"  {f}" for f in fields))
    return EXIT_OK


def cli_main() -> int:
    """Entry point: like :func:`run`, but Ctrl-C exits quietly with 130.

    Named ``cli_main`` (not ``main``) to avoid confusion with the repo's
    ``main`` module, which run() imports.

    Without this, KeyboardInterrupt (not an Exception subclass, so the
    catch-alls in run() don't see it) prints a raw traceback.
    """
    try:
        return run()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(cli_main())
