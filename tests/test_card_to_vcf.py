"""Unit tests for scripts/card_to_vcf.py.

The BAML client is mocked at the unit level (``main.b``), matching
tests/test_main.py, so these tests make no network calls.
"""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import card_to_vcf  # noqa: E402
from tests.test_main import (  # noqa: E402
    TINY_JPEG,
    _make_illegible,
    _make_not_a_card,
    _make_valid_card,
)

FAKE_KEY = "sk-ant-test-not-a-real-key-0000"

integration = pytest.mark.skipif(
    not os.getenv("RUN_INTEGRATION_TESTS"),
    reason="Set RUN_INTEGRATION_TESTS=1 to run live LLM tests",
)


def _mock_b(card):
    mock_b = MagicMock()
    mock_b.with_options.return_value.ExtractBusinessCard.return_value = card
    return mock_b


@pytest.fixture
def env_file(tmp_path):
    path = tmp_path / ".env"
    path.write_text(f"OWNER_ANTHROPIC_API_KEY={FAKE_KEY}\n")
    return path


@pytest.fixture
def image(tmp_path):
    path = tmp_path / "card.jpg"
    path.write_bytes(TINY_JPEG)
    return path


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in card_to_vcf.KEY_NAMES + ("MAX_FILE_SIZE_MB",):
        monkeypatch.delenv(name, raising=False)


def _run(image, out_dir, env_file, *extra):
    return card_to_vcf.run(
        [str(image), "--out-dir", str(out_dir),
         "--env-file", str(env_file), *extra]
    )


# ── API key loading ─────────────────────────────────────────────────────────


def test_load_api_key_prefers_owner_key_from_env_file(env_file):
    assert card_to_vcf.load_api_key(env_file) == FAKE_KEY


def test_load_api_key_falls_back_to_process_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-env")
    assert card_to_vcf.load_api_key(tmp_path / "missing.env") == "from-env"


def test_load_api_key_does_not_mutate_os_environ(env_file):
    card_to_vcf.load_api_key(env_file)
    assert "OWNER_ANTHROPIC_API_KEY" not in os.environ


def test_missing_key_exits_config_error(tmp_path, image, capsys):
    empty = tmp_path / "empty.env"
    empty.write_text("")
    assert _run(image, tmp_path, empty) == card_to_vcf.EXIT_CONFIG
    assert "No Anthropic API key" in capsys.readouterr().err


# ── Happy path ──────────────────────────────────────────────────────────────


def test_valid_card_writes_vcf_with_crlf(tmp_path, image, env_file, capsys):
    with patch("main.b", _mock_b(_make_valid_card())):
        code = _run(image, tmp_path, env_file)
    assert code == card_to_vcf.EXIT_OK
    vcf = (tmp_path / "park-jamie.vcf").read_bytes()
    assert vcf.startswith(b"BEGIN:VCARD\r\nVERSION:3.0\r\n")
    assert b"FN:Jamie Park\r\n" in vcf
    assert b"\r\r\n" not in vcf
    out = capsys.readouterr().out
    assert "Name: Jamie Park" in out
    assert "Organization: Helio Studio" in out


def test_api_key_is_passed_to_baml_but_never_printed(
    tmp_path, image, env_file, capsys
):
    mock_b = _mock_b(_make_valid_card())
    with patch("main.b", mock_b):
        _run(image, tmp_path, env_file, "--json")
    mock_b.with_options.assert_called_once_with(
        env={"ANTHROPIC_API_KEY": FAKE_KEY}
    )
    captured = capsys.readouterr()
    assert FAKE_KEY not in captured.out + captured.err


def test_existing_file_is_not_overwritten(tmp_path, image, env_file):
    (tmp_path / "park-jamie.vcf").write_text("keep me")
    with patch("main.b", _mock_b(_make_valid_card())):
        _run(image, tmp_path, env_file)
    assert (tmp_path / "park-jamie.vcf").read_text() == "keep me"
    assert (tmp_path / "park-jamie-2.vcf").exists()


def test_json_output_shape(tmp_path, image, env_file, capsys):
    with patch("main.b", _mock_b(_make_valid_card())):
        _run(image, tmp_path, env_file, "--json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["path"].endswith("park-jamie.vcf")
    assert "Name: Jamie Park" in payload["fields"]


# ── Failure branches ────────────────────────────────────────────────────────


def test_not_a_card(tmp_path, image, env_file):
    with patch("main.b", _mock_b(_make_not_a_card())):
        assert _run(image, tmp_path, env_file) == card_to_vcf.EXIT_NOT_A_CARD
    assert not list(tmp_path.glob("*.vcf"))


def test_illegible(tmp_path, image, env_file):
    with patch("main.b", _mock_b(_make_illegible())):
        assert _run(image, tmp_path, env_file) == card_to_vcf.EXIT_ILLEGIBLE


def test_non_image_file_is_unsupported(tmp_path, env_file):
    bogus = tmp_path / "notes.jpg"
    bogus.write_bytes(b"this is plain text, not an image")
    assert _run(bogus, tmp_path, env_file) == card_to_vcf.EXIT_UNSUPPORTED


def test_baml_error_maps_to_extraction_failed(tmp_path, image, env_file):
    mock_b = MagicMock()
    mock_b.with_options.return_value.ExtractBusinessCard.side_effect = (
        RuntimeError("boom")
    )
    with patch("main.b", mock_b):
        code = _run(image, tmp_path, env_file)
    assert code == card_to_vcf.EXIT_EXTRACTION_FAILED


def test_missing_image_is_config_error(tmp_path, env_file):
    code = _run(tmp_path / "nope.jpg", tmp_path, env_file)
    assert code == card_to_vcf.EXIT_CONFIG


def test_oversized_image_is_rejected(tmp_path, image, env_file):
    env_file.write_text(
        f"OWNER_ANTHROPIC_API_KEY={FAKE_KEY}\nMAX_FILE_SIZE_MB=0.0001\n"
    )
    assert _run(image, tmp_path, env_file) == card_to_vcf.EXIT_CONFIG


@pytest.mark.parametrize("raw", ["inf", "-inf", "nan", "0", "-5", "abc",
                                 "1e400"])
def test_bad_max_file_size_falls_back_to_default(tmp_path, raw):
    env = tmp_path / ".env"
    env.write_text(f"MAX_FILE_SIZE_MB={raw}\n")
    assert card_to_vcf.max_file_size_bytes(env) == 10 * 1024 * 1024


# ── Key precedence (QA finding: untested paths) ─────────────────────────────


def test_env_file_key_beats_process_env_key(env_file, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-process-env")
    assert card_to_vcf.load_api_key(env_file) == FAKE_KEY


def test_process_env_key_used_when_env_file_has_none(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("SESSION_SECRET=x\n")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-process-env")
    assert card_to_vcf.load_api_key(env) == "from-process-env"


# ── Exit codes (QA finding: usage error collided with not-a-card) ───────────


def test_usage_error_exit_code_is_distinct(capsys):
    with pytest.raises(SystemExit) as excinfo:
        card_to_vcf.run(["--no-such-flag"])
    assert excinfo.value.code == card_to_vcf.EXIT_USAGE
    codes = [card_to_vcf.EXIT_OK, card_to_vcf.EXIT_CONFIG,
             card_to_vcf.EXIT_USAGE, card_to_vcf.EXIT_NOT_A_CARD,
             card_to_vcf.EXIT_ILLEGIBLE, card_to_vcf.EXIT_UNSUPPORTED,
             card_to_vcf.EXIT_EXTRACTION_FAILED]
    assert len(set(codes)) == len(codes)


def test_timeout_maps_to_extraction_failed(tmp_path, image, env_file):
    from main import ExtractionTimeout

    with patch("main._call_baml", side_effect=ExtractionTimeout("slow")):
        code = _run(image, tmp_path, env_file)
    assert code == card_to_vcf.EXIT_EXTRACTION_FAILED


# ── Secret hygiene (QA finding: traceback could leak the key) ───────────────


def test_baml_error_traceback_is_suppressed(tmp_path, image, env_file,
                                            capsys, caplog):
    mock_b = MagicMock()
    mock_b.with_options.return_value.ExtractBusinessCard.side_effect = (
        RuntimeError(f"upstream said: bad key {FAKE_KEY}")
    )
    with caplog.at_level("DEBUG"), patch("main.b", mock_b):
        code = _run(image, tmp_path, env_file)
    assert code == card_to_vcf.EXIT_EXTRACTION_FAILED
    captured = capsys.readouterr()
    assert FAKE_KEY not in captured.out + captured.err
    assert not [r for r in caplog.records if r.name == "main"]
    assert FAKE_KEY not in caplog.text
    # The logger is re-enabled afterwards so the web app is unaffected.
    import logging
    assert logging.getLogger("main").disabled is False


def test_verbose_keeps_traceback_logging(tmp_path, image, env_file, caplog):
    mock_b = MagicMock()
    mock_b.with_options.return_value.ExtractBusinessCard.side_effect = (
        RuntimeError("boom")
    )
    with caplog.at_level("DEBUG"), patch("main.b", mock_b):
        _run(image, tmp_path, env_file, "--verbose")
    assert [r for r in caplog.records if r.name == "main"]


# ── File writes (QA finding: symlink follow + TOCTOU) ───────────────────────


def test_dangling_symlink_is_not_followed(tmp_path, image, env_file):
    out = tmp_path / "out"
    out.mkdir()
    target = tmp_path / "victim.txt"
    (out / "park-jamie.vcf").symlink_to(target)
    with patch("main.b", _mock_b(_make_valid_card())):
        assert _run(image, out, env_file) == card_to_vcf.EXIT_OK
    assert not target.exists()
    assert (out / "park-jamie-2.vcf").is_file()


def test_write_new_file_is_owner_only(tmp_path):
    path = card_to_vcf.write_new_file(tmp_path, "a.vcf", "x")
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permissions")
def test_unwritable_out_dir_is_config_error(tmp_path, image, env_file,
                                            capsys):
    out = tmp_path / "ro"
    out.mkdir()
    out.chmod(0o500)
    try:
        with patch("main.b", _mock_b(_make_valid_card())):
            code = _run(image, out, env_file)
    finally:
        out.chmod(0o700)
    assert code == card_to_vcf.EXIT_CONFIG
    assert "Could not write vCard" in capsys.readouterr().err


# ── Second-review fixes ─────────────────────────────────────────────────────


@pytest.mark.parametrize("raw", ["1e308", "1e300", "99999999"])
def test_huge_max_file_size_is_capped_not_crashing(tmp_path, raw):
    env = tmp_path / ".env"
    env.write_text(f"MAX_FILE_SIZE_MB={raw}\n")
    expected = int(card_to_vcf.MAX_ALLOWED_FILE_SIZE_MB * 1024 * 1024)
    assert card_to_vcf.max_file_size_bytes(env) == expected


def test_unwrapped_error_is_clean_exit_6(tmp_path, image, env_file, capsys):
    secret_msg = f"pillow choked; request had {FAKE_KEY}"
    with patch("main.extract_card_from_bytes",
               side_effect=OSError(secret_msg)):
        code = _run(image, tmp_path, env_file)
    assert code == card_to_vcf.EXIT_EXTRACTION_FAILED
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert "Extraction failed: OSError" in out
    assert FAKE_KEY not in out
    assert "Traceback" not in out
    import logging
    assert logging.getLogger("main").disabled is False


def test_unwrapped_error_reraises_under_verbose(tmp_path, image, env_file):
    with patch("main.extract_card_from_bytes",
               side_effect=ValueError("bad timeout")):
        with pytest.raises(ValueError):
            _run(image, tmp_path, env_file, "--verbose")


def test_build_vcf_error_is_clean_exit_6(tmp_path, image, env_file, capsys):
    with patch("main.b", _mock_b(_make_valid_card())), \
            patch("vcard_builder.build_vcf",
                  side_effect=KeyError(FAKE_KEY)):
        code = _run(image, tmp_path, env_file)
    assert code == card_to_vcf.EXIT_EXTRACTION_FAILED
    captured = capsys.readouterr()
    assert "Could not build vCard: KeyError" in captured.err
    assert FAKE_KEY not in captured.out + captured.err
    assert not list(tmp_path.glob("*.vcf"))


def test_partial_file_removed_when_write_fails(tmp_path, monkeypatch):
    real_fdopen = os.fdopen

    def failing_fdopen(fd, *a, **kw):
        fh = real_fdopen(fd, *a, **kw)

        def boom(_content):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(fh, "write", boom, raising=False)
        return fh

    monkeypatch.setattr(card_to_vcf.os, "fdopen", failing_fdopen)
    with pytest.raises(OSError):
        card_to_vcf.write_new_file(tmp_path, "a.vcf", "content")
    assert not (tmp_path / "a.vcf").exists()


def test_partial_write_does_not_remove_preexisting_file(tmp_path,
                                                        monkeypatch):
    (tmp_path / "a.vcf").write_text("keep me")
    real_fdopen = os.fdopen

    def failing_fdopen(fd, *a, **kw):
        fh = real_fdopen(fd, *a, **kw)
        monkeypatch.setattr(fh, "write",
                            lambda _c: (_ for _ in ()).throw(OSError(28, "x")),
                            raising=False)
        return fh

    monkeypatch.setattr(card_to_vcf.os, "fdopen", failing_fdopen)
    with pytest.raises(OSError):
        card_to_vcf.write_new_file(tmp_path, "a.vcf", "content")
    assert (tmp_path / "a.vcf").read_text() == "keep me"
    assert not (tmp_path / "a-2.vcf").exists()


def test_read_capped_rejects_file_over_limit(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 101)
    with pytest.raises(card_to_vcf.ConfigError):
        card_to_vcf.read_capped(f, 100)
    assert card_to_vcf.read_capped(f, 101) == b"x" * 101


def test_file_growing_after_stat_is_rejected(tmp_path, image, env_file,
                                             monkeypatch):
    """stat() reports a small size, but the real read exceeds the limit."""
    env_file.write_text(
        f"OWNER_ANTHROPIC_API_KEY={FAKE_KEY}\nMAX_FILE_SIZE_MB=0.001\n"
    )
    image.write_bytes(b"x" * 5000)  # > 0.001 MB (1048 bytes)
    real_stat = Path.stat

    def small_stat(self, *a, **kw):
        st = real_stat(self, *a, **kw)
        if self == image:
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev,
                                   st.st_nlink, st.st_uid, st.st_gid, 10,
                                   st.st_atime, st.st_mtime, st.st_ctime))
        return st

    monkeypatch.setattr(Path, "stat", small_stat)
    assert _run(image, tmp_path, env_file) == card_to_vcf.EXIT_CONFIG


# ── BAML log level (QA finding: old test proved nothing) ────────────────────


def test_shell_baml_log_is_overridden_without_verbose(monkeypatch):
    monkeypatch.setenv("BAML_LOG", "info")
    card_to_vcf.configure_baml_logging(verbose=False)
    assert os.environ["BAML_LOG"] == "error"


def test_verbose_respects_shell_baml_log(monkeypatch):
    monkeypatch.setenv("BAML_LOG", "debug")
    card_to_vcf.configure_baml_logging(verbose=True)
    assert os.environ["BAML_LOG"] == "debug"


_ORDER_PROBE = textwrap.dedent("""
    import json, sys
    sys.path.insert(0, {scripts!r})
    import card_to_vcf
    seen = {{}}
    real = card_to_vcf.configure_baml_logging
    def spy(verbose):
        seen["baml_loaded_before"] = "baml_client" in sys.modules
        real(verbose)
    card_to_vcf.configure_baml_logging = spy
    code = card_to_vcf.run([{image!r}, "--out-dir", {out!r},
                            "--env-file", {env!r}])
    import os
    seen["baml_loaded_after"] = "baml_client" in sys.modules
    seen["BAML_LOG"] = os.environ.get("BAML_LOG")
    seen["code"] = code
    print(json.dumps(seen))
""")


def test_baml_log_is_set_before_baml_client_loads(tmp_path, env_file):
    """Fresh interpreter: BAML reads BAML_LOG at import, so order matters.

    Uses a non-image file so the run stops at the MIME check -- main.py
    (and therefore baml_client) is imported, but no API call is made.
    """
    bogus = tmp_path / "notes.jpg"
    bogus.write_bytes(b"plain text, not an image")
    probe = tmp_path / "probe.py"
    probe.write_text(_ORDER_PROBE.format(
        scripts=str(REPO_ROOT / "scripts"), image=str(bogus),
        out=str(tmp_path), env=str(env_file),
    ))
    proc = subprocess.run(
        [sys.executable, str(probe)], cwd=REPO_ROOT, capture_output=True,
        text=True, timeout=60,
        env={k: v for k, v in os.environ.items() if k != "BAML_LOG"},
    )
    assert proc.returncode == 0, proc.stderr
    seen = json.loads(proc.stdout.strip().splitlines()[-1])
    assert seen["baml_loaded_before"] is False
    assert seen["baml_loaded_after"] is True
    assert seen["BAML_LOG"] == "error"
    assert seen["code"] == card_to_vcf.EXIT_UNSUPPORTED


@integration
def test_live_bad_key_leaks_nothing_to_stderr(tmp_path, image):
    """Real BAML call with a fake key: Anthropic rejects it (401, unbilled).

    Proves end to end that BAML's prompt/response log stays quiet and the
    key never reaches stdout/stderr.
    """
    env = tmp_path / ".env"
    env.write_text(f"OWNER_ANTHROPIC_API_KEY={FAKE_KEY}\n")
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "card_to_vcf.py"),
         str(image), "--out-dir", str(tmp_path), "--env-file", str(env)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
        env={k: v for k, v in os.environ.items()
             if k not in ("BAML_LOG",) + card_to_vcf.KEY_NAMES},
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == card_to_vcf.EXIT_EXTRACTION_FAILED
    assert FAKE_KEY not in output
    assert "---PROMPT---" not in output
    assert "STEP 1" not in output
