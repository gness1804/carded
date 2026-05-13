"""Tests for app.py — FastAPI routes.

Unit tests only: BAML is mocked at the app level (mocking app.extract_card_from_bytes).
Integration tests that hit a real LLM are gated on RUN_INTEGRATION_TESTS=1 and
are not included here per CLAUDE.md / project rules.

Environment variables are set BEFORE importing app to ensure session.py and
app.py pick up the correct secrets at module load time.
"""

import io
import os

# Set test env vars before any app import so module-level code in session.py
# and app.py sees them.
from cryptography.fernet import Fernet

os.environ.setdefault("SESSION_SECRET", Fernet.generate_key().decode())
os.environ.setdefault(
    "DOWNLOAD_TOKEN_SECRET", "test-download-secret-do-not-use-in-prod"
)
os.environ.setdefault("OWNER_ANTHROPIC_API_KEY", "sk-ant-owner-test-key")
os.environ.setdefault("COOKIE_SECURE", "false")  # TestClient doesn't do HTTPS

from unittest.mock import MagicMock, patch  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app as app_module  # noqa: E402
from app import (  # noqa: E402
    TokenStore,
    _sanitize_detail,
    is_owner,
)
from main import (  # noqa: E402
    ExtractionError,
    ExtractionTimeout,
    Illegible,
    NotABusinessCard,
    UnsupportedMimeType,
    Valid,
)
from tests.fixtures_data import JAMIE_PARK  # noqa: E402

client = TestClient(app_module.app, raise_server_exceptions=False)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_KEY = "sk-ant-test-valid-key-0000000000000"
_OWNER_KEY = "sk-ant-owner-test-key"

# Minimal valid JPEG bytes (SOI + EOI markers)
_TINY_JPEG = bytes([0xFF, 0xD8, 0xFF, 0xD9])


def _session_cookie(api_key: str = _VALID_KEY) -> dict:
    """Return a cookies dict with a valid carded_session for the given key."""
    import session as session_module_helper
    token = session_module_helper.encrypt_api_key(api_key)
    return {"carded_session": token}


def _make_valid_result(card_dict: dict | None = None) -> Valid:
    """Build a Valid result wrapping a MagicMock BusinessCard from a dict."""
    card_dict = card_dict or JAMIE_PARK
    mock_card = MagicMock()
    mock_card.model_dump.return_value = card_dict
    return Valid(card=mock_card)


# ---------------------------------------------------------------------------
# GET / — index page
# ---------------------------------------------------------------------------


class TestIndex:
    def test_renders_without_session(self):
        response = client.get("/", cookies={})
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_renders_with_session(self):
        response = client.get("/", cookies=_session_cookie())
        assert response.status_code == 200

    def test_health(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# POST /session/key
# ---------------------------------------------------------------------------


class TestSetSessionKey:
    def test_400_invalid_key_format_missing_prefix(self):
        response = client.post("/session/key", json={"api_key": "not-an-anthropic-key"})
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "invalid_api_key_format"
        assert "sk-ant-" in body["message"]

    def test_400_empty_key(self):
        response = client.post("/session/key", json={"api_key": ""})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_api_key_format"

    def test_200_happy_path_sets_cookie(self):
        response = client.post("/session/key", json={"api_key": _VALID_KEY})
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is True
        assert "masked_key" in body
        assert "is_owner" in body

    def test_200_cookie_attributes(self):
        """Verify HttpOnly, SameSite=Lax, Path=/ are present in Set-Cookie."""
        response = client.post("/session/key", json={"api_key": _VALID_KEY})
        assert response.status_code == 200
        set_cookie = response.headers.get("set-cookie", "")
        assert "carded_session" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "SameSite=lax" in set_cookie or "samesite=lax" in set_cookie.lower()
        assert "Path=/" in set_cookie or "path=/" in set_cookie.lower()

    def test_200_owner_key_sets_is_owner_true(self):
        response = client.post("/session/key", json={"api_key": _OWNER_KEY})
        assert response.status_code == 200
        assert response.json()["is_owner"] is True

    def test_200_non_owner_key_sets_is_owner_false(self):
        response = client.post("/session/key", json={"api_key": _VALID_KEY})
        assert response.status_code == 200
        assert response.json()["is_owner"] is False


# ---------------------------------------------------------------------------
# DELETE /session/key — clear the encrypted key cookie
# ---------------------------------------------------------------------------


class TestClearSessionKey:
    def test_200_clears_cookie(self):
        """DELETE /session/key returns 200 and instructs the browser to drop
        the carded_session cookie. After clearing, /process should 401."""
        fresh = TestClient(app_module.app, raise_server_exceptions=False)
        # Set a key first.
        fresh.post("/session/key", json={"api_key": _VALID_KEY})
        assert "carded_session" in fresh.cookies

        # Clear it.
        resp = fresh.delete("/session/key")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

        # The Set-Cookie header should expire the cookie.
        set_cookie = resp.headers.get("set-cookie", "").lower()
        assert "carded_session" in set_cookie
        # httpx applies the expiry, so the client should now have no value.
        assert fresh.cookies.get("carded_session") in (None, "")

        # And /process now returns 401.
        followup = fresh.post(
            "/process",
            files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
        )
        assert followup.status_code == 401
        assert followup.json()["error"] == "missing_api_key"


# ---------------------------------------------------------------------------
# POST /process — authentication
# ---------------------------------------------------------------------------


class TestProcessAuth:
    def _fresh_client(self) -> TestClient:
        """A TestClient with no persisted cookies from prior tests."""
        return TestClient(app_module.app, raise_server_exceptions=False)

    def test_401_no_cookie(self):
        fresh = self._fresh_client()
        response = fresh.post(
            "/process",
            files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
        )
        assert response.status_code == 401
        body = response.json()
        assert body["error"] == "missing_api_key"

    def test_401_bad_cookie(self):
        """A garbage cookie value that cannot be decrypted returns 401."""
        fresh = self._fresh_client()
        fresh.cookies.set("carded_session", "this-is-not-a-valid-fernet-token")
        response = fresh.post(
            "/process",
            files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
        )
        assert response.status_code == 401
        assert response.json()["error"] == "missing_api_key"


# ---------------------------------------------------------------------------
# POST /process — file size enforcement
# ---------------------------------------------------------------------------


class TestProcessFileSize:
    def test_413_over_limit(self):
        """Body larger than MAX_FILE_SIZE_MB (default 10 MB) → 413."""
        big_file = b"x" * (11 * 1024 * 1024)  # 11 MB
        response = client.post(
            "/process",
            files={"file": ("big.jpg", big_file, "image/jpeg")},
            cookies=_session_cookie(),
        )
        assert response.status_code == 413
        body = response.json()
        assert body["error"] == "file_too_large"


# ---------------------------------------------------------------------------
# POST /process — extraction error mapping
# ---------------------------------------------------------------------------


class TestProcessExtractionErrors:
    def test_400_invalid_file_type(self):
        with patch.object(
            app_module, "extract_card_from_bytes", side_effect=UnsupportedMimeType("bad mime")
        ):
            response = client.post(
                "/process",
                files={"file": ("card.gif", _TINY_JPEG, "image/gif")},
                cookies=_session_cookie(),
            )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_file_type"

    def test_502_extraction_timeout(self):
        with patch.object(
            app_module, "extract_card_from_bytes", side_effect=ExtractionTimeout("timed out")
        ):
            response = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        assert response.status_code == 502
        body = response.json()
        assert body["error"] == "extraction_failed"
        # Internal details must never be surfaced
        assert "timed out" not in str(body)

    def test_502_extraction_error(self):
        with patch.object(
            app_module, "extract_card_from_bytes", side_effect=ExtractionError("internal crash")
        ):
            response = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        assert response.status_code == 502
        body = response.json()
        assert body["error"] == "extraction_failed"
        assert "internal crash" not in str(body)


# ---------------------------------------------------------------------------
# POST /process — 422 responses with sanitized detail
# ---------------------------------------------------------------------------


class TestProcessSanitizedDetail:
    def test_422_not_a_business_card(self):
        result = NotABusinessCard(message="a photo of a dog")
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            response = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        assert response.status_code == 422
        body = response.json()
        assert body["error"] == "not_a_business_card"
        assert body["detail"] == "a photo of a dog"

    def test_422_not_a_business_card_strips_control_chars(self):
        """Control characters (ASCII < 0x20) other than \\n/\\t must be stripped."""
        dirty_message = "a \x00photo\x01 of \x1ba dog"
        result = NotABusinessCard(message=dirty_message)
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            response = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        body = response.json()
        assert "\x00" not in body["detail"]
        assert "\x01" not in body["detail"]
        assert "\x1b" not in body["detail"]
        assert "photo" in body["detail"]

    def test_422_not_a_business_card_caps_at_200_chars(self):
        """Detail is capped at 200 characters."""
        long_message = "a" * 300
        result = NotABusinessCard(message=long_message)
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            response = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        body = response.json()
        assert len(body["detail"]) <= 200

    def test_422_illegible(self):
        result = Illegible(message="image is too blurry to read")
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            response = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        assert response.status_code == 422
        body = response.json()
        assert body["error"] == "illegible"
        assert body["detail"] == "image is too blurry to read"

    def test_422_illegible_strips_control_chars_and_caps(self):
        dirty = "\x00" * 5 + "blurry" + "x" * 300
        result = Illegible(message=dirty)
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            response = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        body = response.json()
        assert "\x00" not in body["detail"]
        assert len(body["detail"]) <= 200


# ---------------------------------------------------------------------------
# POST /process — happy path (Valid result)
# ---------------------------------------------------------------------------


class TestProcessHappyPath:
    def test_200_returns_token_and_card(self):
        result = _make_valid_result(JAMIE_PARK)
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            response = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        assert response.status_code == 200
        body = response.json()
        assert "token" in body
        assert isinstance(body["token"], str)
        assert "card" in body
        assert body["card"]["full_name"] == "Jamie Park"

    def test_200_token_is_usable_for_vcf_download(self):
        result = _make_valid_result(JAMIE_PARK)
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            process_resp = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        token = process_resp.json()["token"]
        vcf_resp = client.get(f"/download/vcf?token={token}")
        assert vcf_resp.status_code == 200
        assert "text/vcard" in vcf_resp.headers["content-type"]

    def test_200_token_is_usable_for_csv_download(self):
        result = _make_valid_result(JAMIE_PARK)
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            process_resp = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        token = process_resp.json()["token"]
        csv_resp = client.get(f"/download/csv?token={token}")
        assert csv_resp.status_code == 200
        assert "text/csv" in csv_resp.headers["content-type"]


# ---------------------------------------------------------------------------
# GET /download/vcf
# ---------------------------------------------------------------------------


class TestDownloadVcf:
    def _get_token(self, card_dict: dict | None = None) -> str:
        result = _make_valid_result(card_dict or JAMIE_PARK)
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            resp = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        return resp.json()["token"]

    def test_200_correct_content_type_and_disposition(self):
        token = self._get_token()
        response = client.get(f"/download/vcf?token={token}")
        assert response.status_code == 200
        assert "text/vcard" in response.headers["content-type"]
        assert "attachment" in response.headers["content-disposition"]
        assert ".vcf" in response.headers["content-disposition"]

    def test_200_body_is_vcard(self):
        token = self._get_token()
        response = client.get(f"/download/vcf?token={token}")
        assert "BEGIN:VCARD" in response.text
        assert "END:VCARD" in response.text

    def test_404_unknown_token(self):
        """A correctly signed but never-issued token returns 404."""
        # Sign a UUID that was never stored in the token store.
        phantom_id = "00000000-0000-0000-0000-000000000000"
        signed = app_module._SERIALIZER.dumps(phantom_id)
        response = client.get(f"/download/vcf?token={signed}")
        assert response.status_code == 404

    def test_410_expired_token(self):
        """A token that itsdangerous reports as SignatureExpired returns 410."""
        from itsdangerous import SignatureExpired
        with patch.object(
            app_module._SERIALIZER,
            "loads",
            side_effect=SignatureExpired("token expired"),
        ):
            response = client.get("/download/vcf?token=anything")
        assert response.status_code == 410

    def test_400_bad_signature(self):
        """A tampered token returns 400."""
        response = client.get("/download/vcf?token=this.is.not.a.valid.signature")
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# GET /download/csv
# ---------------------------------------------------------------------------


class TestDownloadCsv:
    def _get_token(self) -> str:
        result = _make_valid_result(JAMIE_PARK)
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            resp = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
            )
        return resp.json()["token"]

    def test_200_correct_content_type_and_disposition(self):
        token = self._get_token()
        response = client.get(f"/download/csv?token={token}")
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]
        assert "attachment" in response.headers["content-disposition"]
        assert ".csv" in response.headers["content-disposition"]

    def test_200_body_has_header_row(self):
        token = self._get_token()
        response = client.get(f"/download/csv?token={token}")
        assert "Name" in response.text
        assert "Jamie Park" in response.text


# ---------------------------------------------------------------------------
# Unit tests — is_owner
# ---------------------------------------------------------------------------


class TestIsOwner:
    def test_matches_env_var_returns_true(self):
        assert is_owner("sk-ant-owner-test-key") is True

    def test_wrong_key_returns_false(self):
        assert is_owner("sk-ant-some-other-key") is False

    def test_none_returns_false(self):
        assert is_owner(None) is False

    def test_empty_string_returns_false(self):
        assert is_owner("") is False

    def test_env_unset_returns_false(self, monkeypatch):
        monkeypatch.delenv("OWNER_ANTHROPIC_API_KEY", raising=False)
        # Reload the function's env lookup at call time (it uses os.environ.get)
        assert is_owner("sk-ant-owner-test-key") is False


# ---------------------------------------------------------------------------
# Unit tests — _sanitize_detail
# ---------------------------------------------------------------------------


class TestSanitizeDetail:
    def test_strips_null_byte(self):
        assert "\x00" not in _sanitize_detail("hello\x00world")

    def test_strips_control_chars_below_0x20(self):
        # All ASCII < 0x20 except \n (\x0a) and \t (\x09) should be stripped.
        for code in range(0x00, 0x20):
            char = chr(code)
            if char in ("\n", "\t"):
                # These are preserved.
                assert char in _sanitize_detail(char), f"Expected \\x{code:02x} to be preserved"
            else:
                assert char not in _sanitize_detail(char), f"Expected \\x{code:02x} to be stripped"

    def test_preserves_newline(self):
        result = _sanitize_detail("line1\nline2")
        assert "line1\nline2" == result

    def test_preserves_tab(self):
        result = _sanitize_detail("col1\tcol2")
        assert "col1\tcol2" == result

    def test_caps_at_200_chars(self):
        long_str = "a" * 300
        result = _sanitize_detail(long_str)
        assert len(result) == 200

    def test_shorter_than_200_unchanged(self):
        short = "hello world"
        assert _sanitize_detail(short) == short

    def test_does_not_html_escape(self):
        """No double-escaping: Jinja handles render-time escaping."""
        html = "<script>alert(1)</script>"
        result = _sanitize_detail(html)
        assert result == html  # Characters >= 0x20, not touched by sanitizer

    def test_strips_escape_sequence(self):
        assert "\x1b" not in _sanitize_detail("hello\x1bworld")


# ---------------------------------------------------------------------------
# Unit tests — TokenStore
# ---------------------------------------------------------------------------


class TestTokenStore:
    def test_put_and_get(self):
        store = TokenStore(ttl_seconds=60)
        store.put("key1", {"foo": "bar"})
        assert store.get("key1") == {"foo": "bar"}

    def test_get_unknown_key_returns_none(self):
        store = TokenStore(ttl_seconds=60)
        assert store.get("nonexistent") is None

    def test_expired_entry_returns_none(self):
        store = TokenStore(ttl_seconds=0)
        store.put("key1", {"foo": "bar"})
        # With ttl=0, any entry is immediately expired.
        assert store.get("key1") is None

    def test_sweep_removes_expired(self):
        store = TokenStore(ttl_seconds=0)
        store.put("k1", {})
        store.put("k2", {})
        # Trigger sweep via get
        store.get("k1")
        with store._lock:
            assert "k1" not in store._store
            assert "k2" not in store._store

    def test_thread_safety_basic(self):
        """Concurrent puts and gets should not raise."""
        import threading
        store = TokenStore(ttl_seconds=60)
        errors = []

        def writer():
            try:
                for i in range(100):
                    store.put(f"key-{i}", {"i": i})
            except Exception as exc:
                errors.append(exc)

        def reader():
            try:
                for i in range(100):
                    store.get(f"key-{i}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
