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


def _binding_for_cookie(cookie_value: str = "") -> str:
    """Recompute the L3 download-token session binding for a cookie value.

    Mirrors app._session_binding so tests can forge correctly-bound tokens
    (e.g. a bound-but-unknown token to exercise the 404 path).
    """
    import hashlib
    import hmac

    return hmac.new(
        app_module._DOWNLOAD_TOKEN_SECRET.encode(),
        cookie_value.encode(),
        hashlib.sha256,
    ).hexdigest()


def _client_with_session(api_key: str = _VALID_KEY) -> TestClient:
    """A fresh, isolated TestClient with a carded_session cookie set at the
    client level.

    The module-level ``client`` persists cookies across tests, which makes
    per-request ``cookies=`` ambiguous (httpx merges them). For tests that
    exercise the L3 session binding — where /process and /download must agree
    on the exact cookie value — use an isolated client instead.
    """
    import session as session_module_helper

    isolated = TestClient(app_module.app, raise_server_exceptions=False)
    isolated.cookies.set(
        "carded_session", session_module_helper.encrypt_api_key(api_key)
    )
    return isolated


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Clear module-level rate-limiter state between tests.

    The limiters are process-global; without this the suite's own request
    volume would trip them and bleed 429s across unrelated tests.
    """
    app_module._session_key_limiter._hits.clear()
    app_module._process_limiter._hits.clear()
    yield
    app_module._session_key_limiter._hits.clear()
    app_module._process_limiter._hits.clear()


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
        body = response.json()
        assert body["status"] == "ok"
        assert "version" in body
        assert body["version"]  # non-empty


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
        # Isolated client: /process and /download must share one cookie value
        # for the L3 binding check to pass.
        sess = _client_with_session()
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            process_resp = sess.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
            )
        token = process_resp.json()["token"]
        vcf_resp = sess.get(f"/download/vcf?token={token}")
        assert vcf_resp.status_code == 200
        assert "text/vcard" in vcf_resp.headers["content-type"]

    def test_200_token_is_usable_for_csv_download(self):
        result = _make_valid_result(JAMIE_PARK)
        sess = _client_with_session()
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            process_resp = sess.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
            )
        token = process_resp.json()["token"]
        csv_resp = sess.get(f"/download/csv?token={token}")
        assert csv_resp.status_code == 200
        assert "text/csv" in csv_resp.headers["content-type"]


# ---------------------------------------------------------------------------
# GET /download/vcf
# ---------------------------------------------------------------------------


class TestDownloadVcf:
    def _get_token(self, card_dict: dict | None = None) -> tuple[str, TestClient]:
        """Return (token, isolated_client). Download on the same client so the
        L3 session-binding check passes."""
        result = _make_valid_result(card_dict or JAMIE_PARK)
        sess = _client_with_session()
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            resp = sess.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
            )
        return resp.json()["token"], sess

    def test_200_correct_content_type_and_disposition(self):
        token, sess = self._get_token()
        response = sess.get(f"/download/vcf?token={token}")
        assert response.status_code == 200
        assert "text/vcard" in response.headers["content-type"]
        assert "attachment" in response.headers["content-disposition"]
        assert ".vcf" in response.headers["content-disposition"]

    def test_200_body_is_vcard(self):
        token, sess = self._get_token()
        response = sess.get(f"/download/vcf?token={token}")
        assert "BEGIN:VCARD" in response.text
        assert "END:VCARD" in response.text

    def test_404_unknown_token(self):
        """A correctly signed and correctly bound but never-issued token → 404."""
        # Sign a UUID that was never stored, bound to the no-cookie session.
        # An isolated client with no cookie makes the binding deterministic.
        phantom_id = "00000000-0000-0000-0000-000000000000"
        signed = app_module._SERIALIZER.dumps([phantom_id, _binding_for_cookie("")])
        fresh = TestClient(app_module.app, raise_server_exceptions=False)
        response = fresh.get(f"/download/vcf?token={signed}")
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
    def _get_token(self) -> tuple[str, TestClient]:
        """Return (token, isolated_client); download on the same client so the
        L3 session-binding check passes."""
        result = _make_valid_result(JAMIE_PARK)
        sess = _client_with_session()
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            resp = sess.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
            )
        return resp.json()["token"], sess

    def test_200_correct_content_type_and_disposition(self):
        token, sess = self._get_token()
        response = sess.get(f"/download/csv?token={token}")
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]
        assert "attachment" in response.headers["content-disposition"]
        assert ".csv" in response.headers["content-disposition"]

    def test_200_body_has_header_row(self):
        token, sess = self._get_token()
        response = sess.get(f"/download/csv?token={token}")
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

    def test_strips_unicode_c1_control_chars(self):
        """L1: Unicode C1 controls (U+0080–U+009F) are stripped."""
        for code in range(0x80, 0xA0):
            char = chr(code)
            result = _sanitize_detail(f"a{char}b")
            assert char not in result, f"Expected U+{code:04X} to be stripped"
            assert result == "ab"

    def test_strips_bidi_override_codepoints(self):
        """L1: bidi-override / isolate codepoints are stripped."""
        bidi = [
            "‪", "‫", "‬", "‭", "‮",  # embeddings/overrides
            "⁦", "⁧", "⁨", "⁩",            # isolates
        ]
        for cp in bidi:
            result = _sanitize_detail(f"safe{cp}text")
            assert cp not in result, f"Expected U+{ord(cp):04X} to be stripped"
            assert result == "safetext"

    def test_preserves_ordinary_unicode(self):
        """Non-control Unicode (accents, CJK, emoji) is preserved."""
        text = "café 名刺 \U0001f600"
        assert _sanitize_detail(text) == text


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


# ---------------------------------------------------------------------------
# Security headers middleware (L4)
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    def test_index_has_security_headers(self):
        response = client.get("/")
        assert response.status_code == 200
        csp = response.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("referrer-policy") == "no-referrer"
        assert "camera=()" in response.headers.get("permissions-policy", "")

    def test_headers_present_on_json_error_responses(self):
        """Middleware must cover non-200 paths too."""
        response = client.post(
            "/session/key", json={"api_key": "not-valid"}
        )
        assert response.status_code == 400
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert "content-security-policy" in response.headers

    def test_headers_present_on_health(self):
        response = client.get("/health")
        assert "content-security-policy" in response.headers


# ---------------------------------------------------------------------------
# Rate limiting (L2)
# ---------------------------------------------------------------------------


class TestRateLimiting:
    def test_session_key_rate_limited_after_threshold(self):
        limit = app_module._RATE_LIMIT_SESSION_KEY
        fresh = TestClient(app_module.app, raise_server_exceptions=False)
        # Burn through the allowance.
        for _ in range(limit):
            resp = fresh.post("/session/key", json={"api_key": "not-valid"})
            assert resp.status_code != 429
        # The next request trips the limiter.
        resp = fresh.post("/session/key", json={"api_key": "not-valid"})
        assert resp.status_code == 429
        assert resp.json()["error"] == "rate_limited"

    def test_process_rate_limited_after_threshold(self):
        limit = app_module._RATE_LIMIT_PROCESS
        fresh = TestClient(app_module.app, raise_server_exceptions=False)
        cookies = _session_cookie()
        result = _make_valid_result(JAMIE_PARK)
        with patch.object(
            app_module, "extract_card_from_bytes", return_value=result
        ):
            for _ in range(limit):
                resp = fresh.post(
                    "/process",
                    files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                    cookies=cookies,
                )
                assert resp.status_code != 429
            resp = fresh.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=cookies,
            )
        assert resp.status_code == 429
        assert resp.json()["error"] == "rate_limited"

    def test_rate_limit_keyed_by_forwarded_for(self):
        """Distinct X-Forwarded-For clients get independent allowances."""
        limit = app_module._RATE_LIMIT_SESSION_KEY
        fresh = TestClient(app_module.app, raise_server_exceptions=False)
        for _ in range(limit):
            fresh.post(
                "/session/key",
                json={"api_key": "not-valid"},
                headers={"X-Forwarded-For": "10.0.0.1"},
            )
        # client 10.0.0.1 is now exhausted...
        blocked = fresh.post(
            "/session/key",
            json={"api_key": "not-valid"},
            headers={"X-Forwarded-For": "10.0.0.1"},
        )
        assert blocked.status_code == 429
        # ...but a different client IP is unaffected.
        other = fresh.post(
            "/session/key",
            json={"api_key": "not-valid"},
            headers={"X-Forwarded-For": "10.0.0.2"},
        )
        assert other.status_code == 400


class TestRateLimiterUnit:
    def test_allows_up_to_limit(self):
        limiter = app_module.RateLimiter(max_requests=3, window_seconds=60)
        assert [limiter.allow("k") for _ in range(3)] == [True, True, True]

    def test_blocks_past_limit(self):
        limiter = app_module.RateLimiter(max_requests=2, window_seconds=60)
        limiter.allow("k")
        limiter.allow("k")
        assert limiter.allow("k") is False

    def test_keys_are_independent(self):
        limiter = app_module.RateLimiter(max_requests=1, window_seconds=60)
        assert limiter.allow("a") is True
        assert limiter.allow("b") is True
        assert limiter.allow("a") is False

    def test_window_eviction_restores_allowance(self):
        limiter = app_module.RateLimiter(max_requests=1, window_seconds=0)
        assert limiter.allow("k") is True
        # window_seconds=0 means every prior hit is immediately outside it.
        assert limiter.allow("k") is True


# ---------------------------------------------------------------------------
# Download token / session binding (L3)
# ---------------------------------------------------------------------------


class TestDownloadTokenBinding:
    def _mint_token(self, sess: TestClient) -> str:
        result = _make_valid_result(JAMIE_PARK)
        with patch.object(
            app_module, "extract_card_from_bytes", return_value=result
        ):
            resp = sess.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
            )
        return resp.json()["token"]

    def test_token_redeemable_by_issuing_session(self):
        sess = _client_with_session()
        token = self._mint_token(sess)
        resp = sess.get(f"/download/vcf?token={token}")
        assert resp.status_code == 200

    def test_token_rejected_for_different_session(self):
        """A token leaked to another session must not redeem (400)."""
        issuer = _client_with_session()
        token = self._mint_token(issuer)
        # A different client with its own (distinct) session cookie value.
        attacker = _client_with_session()
        resp = attacker.get(f"/download/vcf?token={token}")
        assert resp.status_code == 400

    def test_token_rejected_when_session_absent(self):
        issuer = _client_with_session()
        token = self._mint_token(issuer)
        no_session = TestClient(app_module.app, raise_server_exceptions=False)
        resp = no_session.get(f"/download/vcf?token={token}")
        assert resp.status_code == 400

    def test_legacy_string_payload_rejected(self):
        """Old single-string token payloads (pre-L3) are no longer accepted."""
        signed = app_module._SERIALIZER.dumps("some-token-id")
        fresh = TestClient(app_module.app, raise_server_exceptions=False)
        resp = fresh.get(f"/download/vcf?token={signed}")
        assert resp.status_code == 400

    def test_csv_download_also_binds_to_session(self):
        issuer = _client_with_session()
        token = self._mint_token(issuer)
        attacker = _client_with_session()
        resp = attacker.get(f"/download/csv?token={token}")
        assert resp.status_code == 400

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


# ---------------------------------------------------------------------------
# GET /download/csv — error paths (404, 410, 400)
# ---------------------------------------------------------------------------


class TestDownloadCsvErrorPaths:
    """The CSV download shares _resolve_token with VCF but previously had no
    error-path coverage. These tests close that gap."""

    def test_404_unknown_token(self):
        """A valid, well-bound token that was never stored returns 404."""
        phantom_id = "00000000-0000-0000-0000-000000000001"
        signed = app_module._SERIALIZER.dumps([phantom_id, _binding_for_cookie("")])
        fresh = TestClient(app_module.app, raise_server_exceptions=False)
        response = fresh.get(f"/download/csv?token={signed}")
        assert response.status_code == 404

    def test_410_expired_token(self):
        """An expired token returns 410 on the CSV endpoint too."""
        from itsdangerous import SignatureExpired

        with patch.object(
            app_module._SERIALIZER,
            "loads",
            side_effect=SignatureExpired("token expired"),
        ):
            response = client.get("/download/csv?token=anything")
        assert response.status_code == 410

    def test_400_bad_signature(self):
        """A tampered token returns 400 on the CSV endpoint."""
        response = client.get("/download/csv?token=not.a.valid.token")
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# POST /process — malformed Content-Length header
# ---------------------------------------------------------------------------


class TestProcessMalformedContentLength:
    def test_malformed_content_length_header_falls_through_to_byte_check(self):
        """A non-integer Content-Length header must not raise a 500. The route
        silently falls through to the post-read byte-level size check."""
        result = _make_valid_result(JAMIE_PARK)
        with patch.object(app_module, "extract_card_from_bytes", return_value=result):
            response = client.post(
                "/process",
                files={"file": ("card.jpg", _TINY_JPEG, "image/jpeg")},
                cookies=_session_cookie(),
                headers={"Content-Length": "not-an-integer"},
            )
        # Should process normally (malformed header is silently ignored).
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# POST /process — MIME type not in allow-list (image/gif)
# ---------------------------------------------------------------------------


class TestProcessUnsupportedMimeTypes:
    @pytest.mark.parametrize("mime_type", ["image/gif", "image/bmp", "image/tiff"])
    def test_400_unsupported_image_mime(self, mime_type):
        """MIME types that are not in the explicit allowlist return 400."""
        with patch.object(
            app_module,
            "extract_card_from_bytes",
            side_effect=UnsupportedMimeType(f"unsupported: {mime_type}"),
        ):
            response = client.post(
                "/process",
                files={"file": ("card.img", _TINY_JPEG, mime_type)},
                cookies=_session_cookie(),
            )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_file_type"
