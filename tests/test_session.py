"""Tests for session.py — Fernet BYOK encryption.

All tests are pure unit tests: no HTTP, no BAML, no external calls.

Note: session.py reads SESSION_SECRET at module import time. If the module
is already imported (e.g., via test_app.py), the secret is already set.
We set it here as well so this file can run standalone.
"""

import os

from cryptography.fernet import Fernet

os.environ.setdefault("SESSION_SECRET", Fernet.generate_key().decode())

import session  # noqa: E402


# ---------------------------------------------------------------------------
# encrypt_api_key / decrypt_api_key
# ---------------------------------------------------------------------------


class TestEncryptDecrypt:
    def test_round_trip(self):
        key = "sk-ant-api03-test-key-round-trip"
        token = session.encrypt_api_key(key)
        assert isinstance(token, str)
        assert token != key  # must be opaque
        result = session.decrypt_api_key(token)
        assert result == key

    def test_decrypt_garbage_returns_none(self):
        assert session.decrypt_api_key("this-is-not-a-fernet-token") is None

    def test_decrypt_empty_string_returns_none(self):
        assert session.decrypt_api_key("") is None

    def test_decrypt_none_like_empty(self):
        """decrypt_api_key("") returns None (falsy input guard)."""
        assert session.decrypt_api_key("") is None

    def test_different_keys_produce_different_tokens(self):
        key1 = "sk-ant-aaa-111"
        key2 = "sk-ant-bbb-222"
        assert session.encrypt_api_key(key1) != session.encrypt_api_key(key2)

    def test_same_key_different_tokens_each_call(self):
        """Fernet uses a random IV per call, so two encryptions of the same
        plaintext should not be identical."""
        key = "sk-ant-api03-determinism-test"
        t1 = session.encrypt_api_key(key)
        t2 = session.encrypt_api_key(key)
        assert t1 != t2

    def test_tampered_token_returns_none(self):
        key = "sk-ant-api03-tamper-test"
        token = session.encrypt_api_key(key)
        # Flip a byte near the end of the token
        tampered = token[:-3] + "XXX"
        assert session.decrypt_api_key(tampered) is None

    def test_truncated_token_returns_none(self):
        key = "sk-ant-api03-truncate-test"
        token = session.encrypt_api_key(key)
        assert session.decrypt_api_key(token[:10]) is None


# ---------------------------------------------------------------------------
# mask_api_key
# ---------------------------------------------------------------------------


class TestMaskApiKey:
    def test_long_key_masked_format(self):
        key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        result = session.mask_api_key(key)
        # Must start with first 7 chars of key
        assert result.startswith(key[:7])
        # Must end with last 4 chars of key
        assert result.endswith(key[-4:])
        # Middle must be ...
        assert "..." in result

    def test_long_key_exact_format(self):
        key = "sk-ant-api03-ABCDEFGHIJKLMNOPWXYZ"
        result = session.mask_api_key(key)
        expected = key[:7] + "..." + key[-4:]
        assert result == expected

    def test_short_key_returns_stars(self):
        """Keys with 11 chars or fewer → '***'."""
        assert session.mask_api_key("sk-ant-abc") == "***"
        assert session.mask_api_key("sk-ant-") == "***"
        assert session.mask_api_key("short") == "***"

    def test_exactly_12_chars_is_long_enough(self):
        """len > 11 should produce the sk-ant-... format."""
        key = "sk-ant-abcde"  # 12 chars
        result = session.mask_api_key(key)
        assert result == key[:7] + "..." + key[-4:]
        assert result != "***"

    def test_mask_does_not_expose_full_key(self):
        key = "sk-ant-api03-supersecret-value-here"
        result = session.mask_api_key(key)
        # The masked result should be much shorter than the original
        assert len(result) < len(key)
        assert "supersecret" not in result
