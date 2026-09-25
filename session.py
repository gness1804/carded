"""Session management for Carded.

API keys are Fernet-encrypted before being stored in an HttpOnly cookie,
so plaintext keys are never exposed to client-side JavaScript.

To generate a SESSION_SECRET, run in a Python shell:
    from cryptography.fernet import Fernet
    print(Fernet.generate_key().decode())
"""

import os
import warnings

from cryptography.fernet import Fernet, InvalidToken

# Server-side ceiling on token age, in seconds. Matches the longest cookie
# lifetime offered in the UI (90 days, see KEY_PERSISTENCE_MAX_AGES in app.py),
# so a captured token cannot be replayed indefinitely. Mirrors Receipt Ranger.
MAX_TOKEN_TTL = 90 * 24 * 60 * 60  # 90 days

_SESSION_SECRET = os.environ.get("SESSION_SECRET", "")

if not _SESSION_SECRET:
    _fernet = Fernet(Fernet.generate_key())
    warnings.warn(
        "SESSION_SECRET not set. Using a randomly generated encryption key. "
        "Set SESSION_SECRET in .env for a stable key across restarts. "
        'Generate one with: python -c "from cryptography.fernet import Fernet; '
        'print(Fernet.generate_key().decode())"',
        RuntimeWarning,
        stacklevel=2,
    )
else:
    try:
        _fernet = Fernet(_SESSION_SECRET.encode())
    except Exception as exc:
        raise ValueError(
            "SESSION_SECRET must be a valid Fernet key. "
            "Generate one with: "
            'python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        ) from exc


def encrypt_api_key(api_key: str) -> str:
    """Encrypt an API key and return an opaque token."""
    return _fernet.encrypt(api_key.encode()).decode()


def decrypt_api_key(token: str, ttl: int | None = MAX_TOKEN_TTL) -> str | None:
    """Decrypt a session token and return the plaintext API key.

    Tokens older than ``ttl`` seconds are rejected (server-side expiry), so a
    captured token cannot be replayed indefinitely even if the browser cookie
    that carried it is long-lived. Pass ``ttl=None`` to disable expiry.

    Returns None if the token is empty, invalid, expired, or cannot be
    decrypted.
    """
    if not token:
        return None
    try:
        return _fernet.decrypt(token.encode(), ttl=ttl).decode()
    except (InvalidToken, Exception):
        return None


def mask_api_key(api_key: str) -> str:
    """Return a masked version of the API key for display.

    Example: "sk-ant-...wxyz"
    """
    if len(api_key) <= 11:
        return "***"
    return api_key[:7] + "..." + api_key[-4:]
