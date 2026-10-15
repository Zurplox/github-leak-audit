"""Redaction helpers. Complete candidates must not leave this layer."""

from __future__ import annotations

import hashlib
import hmac
import re


_PLACEHOLDER_WORDS = {
    "change-me", "changeme", "example", "fake", "placeholder", "redacted",
    "replace-me", "test-token", "your-api-key", "your_api_key", "your-token",
    "your_token", "none", "null", "undefined",
}


def mask_secret(value: str, prefix: int = 4, suffix: int = 4) -> str:
    """Return a bounded preview that never returns the complete value."""
    if not value:
        return ""
    if len(value) <= prefix + suffix:
        prefix = min(2, max(1, len(value) // 3))
        suffix = min(2, max(1, len(value) // 3))
    if prefix + suffix >= len(value):
        return "…"
    return f"{value[:prefix]}...{value[-suffix:]}"


def fingerprint_secret(value: str, key: bytes) -> str:
    """Return a stable keyed digest suitable for deduplication."""
    if not key:
        raise ValueError("fingerprint key must not be empty")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    if not normalized or normalized in _PLACEHOLDER_WORDS:
        return True
    if normalized.startswith(("${", "$(", "<", "{{")):
        return True
    if set(normalized) <= {"*", "x", "#", "-", "_"}:
        return True
    if any(word in normalized for word in _PLACEHOLDER_WORDS):
        return True
    if re.fullmatch(r"(?:sample|demo|test)[-_a-z0-9]*", normalized):
        return True
    return False
