"""Redaction utilities for sensitive column values."""

import hashlib

SENSITIVE_COLUMN_PATTERNS = frozenset(
    {
        "password",
        "passwd",
        "pass_hash",
        "hash",
        "salt",
        "token",
        "api_key",
        "secret",
        "private_key",
        "session",
        "cookie",
        "reset",
        "access_token",
        "refresh_token",
    }
)


def is_sensitive_column(column_name: str) -> bool:
    lower = column_name.lower()
    return any(pattern in lower for pattern in SENSITIVE_COLUMN_PATTERNS)


def redact_value(value: str) -> str:
    if not value:
        return value
    digest = hashlib.sha256(str(value).encode()).hexdigest()[:12]
    return f"<redacted:sha256={digest}>"


def redact_row(row: dict, preserve: bool = False) -> dict:
    if preserve:
        return row
    return {
        k: redact_value(str(v)) if v is not None and is_sensitive_column(k) else v
        for k, v in row.items()
    }
