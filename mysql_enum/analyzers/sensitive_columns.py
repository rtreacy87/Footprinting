"""Sensitive column detection."""

from __future__ import annotations

from ..utils.redaction import is_sensitive_column

SENSITIVE_TABLE_PATTERNS = frozenset(
    {
        "user", "users", "account", "accounts", "admin", "admins",
        "auth", "login", "credential", "credentials", "password",
        "passwords", "token", "tokens", "session", "sessions",
        "api_key", "secret", "secrets",
    }
)


def find_sensitive_columns(columns: list[dict]) -> list[dict]:
    """Return columns flagged as likely sensitive."""
    flagged = []
    for col in columns:
        col_name = col.get("column_name", "")
        table_name = col.get("table_name", "")
        if is_sensitive_column(col_name):
            flagged.append({
                "database": col.get("table_schema"),
                "table": table_name,
                "column": col_name,
                "data_type": col.get("data_type"),
                "reason": "sensitive column name pattern",
            })
    return flagged


def find_high_value_tables(tables: list[dict]) -> list[dict]:
    """Return tables likely to contain sensitive data."""
    flagged = []
    for t in tables:
        name = t.get("table_name", "").lower()
        if any(pat in name for pat in SENSITIVE_TABLE_PATTERNS):
            flagged.append({
                "database": t.get("table_schema"),
                "table": t.get("table_name"),
                "rows": t.get("table_rows"),
                "reason": "table name matches high-value pattern",
            })
    return flagged
