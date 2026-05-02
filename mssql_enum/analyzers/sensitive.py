"""Classify sensitive table and column names by keyword matching."""

from __future__ import annotations

SENSITIVE_KEYWORDS = {
    "user", "account", "login", "password", "passwd", "pwd", "hash",
    "token", "secret", "key", "apikey", "api_key", "connection", "connstr",
    "credential", "session", "jwt", "oauth", "saml", "ldap", "ad", "domain",
    "employee", "customer", "payment", "card", "ssn", "dob", "email", "phone",
}


def find_sensitive_columns(columns: list[dict]) -> list[dict]:
    """Return columns whose name contains a sensitive keyword."""
    results = []
    for col in columns:
        name = col.get("column_name", "").lower()
        matched = [kw for kw in SENSITIVE_KEYWORDS if kw in name]
        if matched:
            results.append({**col, "matched_keywords": matched})
    return results


def find_sensitive_tables(tables: list[dict]) -> list[dict]:
    """Return tables whose name contains a sensitive keyword."""
    results = []
    for tbl in tables:
        name = tbl.get("table_name", "").lower()
        matched = [kw for kw in SENSITIVE_KEYWORDS if kw in name]
        if matched:
            results.append({**tbl, "matched_keywords": matched})
    return results
