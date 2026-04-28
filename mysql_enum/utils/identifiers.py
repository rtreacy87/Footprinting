"""Utilities for safe SQL identifier handling."""

import re

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_$]+$")

SYSTEM_DATABASES = frozenset(
    {"information_schema", "mysql", "performance_schema", "sys"}
)


def is_safe_identifier(name: str) -> bool:
    return bool(_SAFE_IDENTIFIER.match(name))


def quote_identifier(name: str) -> str:
    escaped = name.replace("`", "``")
    return f"`{escaped}`"


def is_system_database(name: str) -> bool:
    return name.lower() in SYSTEM_DATABASES


def classify_database(name: str) -> str:
    return "system" if is_system_database(name) else "application"
