from __future__ import annotations
import re


def is_valid_ip(value: str) -> bool:
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(pattern, value))


def is_valid_port(value: int) -> bool:
    return 1 <= value <= 65535


def is_valid_sid(value: str) -> bool:
    return bool(value) and len(value) <= 30
