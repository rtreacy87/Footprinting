"""Privilege risk analysis."""

from __future__ import annotations

DANGEROUS_PRIVILEGES = frozenset(
    {"FILE", "SUPER", "PROCESS", "CREATE USER", "GRANT OPTION", "ALL PRIVILEGES", "ALL"}
)


def parse_grants(grant_strings: list[str]) -> list[dict]:
    """Parse SHOW GRANTS output into structured dicts."""
    parsed = []
    for grant in grant_strings:
        upper = grant.upper()
        privileges: list[str] = []
        for priv in DANGEROUS_PRIVILEGES:
            if priv in upper:
                privileges.append(priv)
        parsed.append({
            "raw": grant,
            "dangerous_privileges": privileges,
            "is_dangerous": bool(privileges),
        })
    return parsed


def find_dangerous_privileges(grants: list[str]) -> list[str]:
    found = []
    for grant in grants:
        upper = grant.upper()
        for priv in DANGEROUS_PRIVILEGES:
            if priv in upper and priv not in found:
                found.append(priv)
    return found


def has_file_privilege(grants: list[str]) -> bool:
    return any("FILE" in g.upper() for g in grants)


def is_root_equivalent(identity: dict, grants: list[str]) -> bool:
    user = identity.get("login_user", "") or ""
    if user.lower().startswith("root"):
        return True
    return any("ALL PRIVILEGES" in g.upper() for g in grants)
