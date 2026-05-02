"""Collect server and database logins, roles, and role memberships."""

from __future__ import annotations

from ..queries import QueryRunner

PRIVILEGED_ROLES = {
    "sysadmin", "serveradmin", "securityadmin", "setupadmin",
    "processadmin", "diskadmin", "dbcreator", "bulkadmin",
}


class PrincipalsCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        logins = self._collect_logins()
        role_memberships = self._collect_role_memberships()
        privileged = self._extract_privileged(role_memberships)
        return {
            "logins": logins,
            "role_memberships": role_memberships,
            "privileged_members": privileged,
        }

    def _collect_logins(self) -> list[dict]:
        result = self._runner.run(
            "server_logins",
            """
            SELECT
                name,
                type_desc,
                CAST(is_disabled AS INT)       AS is_disabled,
                CONVERT(VARCHAR(30), create_date, 120) AS create_date,
                CONVERT(VARCHAR(30), modify_date, 120) AS modify_date,
                default_database_name
            FROM sys.server_principals
            WHERE type IN ('S', 'U', 'G')
            ORDER BY name
            """,
        )
        return result.rows

    def _collect_role_memberships(self) -> list[dict]:
        result = self._runner.run(
            "role_memberships",
            """
            SELECT
                roles.name   AS role_name,
                members.name AS member_name,
                members.type_desc AS member_type
            FROM sys.server_role_members srm
            JOIN sys.server_principals roles
                ON srm.role_principal_id = roles.principal_id
            JOIN sys.server_principals members
                ON srm.member_principal_id = members.principal_id
            ORDER BY roles.name, members.name
            """,
        )
        return result.rows

    def _extract_privileged(self, memberships: list[dict]) -> list[dict]:
        return [
            m for m in memberships
            if m.get("role_name", "").lower() in PRIVILEGED_ROLES
        ]
