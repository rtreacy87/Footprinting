"""User and role enumeration collector."""

from __future__ import annotations

from ..queries import QueryRunner


class UsersCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        grants = self._collect_grants()
        users = self._collect_users()
        roles = self._collect_roles()
        return {
            "grants": grants,
            "users": users,
            "roles": roles,
        }

    def _collect_grants(self) -> list[str]:
        result = self._runner.run("current_grants", "SHOW GRANTS FOR CURRENT_USER()")
        return [list(row.values())[0] for row in result.rows if row]

    def _collect_users(self) -> dict:
        result = self._runner.run(
            "mysql_users",
            "SELECT user, host, account_locked, password_expired, plugin "
            "FROM mysql.user ORDER BY user, host",
        )
        if result.success:
            return {"visible": True, "rows": result.rows}

        fallback = self._runner.run(
            "mysql_users_fallback",
            "SELECT user, host FROM mysql.user ORDER BY user, host",
        )
        if fallback.success:
            return {"visible": True, "rows": fallback.rows}

        return {"visible": False, "error": result.error}

    def _collect_roles(self) -> dict:
        role_edges = self._runner.run(
            "role_edges",
            "SELECT * FROM mysql.role_edges",
        )
        default_roles = self._runner.run(
            "default_roles",
            "SELECT * FROM mysql.default_roles",
        )
        return {
            "role_edges": role_edges.rows if role_edges.success else [],
            "default_roles": default_roles.rows if default_roles.success else [],
            "error": role_edges.error if not role_edges.success else None,
        }
