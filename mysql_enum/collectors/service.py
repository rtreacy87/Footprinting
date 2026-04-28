"""Service identity and version collector."""

from __future__ import annotations

from ..queries import QueryRunner


class ServiceCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        identity = self._collect_identity()
        version_vars = self._collect_version_vars()
        return {
            "identity": identity,
            "version_variables": version_vars,
        }

    def _collect_identity(self) -> dict:
        result = self._runner.run(
            "identity",
            "SELECT USER() AS login_user, CURRENT_USER() AS effective_user, "
            "DATABASE() AS current_database, @@hostname AS server_hostname, "
            "@@version AS version, @@version_comment AS version_comment, "
            "@@port AS port, @@datadir AS datadir, @@basedir AS basedir",
        )
        return result.rows[0] if result.rows else {}

    def _collect_version_vars(self) -> list[dict]:
        result = self._runner.run(
            "version_variables",
            "SHOW VARIABLES LIKE 'version%'",
        )
        return result.rows
