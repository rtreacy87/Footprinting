"""Collect server identity, version, and configuration."""

from __future__ import annotations

from ..queries import QueryRunner


class ServerInfoCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        identity = self._collect_identity()
        auth_context = self._collect_auth_context()
        config = self._collect_config()
        return {
            "identity": identity,
            "auth_context": auth_context,
            "config": config,
        }

    def _collect_identity(self) -> dict:
        result = self._runner.run(
            "server_identity",
            """
            SELECT
                SERVERPROPERTY('MachineName')    AS machine_name,
                SERVERPROPERTY('ServerName')     AS server_name,
                SERVERPROPERTY('InstanceName')   AS instance_name,
                SERVERPROPERTY('Edition')        AS edition,
                SERVERPROPERTY('ProductVersion') AS product_version,
                SERVERPROPERTY('ProductLevel')   AS product_level,
                @@VERSION                        AS full_version,
                @@SERVERNAME                     AS server_name_var
            """,
        )
        return result.rows[0] if result.rows else {}

    def _collect_auth_context(self) -> dict:
        result = self._runner.run(
            "auth_context",
            """
            SELECT
                SYSTEM_USER                  AS system_user,
                CURRENT_USER                 AS current_user,
                ORIGINAL_LOGIN()             AS original_login,
                SUSER_SNAME()                AS suser_name,
                IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin,
                DB_NAME()                    AS current_database
            """,
        )
        return result.rows[0] if result.rows else {}

    def _collect_config(self) -> list[dict]:
        result = self._runner.run(
            "server_config",
            """
            SELECT
                name,
                value,
                value_in_use,
                description,
                is_dynamic,
                is_advanced
            FROM sys.configurations
            ORDER BY name
            """,
        )
        return result.rows
