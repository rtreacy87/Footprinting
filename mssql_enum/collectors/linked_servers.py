"""Enumerate linked servers — a primary MSSQL pivot path."""

from __future__ import annotations

from ..queries import QueryRunner


class LinkedServerCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        servers = self._collect_linked_servers()
        return {"linked_servers": servers}

    def _collect_linked_servers(self) -> list[dict]:
        result = self._runner.run(
            "linked_servers",
            """
            SELECT
                name,
                product,
                provider,
                data_source,
                catalog,
                CAST(is_linked AS INT)               AS is_linked,
                CAST(is_remote_login_enabled AS INT)  AS is_remote_login_enabled,
                CAST(is_rpc_out_enabled AS INT)       AS is_rpc_out_enabled,
                CAST(is_data_access_enabled AS INT)   AS is_data_access_enabled
            FROM sys.servers
            WHERE is_linked = 1
            ORDER BY name
            """,
        )
        return result.rows
