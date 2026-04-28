"""Privilege table collector."""

from __future__ import annotations

from ..queries import QueryRunner


class PrivilegesCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        return {
            "global_privileges": self._try_table("mysql.user"),
            "db_privileges": self._try_table("mysql.db"),
            "table_privileges": self._try_table("mysql.tables_priv"),
            "column_privileges": self._try_table("mysql.columns_priv"),
            "processlist": self._collect_processlist(),
        }

    def _try_table(self, table: str) -> dict:
        result = self._runner.run(f"priv_{table}", f"SELECT * FROM {table}")
        if result.success:
            return {"visible": True, "rows": result.rows}
        return {"visible": False, "error": result.error}

    def _collect_processlist(self) -> dict:
        result = self._runner.run(
            "processlist",
            "SELECT * FROM information_schema.processlist",
        )
        if result.success:
            return {"visible": True, "rows": result.rows}
        return {"visible": False, "error": result.error}
