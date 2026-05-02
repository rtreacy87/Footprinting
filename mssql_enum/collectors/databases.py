"""Collect database inventory and per-database schema metadata."""

from __future__ import annotations

from ..queries import QueryRunner

SYSTEM_DATABASES = {"master", "model", "msdb", "tempdb", "resource"}


class DatabaseCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        all_databases = self._collect_databases()
        non_default = [
            db for db in all_databases
            if db.get("name", "").lower() not in SYSTEM_DATABASES
        ]
        schemas = self._collect_schemas(non_default)
        tables = self._collect_tables(non_default)
        columns = self._collect_columns(non_default)
        return {
            "databases": all_databases,
            "non_default_databases": non_default,
            "schemas": schemas,
            "tables": tables,
            "columns": columns,
        }

    def _collect_databases(self) -> list[dict]:
        result = self._runner.run(
            "databases",
            """
            SELECT
                name,
                database_id,
                CONVERT(VARCHAR(30), create_date, 120) AS create_date,
                state_desc,
                recovery_model_desc,
                containment_desc,
                CAST(is_read_only AS INT)       AS is_read_only,
                CAST(is_trustworthy_on AS INT)  AS is_trustworthy_on
            FROM sys.databases
            ORDER BY name
            """,
        )
        return result.rows

    def _collect_schemas(self, databases: list[dict]) -> list[dict]:
        all_schemas: list[dict] = []
        for db in databases:
            db_name = db.get("name", "")
            result = self._runner.run(
                f"schemas_{db_name}",
                """
                SELECT
                    SCHEMA_NAME AS schema_name,
                    SCHEMA_OWNER AS schema_owner
                FROM INFORMATION_SCHEMA.SCHEMATA
                ORDER BY SCHEMA_NAME
                """,
                database=db_name,
            )
            for row in result.rows:
                row["database"] = db_name
            all_schemas.extend(result.rows)
        return all_schemas

    def _collect_tables(self, databases: list[dict]) -> list[dict]:
        all_tables: list[dict] = []
        for db in databases:
            db_name = db.get("name", "")
            result = self._runner.run(
                f"tables_{db_name}",
                """
                SELECT
                    TABLE_SCHEMA AS table_schema,
                    TABLE_NAME   AS table_name,
                    TABLE_TYPE   AS table_type
                FROM INFORMATION_SCHEMA.TABLES
                ORDER BY TABLE_SCHEMA, TABLE_NAME
                """,
                database=db_name,
            )
            for row in result.rows:
                row["database"] = db_name
            all_tables.extend(result.rows)
        return all_tables

    def _collect_columns(self, databases: list[dict]) -> list[dict]:
        all_columns: list[dict] = []
        for db in databases:
            db_name = db.get("name", "")
            result = self._runner.run(
                f"columns_{db_name}",
                """
                SELECT
                    TABLE_SCHEMA             AS table_schema,
                    TABLE_NAME               AS table_name,
                    COLUMN_NAME              AS column_name,
                    DATA_TYPE                AS data_type,
                    CHARACTER_MAXIMUM_LENGTH AS max_length,
                    IS_NULLABLE              AS is_nullable
                FROM INFORMATION_SCHEMA.COLUMNS
                ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION
                """,
                database=db_name,
            )
            for row in result.rows:
                row["database"] = db_name
            all_columns.extend(result.rows)
        return all_columns
