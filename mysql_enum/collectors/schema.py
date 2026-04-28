"""Database and schema enumeration collector."""

from __future__ import annotations

from ..queries import QueryRunner
from ..utils.identifiers import classify_database


class SchemaCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        databases = self._collect_databases()
        tables = self._collect_tables()
        columns = self._collect_columns()
        indexes = self._collect_indexes()
        return {
            "databases": databases,
            "tables": tables,
            "columns": columns,
            "indexes": indexes,
        }

    def _collect_databases(self) -> list[dict]:
        result = self._runner.run(
            "databases",
            "SELECT schema_name, default_character_set_name, default_collation_name "
            "FROM information_schema.schemata ORDER BY schema_name",
        )
        for row in result.rows:
            row["db_type"] = classify_database(row.get("schema_name", ""))
        return result.rows

    def _collect_tables(self) -> list[dict]:
        result = self._runner.run(
            "tables",
            "SELECT table_schema, table_name, table_type, engine, "
            "table_rows, data_length, index_length, create_time, "
            "update_time, table_collation "
            "FROM information_schema.tables "
            "ORDER BY table_schema, table_name",
        )
        return result.rows

    def _collect_columns(self) -> list[dict]:
        result = self._runner.run(
            "columns",
            "SELECT table_schema, table_name, column_name, ordinal_position, "
            "column_default, is_nullable, data_type, column_type, "
            "character_maximum_length, column_key, extra, column_comment "
            "FROM information_schema.columns "
            "ORDER BY table_schema, table_name, ordinal_position",
        )
        return result.rows

    def _collect_indexes(self) -> list[dict]:
        result = self._runner.run(
            "indexes",
            "SELECT table_schema, table_name, index_name, non_unique, "
            "seq_in_index, column_name, cardinality, index_type "
            "FROM information_schema.statistics "
            "ORDER BY table_schema, table_name, index_name, seq_in_index",
        )
        return result.rows
