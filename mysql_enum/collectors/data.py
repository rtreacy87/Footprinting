"""Table data sampling collector."""

from __future__ import annotations

from ..config import TargetConfig
from ..queries import QueryRunner
from ..utils.identifiers import quote_identifier, is_system_database
from ..utils.redaction import redact_row

HIGH_VALUE_TABLE_PATTERNS = frozenset(
    {
        "user", "users", "account", "accounts", "admin", "admins",
        "auth", "login", "credential", "credentials", "password",
        "passwords", "token", "tokens", "session", "sessions",
        "api", "apikey", "api_key", "secret", "secrets", "config",
        "configuration", "settings", "customer", "customers",
        "employee", "employees", "person", "people", "profile",
        "profiles", "payment", "invoice", "orders",
    }
)


def _is_high_value_table(name: str) -> bool:
    lower = name.lower()
    return any(pattern in lower for pattern in HIGH_VALUE_TABLE_PATTERNS)


class DataCollector:
    def __init__(self, runner: QueryRunner, config: TargetConfig) -> None:
        self._runner = runner
        self._config = config

    def collect_samples(self, tables: list[dict]) -> list[dict]:
        samples = []
        for table in tables:
            schema = table.get("table_schema", "")
            name = table.get("table_name", "")
            if is_system_database(schema):
                continue
            if not _is_high_value_table(name):
                continue
            sample = self._sample_table(schema, name)
            if sample:
                samples.append(sample)
        return samples

    def _sample_table(self, schema: str, table: str) -> dict | None:
        sql = (
            f"SELECT * FROM {quote_identifier(schema)}.{quote_identifier(table)} "
            f"LIMIT {self._config.sample_rows}"
        )
        result = self._runner.run(f"sample_{schema}_{table}", sql)
        if not result.success:
            return None
        redacted_rows = [
            redact_row(row, self._config.preserve_sensitive)
            for row in result.rows
        ]
        return {
            "database": schema,
            "table": table,
            "sample_limit": self._config.sample_rows,
            "row_count": len(redacted_rows),
            "rows": redacted_rows,
            "redactions_applied": not self._config.preserve_sensitive,
        }
