"""Query execution with structured logging."""

from __future__ import annotations

from datetime import datetime, timezone

from .config import QueryResult
from .connection import MSSQLConnection


class QueryRunner:
    """Runs named queries and records an immutable log."""

    def __init__(self, conn: MSSQLConnection) -> None:
        self._conn = conn
        self._log: list[QueryResult] = []

    def run(self, name: str, sql: str, database: str | None = None) -> QueryResult:
        started = datetime.now(timezone.utc)
        rows, error = self._conn.execute(sql, database=database)
        finished = datetime.now(timezone.utc)
        result = QueryResult(
            query_name=name,
            sql=sql,
            success=error is None,
            rows=rows,
            error=error,
            started_at=started,
            finished_at=finished,
        )
        self._log.append(result)
        return result

    def log(self) -> list[QueryResult]:
        return list(self._log)
