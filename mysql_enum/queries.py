"""Query execution with logging."""

from __future__ import annotations

from datetime import datetime, timezone

from .config import QueryResult
from .connection import MySQLConnection


class QueryRunner:
    """Runs named queries and records results in a log."""

    def __init__(self, conn: MySQLConnection) -> None:
        self._conn = conn
        self._log: list[QueryResult] = []

    def run(self, name: str, sql: str) -> QueryResult:
        started = datetime.now(timezone.utc)
        rows, error = self._conn.execute(sql)
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
