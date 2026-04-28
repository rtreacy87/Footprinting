"""MySQL connection management."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

import pymysql
import pymysql.cursors

from .config import TargetConfig


class ConnectionError(Exception):
    pass


class MySQLConnection:
    """Wraps a pymysql connection with safe defaults."""

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._conn: pymysql.Connection | None = None

    def connect(self) -> None:
        kwargs: dict = {
            "host": self._config.target,
            "port": self._config.port,
            "user": self._config.username or "",
            "password": self._config.password_value or "",
            "database": self._config.database,
            "connect_timeout": self._config.timeout_seconds,
            "cursorclass": pymysql.cursors.DictCursor,
            "autocommit": True,
        }
        if self._config.ssl_mode == "required":
            kwargs["ssl"] = {"verify_cert": True}

        try:
            self._conn = pymysql.connect(**kwargs)
        except pymysql.err.OperationalError as e:
            raise ConnectionError(str(e)) from e

        self._apply_session_settings()

    def _apply_session_settings(self) -> None:
        for sql in [
            "SET SESSION group_concat_max_len = 1000000",
        ]:
            try:
                self._execute_raw(sql)
            except Exception:
                pass

    def _execute_raw(self, sql: str) -> list[dict]:
        if self._conn is None:
            raise ConnectionError("Not connected")
        with self._conn.cursor() as cursor:
            cursor.execute(sql)
            result = cursor.fetchall()
            return list(result) if result else []

    def execute(self, sql: str) -> tuple[list[dict], str | None]:
        """Execute SQL and return (rows, error). Never raises."""
        if self._conn is None:
            return [], "Not connected"
        try:
            rows = self._execute_raw(sql)
            return rows, None
        except pymysql.err.ProgrammingError as e:
            return [], f"ProgrammingError: {e}"
        except pymysql.err.OperationalError as e:
            return [], f"OperationalError: {e}"
        except pymysql.err.InternalError as e:
            return [], f"InternalError: {e}"
        except Exception as e:
            return [], str(e)

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def is_connected(self) -> bool:
        return self._conn is not None


@contextmanager
def open_connection(config: TargetConfig) -> Generator[MySQLConnection, None, None]:
    conn = MySQLConnection(config)
    try:
        conn.connect()
        yield conn
    finally:
        conn.close()
