"""Oracle database connection wrapper using oracledb in thick mode.

Oracle XE 11g requires thick mode (Oracle Instant Client).
Instant Client must be at the path specified in oracle_client_lib.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

_THICK_INITIALIZED = False


def ensure_thick_mode(lib_dir: str) -> None:
    global _THICK_INITIALIZED
    if not _THICK_INITIALIZED:
        import oracledb
        oracledb.init_oracle_client(lib_dir=lib_dir)
        _THICK_INITIALIZED = True


class OracleConnectionError(Exception):
    pass


class OracleConnection:
    """Thin wrapper around oracledb connection for safe, read-oriented queries."""

    def __init__(
        self,
        host: str,
        port: int,
        sid: str | None = None,
        service_name: str | None = None,
        username: str = "",
        password: str = "",
        sysdba: bool = False,
        lib_dir: str = "/usr/lib/oracle/19.6/client64/lib",
    ) -> None:
        ensure_thick_mode(lib_dir)
        import oracledb

        if sid:
            dsn = oracledb.makedsn(host, port, sid=sid)
        elif service_name:
            dsn = oracledb.makedsn(host, port, service_name=service_name)
        else:
            raise OracleConnectionError("Either sid or service_name must be provided")

        mode = oracledb.AUTH_MODE_SYSDBA if sysdba else oracledb.AUTH_MODE_DEFAULT
        try:
            self._conn = oracledb.connect(user=username, password=password, dsn=dsn, mode=mode)
        except Exception as e:
            raise OracleConnectionError(str(e)) from e

    def query(self, sql: str) -> list[dict]:
        """Execute a SELECT and return rows as list[dict]."""
        cursor = self._conn.cursor()
        try:
            cursor.execute(sql)
            cols = [d[0].lower() for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
        except Exception as e:
            raise OracleConnectionError(str(e)) from e
        finally:
            cursor.close()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self) -> "OracleConnection":
        return self

    def __exit__(self, *_) -> None:
        self.close()


@contextmanager
def oracle_connect(
    host: str,
    port: int,
    username: str,
    password: str,
    sid: str | None = None,
    service_name: str | None = None,
    sysdba: bool = False,
    lib_dir: str = "/usr/lib/oracle/19.6/client64/lib",
) -> Generator[OracleConnection, None, None]:
    conn = OracleConnection(
        host=host,
        port=port,
        sid=sid,
        service_name=service_name,
        username=username,
        password=password,
        sysdba=sysdba,
        lib_dir=lib_dir,
    )
    try:
        yield conn
    finally:
        conn.close()
