"""MSSQL connection management — pymssql with impacket-mssqlclient subprocess fallback.

pymssql/FreeTDS fails TLS negotiation on modern SQL Server (2016+).
ImpacketConnection wraps `impacket-mssqlclient -command` as a subprocess,
which implements its own TDS/TLS stack and is used automatically when pymssql
raises a ConnectionError.  One subprocess is spawned per execute() call;
this is slower than a persistent connection but reliable against any server.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from contextlib import contextmanager
from typing import Generator

import pymssql

from .config import TargetConfig


class ConnectionError(Exception):
    pass


# ---------------------------------------------------------------------------
# pymssql backend
# ---------------------------------------------------------------------------

class MSSQLConnection:
    """Wraps a pymssql connection with read-only, non-destructive defaults."""

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._conn: pymssql.Connection | None = None

    def connect(self) -> None:
        kwargs: dict = {
            "server": self._config.target,
            "port": self._config.port,
            "user": self._config.username or "",
            "password": self._config.password_value or "",
            "timeout": self._config.timeout_seconds,
            "login_timeout": self._config.timeout_seconds,
            "as_dict": True,
            "autocommit": True,
        }
        if self._config.auth_mode == "windows" and self._config.domain:
            kwargs["user"] = f"{self._config.domain}\\{self._config.username}"

        try:
            self._conn = pymssql.connect(**kwargs)
        except pymssql.OperationalError as e:
            raise ConnectionError(str(e)) from e
        except pymssql.InterfaceError as e:
            raise ConnectionError(str(e)) from e

    def execute(self, sql: str, database: str | None = None) -> tuple[list[dict], str | None]:
        """Execute SQL and return (rows, error). Never raises."""
        if self._conn is None:
            return [], "Not connected"
        try:
            cursor = self._conn.cursor()
            if database:
                cursor.execute(f"USE [{database}]")
            cursor.execute(sql)
            rows = cursor.fetchall() or []
            cursor.close()
            return list(rows), None
        except pymssql.ProgrammingError as e:
            return [], f"ProgrammingError: {e}"
        except pymssql.OperationalError as e:
            return [], f"OperationalError: {e}"
        except pymssql.DatabaseError as e:
            return [], f"DatabaseError: {e}"
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


# ---------------------------------------------------------------------------
# impacket-mssqlclient subprocess backend
# ---------------------------------------------------------------------------

class ImpacketConnection:
    """Execute SQL via `impacket-mssqlclient -command` subprocess.

    Spawns one subprocess per execute() call.  Slower than a persistent
    connection (~3-8 s overhead per call) but handles any SQL Server TLS
    configuration without FreeTDS compatibility issues.

    Rows are returned as list[dict[column_name, value]], matching the
    MSSQLConnection.execute() contract so QueryRunner works unchanged.
    """

    _BINARY = "impacket-mssqlclient"

    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._available: bool = False

    @classmethod
    def binary_available(cls) -> bool:
        return shutil.which(cls._BINARY) is not None

    def connect(self) -> None:
        if not self.binary_available():
            raise ConnectionError(f"{self._BINARY} not found in PATH")
        # Verify credentials with a lightweight query.
        rows, err = self.execute("SELECT 1 AS connected")
        if err is not None:
            raise ConnectionError(f"impacket auth check failed: {err}")
        self._available = True

    def execute(self, sql: str, database: str | None = None) -> tuple[list[dict], str | None]:
        """Run one SQL statement via subprocess and parse the output."""
        user = self._config.username or ""
        pwd = self._config.password_value or ""
        target_arg = f"{user}:{pwd}@{self._config.target}"

        cmd = [self._BINARY, target_arg, "-port", str(self._config.port)]
        if self._config.auth_mode == "windows":
            cmd += ["-windows-auth"]
        if database:
            cmd += ["-db", database]
        cmd += ["-command", sql]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = proc.stdout + proc.stderr

            if "Login failed" in output or "Authentication failed" in output:
                return [], f"Authentication failed"

            rows = _parse_impacket_output(output)
            return rows, None
        except subprocess.TimeoutExpired:
            return [], "Subprocess timeout (60s)"
        except FileNotFoundError:
            return [], f"{self._BINARY} not found"
        except Exception as e:
            return [], str(e)

    def close(self) -> None:
        pass  # no persistent connection to close

    def is_connected(self) -> bool:
        return self._available


# ---------------------------------------------------------------------------
# Output parser for impacket-mssqlclient tabular format
# ---------------------------------------------------------------------------

_SEP_RE = re.compile(r"^-+(\s+-+)*\s*$")


def _col_ranges(sep_line: str) -> list[tuple[int, int | None]]:
    """Return (start, end) column slices derived from the separator row.

    Example separator: "--------   --------   ------"
    Produces:          [(0, 11), (11, 22), (22, None)]
    The last column extends to end-of-line (end=None).
    """
    starts: list[int] = []
    in_dash = False
    for i, ch in enumerate(sep_line):
        if ch == "-" and not in_dash:
            starts.append(i)
            in_dash = True
        elif ch == " " and in_dash:
            in_dash = False
    ranges: list[tuple[int, int | None]] = []
    for i, s in enumerate(starts):
        e: int | None = starts[i + 1] if i + 1 < len(starts) else None
        ranges.append((s, e))
    return ranges


def _extract_value(line: str, start: int, end: int | None) -> str | None:
    val = (line[start:end] if end else line[start:]).strip() if start < len(line) else ""
    return None if val.upper() == "NULL" else (val or None)


def _parse_impacket_output(output: str) -> list[dict]:
    """Parse the column-aligned tabular output of impacket-mssqlclient."""
    lines = output.splitlines()
    rows: list[dict] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        next_line = lines[i + 1] if i + 1 < len(lines) else ""

        # Skip metadata / prompt lines
        stripped = line.strip()
        if (not stripped
                or stripped.startswith("[")
                or stripped.startswith("SQL (")
                or stripped.startswith("Impacket")
                or stripped.startswith("(") and "row" in stripped.lower()):
            i += 1
            continue

        # Detect header + separator pair
        if next_line.strip() and _SEP_RE.match(next_line.rstrip()):
            col_spec = _col_ranges(next_line)
            headers = [
                (line[s:e] if e else line[s:]).strip() if s < len(line) else f"col{k}"
                for k, (s, e) in enumerate(col_spec)
            ]
            j = i + 2
            while j < len(lines):
                data = lines[j]
                ds = data.strip()
                if (not ds
                        or ds.startswith("[")
                        or ds.startswith("SQL (")
                        or ds.startswith("Impacket")
                        or (ds.startswith("(") and "row" in ds.lower())):
                    j += 1
                    if not ds:
                        break  # blank line ends result set
                    continue
                row = {
                    headers[k]: _extract_value(data, s, e)
                    for k, (s, e) in enumerate(col_spec)
                    if k < len(headers)
                }
                rows.append(row)
                j += 1
            i = j
        else:
            i += 1

    return rows


# ---------------------------------------------------------------------------
# Connection factory — tries pymssql then impacket subprocess
# ---------------------------------------------------------------------------

def _open_best(config: TargetConfig) -> MSSQLConnection | ImpacketConnection:
    """Return a connected backend: pymssql first, impacket subprocess fallback."""
    try:
        conn = MSSQLConnection(config)
        conn.connect()
        return conn
    except ConnectionError:
        pass

    conn = ImpacketConnection(config)
    conn.connect()   # raises ConnectionError if this also fails
    return conn


@contextmanager
def open_connection(config: TargetConfig) -> Generator:
    conn = _open_best(config)
    try:
        yield conn
    finally:
        conn.close()
