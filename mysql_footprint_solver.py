#!/usr/bin/env python3
"""MySQL footprinting lab solver.

Questions answered:
  Q1: Enumerate the MySQL server and determine the version in use.
      Format: MySQL X.X.XX
  Q2: Using credentials "robin:robin", what is the email address of customer "Otto Lang"?
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from pydantic import SecretStr

sys.path.insert(0, str(Path(__file__).parent))

from mysql_enum.config import TargetConfig
from mysql_enum.connection import open_connection, ConnectionError
from mysql_enum.enumerator import MySQLEnumerator
from mysql_enum.queries import QueryRunner


TARGET = "10.129.42.195"
PORT = 3306


def get_version(target: str, port: int) -> str:
    """Phase 1: discover version via unauthenticated nmap + anonymous connection attempt."""
    print(f"[*] Probing {target}:{port} for version ...", file=sys.stderr)

    config = TargetConfig(
        target=target,
        port=port,
        output_dir=Path("output"),
    )
    enumerator = MySQLEnumerator(config)
    result = enumerator.run_discover()

    if not result.reachable:
        print(f"[-] Host unreachable: {result.error}", file=sys.stderr)
        return "UNREACHABLE"

    nmap = result.nmap if hasattr(result, "nmap") else {}
    nmap_out = nmap.get("stdout", "") if isinstance(nmap, dict) else ""

    version = _parse_version_from_nmap(nmap_out)
    if version:
        print(f"[+] Version from nmap: {version}", file=sys.stderr)
        return version

    version = _version_from_connection(target, port)
    return version


def _parse_version_from_nmap(nmap_output: str) -> str | None:
    import re
    patterns = [
        r"Version:\s+([\d.]+\S*)",
        r"mysql-info.*?Version:\s+([\d.]+\S*)",
        r"\d+/tcp\s+open\s+\S+\s+MySQL\s+([\d.]+\S*)",
        r"(\d+\.\d+\.\d+[^\s|]*)",
    ]
    for pattern in patterns:
        m = re.search(pattern, nmap_output, re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


def _version_from_connection(target: str, port: int) -> str:
    """Try anonymous connection just for version banner."""
    config = TargetConfig(
        target=target,
        port=port,
        username="",
        password=SecretStr(""),
        output_dir=Path("output"),
    )
    try:
        with open_connection(config) as conn:
            runner = QueryRunner(conn)
            r = runner.run("version", "SELECT @@version AS version")
            if r.rows:
                return r.rows[0].get("version", "UNKNOWN")
    except ConnectionError:
        pass

    print("[*] Trying version via robin:robin for Q1 fallback ...", file=sys.stderr)
    config2 = TargetConfig(
        target=target,
        port=port,
        username="robin",
        password=SecretStr("robin"),
        output_dir=Path("output"),
    )
    try:
        with open_connection(config2) as conn:
            runner = QueryRunner(conn)
            r = runner.run("version", "SELECT @@version AS version")
            if r.rows:
                return r.rows[0].get("version", "UNKNOWN")
    except ConnectionError as e:
        print(f"[-] Connection error: {e}", file=sys.stderr)

    return "UNKNOWN"


def get_otto_lang_email(target: str, port: int) -> str:
    """Phase 2: authenticate as robin:robin and find Otto Lang's email."""
    print(f"[*] Connecting as robin:robin to find Otto Lang's email ...", file=sys.stderr)

    config = TargetConfig(
        target=target,
        port=port,
        username="robin",
        password=SecretStr("robin"),
        output_dir=Path("output"),
    )

    try:
        with open_connection(config) as conn:
            runner = QueryRunner(conn)

            # List accessible databases
            db_result = runner.run("databases", "SHOW DATABASES")
            databases = [list(r.values())[0] for r in db_result.rows]
            print(f"[+] Databases: {databases}", file=sys.stderr)

            # Search each non-system database for a customer/user table with Otto Lang
            system_dbs = {"information_schema", "mysql", "performance_schema", "sys"}
            for db in databases:
                if db.lower() in system_dbs:
                    continue
                email = _search_database_for_otto(runner, db)
                if email:
                    return email

    except ConnectionError as e:
        print(f"[-] Authentication failed: {e}", file=sys.stderr)
        return "AUTH_FAILED"

    return "NOT_FOUND"


def _search_database_for_otto(runner: QueryRunner, db: str) -> str | None:
    from mysql_enum.utils.identifiers import quote_identifier

    tables_result = runner.run(f"tables_{db}", f"SHOW TABLES FROM {quote_identifier(db)}")
    tables = [list(r.values())[0] for r in tables_result.rows]
    print(f"  [*] Database '{db}' tables: {tables}", file=sys.stderr)

    for table in tables:
        columns_result = runner.run(
            f"cols_{db}_{table}",
            f"SHOW COLUMNS FROM {quote_identifier(db)}.{quote_identifier(table)}",
        )
        col_names = [list(r.values())[0].lower() for r in columns_result.rows if r]

        has_name = any(c in col_names for c in ["name", "first_name", "last_name", "full_name", "username"])
        has_email = any("email" in c for c in col_names)

        print(f"  [*] Searching '{db}.{table}' for Otto Lang ...", file=sys.stderr)
        email = _query_table_for_otto(runner, db, table, col_names)
        if email:
            print(f"[+] Found in '{db}.{table}'", file=sys.stderr)
            return email

    return None


def _query_table_for_otto(runner: QueryRunner, db: str, table: str, col_names: list[str]) -> str | None:
    from mysql_enum.utils.identifiers import quote_identifier

    db_q = quote_identifier(db)
    tbl_q = quote_identifier(table)

    # Try combined name columns
    name_queries = []
    if "name" in col_names:
        name_queries.append(f"name LIKE '%Otto%Lang%' OR name LIKE '%Otto Lang%'")
    if "first_name" in col_names and "last_name" in col_names:
        name_queries.append("(first_name = 'Otto' AND last_name = 'Lang')")
    if "full_name" in col_names:
        name_queries.append("full_name LIKE '%Otto%Lang%'")
    if "username" in col_names:
        name_queries.append("username LIKE '%otto%' OR username LIKE '%lang%'")

    if not name_queries:
        # Fall back to selecting all rows and filtering
        result = runner.run(
            f"scan_{db}_{table}",
            f"SELECT * FROM {db_q}.{tbl_q} LIMIT 500",
        )
        for row in result.rows:
            row_str = " ".join(str(v) for v in row.values()).lower()
            if "otto" in row_str and "lang" in row_str:
                email = _extract_email_from_row(row)
                if email:
                    return email
        return None

    where = " OR ".join(f"({q})" for q in name_queries)
    result = runner.run(
        f"otto_{db}_{table}",
        f"SELECT * FROM {db_q}.{tbl_q} WHERE {where}",
    )

    if not result.success or not result.rows:
        # full scan fallback
        result = runner.run(
            f"scan_{db}_{table}",
            f"SELECT * FROM {db_q}.{tbl_q} LIMIT 1000",
        )
        for row in result.rows:
            vals = " ".join(str(v) for v in row.values()).lower()
            if "otto" in vals and "lang" in vals:
                return _extract_email_from_row(row)
        return None

    for row in result.rows:
        email = _extract_email_from_row(row)
        if email:
            return email

    return None


def _extract_email_from_row(row: dict) -> str | None:
    for k, v in row.items():
        if "email" in k.lower() and v:
            return str(v)
    # Fallback: find any value that looks like an email
    import re
    for v in row.values():
        if v and re.match(r"[^@]+@[^@]+\.[^@]+", str(v)):
            return str(v)
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solve the HTB MySQL footprinting lab.")
    parser.add_argument("--target", default=TARGET, help="Target IP (default: %(default)s)")
    parser.add_argument("--port", type=int, default=PORT, help="MySQL port (default: %(default)s)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = args.target
    port = args.port

    print(f"\n=== MySQL Lab Solver — target {target}:{port} ===\n")

    # Q1: Version
    version = get_version(target, port)
    if not version.upper().startswith("MYSQL") and version not in ("UNKNOWN", "UNREACHABLE"):
        version_display = f"MySQL {version}"
    elif version in ("UNKNOWN", "UNREACHABLE"):
        version_display = version
    else:
        version_display = version

    print(f"\nQ1 — MySQL version:            {version_display}")

    # Q2: Otto Lang email
    email = get_otto_lang_email(target, port)
    print(f"Q2 — Otto Lang's email:        {email}")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
