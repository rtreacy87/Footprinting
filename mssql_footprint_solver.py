#!/usr/bin/env python3
"""MSSQL footprinting lab solver.

Questions answered:
  Q1: Enumerate the target — list the hostname of the MSSQL server.
  Q2: Connect as backdoor:Password1 and list the non-default database present.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from pydantic import SecretStr

sys.path.insert(0, str(Path(__file__).parent))

from mssql_enum.config import TargetConfig
from mssql_enum.connection import open_connection, ImpacketConnection, ConnectionError
from mssql_enum.queries import QueryRunner
from mssql_enum.enumerator import MSSQLEnumerator
from mssql_enum.collectors.databases import SYSTEM_DATABASES

TARGET = "10.129.201.248"
PORT = 1433


# ---------------------------------------------------------------------------
# Q1: Discover the server hostname
# ---------------------------------------------------------------------------

def get_hostname(target: str, port: int) -> str:
    """Phase 1: resolve hostname via nmap NTLM probe then SQL fallback."""
    print(f"[*] Probing {target}:{port} for MSSQL hostname ...", file=sys.stderr)

    hostname = _hostname_from_nmap(target, port)
    if hostname:
        print(f"[+] Hostname from nmap: {hostname}", file=sys.stderr)
        return hostname

    print("[*] Nmap probe inconclusive, trying SQL connection ...", file=sys.stderr)
    hostname = _hostname_from_sql(target, port)
    return hostname


def _hostname_from_nmap(target: str, port: int) -> str | None:
    """Run nmap mssql NSE scripts and parse the machine name."""
    import re

    nmap_cmd = [
        "nmap", "-p", str(port),
        "--script", "ms-sql-info,ms-sql-ntlm-info,ms-sql-config",
        "-Pn", "-sV",
        "--script-timeout", "15s",
        target,
    ]
    try:
        proc = subprocess.run(
            nmap_cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = proc.stdout + proc.stderr
        _save_nmap_output(target, output)

        # ms-sql-ntlm-info leaks the NetBIOS machine name before auth
        patterns = [
            r"NetBIOS_Computer_Name:\s*(\S+)",
            r"Target_Name:\s*(\S+)",
            r"DNS_Computer_Name:\s*(\S+)",
            r"Machine Name:\s*(\S+)",
            r"MachineName:\s*(\S+)",
        ]
        for pat in patterns:
            m = re.search(pat, output, re.IGNORECASE)
            if m:
                return m.group(1).strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def _save_nmap_output(target: str, output: str) -> None:
    out_path = Path("output") / "mssql" / target / "raw" / "nmap_mssql.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(output, encoding="utf-8")


def _hostname_from_sql(target: str, port: int, username: str = "backdoor", password: str = "Password1") -> str:
    """Connect and query SERVERPROPERTY('MachineName'); auto-falls back to impacket."""
    config = TargetConfig(
        target=target,
        port=port,
        username=username,
        password=SecretStr(password),
        auth_mode="windows",
        output_dir=Path("output"),
    )
    try:
        with open_connection(config) as conn:
            runner = QueryRunner(conn)
            result = runner.run(
                "machine_name",
                "SELECT SERVERPROPERTY('MachineName') AS machine_name",
            )
            if result.rows:
                return str(result.rows[0].get("machine_name", "UNKNOWN"))
    except ConnectionError as e:
        print(f"[-] SQL connection failed: {e}", file=sys.stderr)
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Q2: List non-default databases via backdoor:Password1
# ---------------------------------------------------------------------------

def get_non_default_databases(target: str, port: int) -> list[str]:
    """Phase 2: authenticate as backdoor:Password1 (Windows auth) and list user databases."""
    print(f"[*] Connecting as backdoor:Password1 (Windows auth) to list databases ...", file=sys.stderr)

    config = TargetConfig(
        target=target,
        port=port,
        username="backdoor",
        password=SecretStr("Password1"),
        auth_mode="windows",
        output_dir=Path("output"),
    )

    try:
        with open_connection(config) as conn:
            backend = "impacket" if isinstance(conn, ImpacketConnection) else "pymssql"
            print(f"[+] Connected via {backend}", file=sys.stderr)
            runner = QueryRunner(conn)
            result = runner.run(
                "databases",
                "SELECT name FROM sys.databases WHERE state_desc = 'ONLINE' ORDER BY name",
            )
            all_dbs = [row["name"] for row in result.rows]
            print(f"[+] All databases: {all_dbs}", file=sys.stderr)
            non_default = [db for db in all_dbs if db.lower() not in SYSTEM_DATABASES]
            return non_default
    except ConnectionError as e:
        print(f"[-] Connection failed: {e}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# Full enumeration (optional)
# ---------------------------------------------------------------------------

def run_full_enum(target: str, port: int) -> None:
    config = TargetConfig(
        target=target,
        port=port,
        username="backdoor",
        password=SecretStr("Password1"),
        auth_mode="windows",
        output_dir=Path("output"),
    )
    enumerator = MSSQLEnumerator(config)
    result = enumerator.run_enum()
    print(f"[*] Full enumeration complete. Artifacts in output/mssql/{target}/", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solve the HTB MSSQL footprinting lab.")
    parser.add_argument("--target", default=TARGET, help="Target IP (default: %(default)s)")
    parser.add_argument("--port", type=int, default=PORT, help="MSSQL port (default: %(default)s)")
    parser.add_argument("--full-enum", action="store_true", help="Run full enumeration and write all artifacts")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = args.target
    port = args.port

    print(f"\n=== MSSQL Lab Solver — target {target}:{port} ===\n")

    hostname = get_hostname(target, port)
    non_default_dbs = get_non_default_databases(target, port)

    print(f"\nQ1 — MSSQL server hostname:      {hostname}")
    print(f"Q2 — Non-default database(s):    {', '.join(non_default_dbs) if non_default_dbs else 'NONE FOUND'}")
    print()

    if args.full_enum:
        run_full_enum(target, port)

    return 0


if __name__ == "__main__":
    sys.exit(main())
