#!/usr/bin/env python3
"""SNMP footprinting lab solver — answers all three HTB lab questions:
  Q1: Admin email address  (grep @inlanefreight)
  Q2: Customised SNMP server version  (sysDescr OID)
  Q3: Custom extend-script output  (grep context around "HTB")
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


def run_cmd(cmd: List[str], timeout: int = 120) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (result.stdout or "") + (result.stderr or "")


def snmpwalk_probe(target: str, community: str, version: str = "2c") -> bool:
    """Quick check: walk only the system subtree with a short snmpwalk-level timeout.
    snmpwalk -t 3 -r 1 will exit in ~3 s if the community is wrong/host is down."""
    out = run_cmd(
        ["snmpwalk", f"-v{version}", "-c", community,
         "-t", "3", "-r", "1", target, "1.3.6.1.2.1.1"],
        timeout=15,  # must be > snmpwalk's own (3 s * 1 retry + overhead)
    )
    return bool(out.strip()) and "Timeout" not in out and "No Response" not in out


def snmpwalk_full(target: str, community: str, version: str = "2c") -> str:
    """Full MIB walk — can take several minutes; subprocess timeout is generous."""
    return run_cmd(
        ["snmpwalk", f"-v{version}", "-c", community, target],
        timeout=600,
    )


def walk_is_valid(output: str) -> bool:
    """True when snmpwalk returned real SNMP data (not just a timeout/error)."""
    return bool(output.strip()) and "Timeout" not in output and "No Response" not in output


SNMP_WORDLISTS = [
    "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt",
    "/usr/share/seclists/Discovery/SNMP/snmp.txt",
    "/opt/useful/seclists/Discovery/SNMP/common-snmp-community-strings.txt",
    "/opt/useful/seclists/Discovery/SNMP/snmp.txt",
]

QUICK_STRINGS = [
    "public", "private", "community", "snmp", "manager", "backup",
    "internal", "secret", "admin", "default", "test", "guest",
]


def find_community_string(target: str, wordlist: Optional[str], version: str) -> "tuple[Optional[str], Optional[str]]":
    """Probe quickly, then do the full walk only once we have a confirmed string."""
    print("[*] Trying common community strings ...", file=sys.stderr)
    for cs in QUICK_STRINGS:
        print(f"    trying '{cs}' ...", file=sys.stderr)
        if snmpwalk_probe(target, cs, version):
            print(f"[+] Confirmed: '{cs}'", file=sys.stderr)
            return cs, snmpwalk_full(target, cs, version)

    candidates: List[str] = []
    if wordlist:
        candidates.append(wordlist)
    candidates.extend(SNMP_WORDLISTS)

    wl_path: Optional[Path] = None
    for p in candidates:
        if Path(p).exists():
            wl_path = Path(p)
            break

    if wl_path is None:
        print("[!] No SNMP community wordlist found.", file=sys.stderr)
        return None, None

    print(f"[*] Using wordlist: {wl_path}", file=sys.stderr)

    if shutil.which("onesixtyone"):
        print(f"[*] Running onesixtyone against {target} ...", file=sys.stderr)
        out = run_cmd(["onesixtyone", "-c", str(wl_path), target], timeout=180)
        print(f"[*] onesixtyone output:\n{out[:500]}", file=sys.stderr)
        m = re.search(r"\[([^\]]+)\]", out)
        if m:
            cs = m.group(1).strip()
            dump = snmpwalk_full(target, cs, version)
            if walk_is_valid(dump):
                return cs, dump
    else:
        print("[!] onesixtyone not found — trying wordlist manually ...", file=sys.stderr)
        for line in wl_path.read_text(errors="ignore").splitlines():
            cs = line.strip()
            if cs and not cs.startswith("#"):
                if snmpwalk_probe(target, cs, version):
                    return cs, snmpwalk_full(target, cs, version)

    return None, None


# --- answer parsers -----------------------------------------------------------

def get_admin_email(dump: str) -> str:
    """Q1: first line containing @inlanefreight"""
    for line in dump.splitlines():
        if "@inlanefreight" in line.lower():
            m = re.search(r"STRING:\s+(.+)", line)
            if m:
                return m.group(1).strip().strip('"')
    return "NOT_FOUND"


def get_server_version(dump: str) -> str:
    """Q2: sysDescr — the STRING value on the 1.3.6.1.2.1.1.1.0 line"""
    for line in dump.splitlines():
        if "1.3.6.1.2.1.1.1.0" in line or "iso.3.6.1.2.1.1.1.0" in line:
            m = re.search(r"STRING:\s+(.+)", line)
            if m:
                return m.group(1).strip().strip('"')
    return "NOT_FOUND"


def get_custom_script_output(dump: str) -> str:
    """Q3: 8 lines of context before the first 'HTB' occurrence (grep -m1 -B8 HTB)"""
    lines = dump.splitlines()
    for idx, line in enumerate(lines):
        if "HTB" in line:
            start = max(0, idx - 8)
            return "\n".join(lines[start: idx + 1])
    return "NOT_FOUND"


# ------------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Solve the HTB SNMP footprinting lab (3 questions)."
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--community", default=None, help="SNMP community string (skip discovery)")
    parser.add_argument("--version", default="2c", choices=["1", "2c", "3"], help="SNMP version")
    parser.add_argument("--wordlist", default=None, help="Community-string wordlist for brute-force")
    parser.add_argument("--save", default=None, metavar="FILE", help="Save snmpwalk output to file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    dump: Optional[str] = None
    community = args.community

    if community:
        print(f"[*] Using provided community string: {community}", file=sys.stderr)
        dump = snmpwalk_full(args.target, community, args.version)
        if not walk_is_valid(dump):
            print(f"[-] snmpwalk failed with community '{community}'.", file=sys.stderr)
            print(dump[:300], file=sys.stderr)
            return 1
    else:
        community, dump = find_community_string(args.target, args.wordlist, args.version)
        if not community or not dump:
            print("[-] Could not find a working community string.", file=sys.stderr)
            return 1
        print(f"[+] Community string: {community}", file=sys.stderr)

    if args.save:
        Path(args.save).write_text(dump)
        print(f"[*] Walk saved to {args.save}", file=sys.stderr)

    print(f"\n=== SNMP Lab Results for {args.target} ===\n")

    email = get_admin_email(dump)
    print(f"Q1 — Admin email:            {email}")

    version_str = get_server_version(dump)
    print(f"Q2 — Server version:         {version_str}")

    script_out = get_custom_script_output(dump)
    print(f"Q3 — Custom script context:\n{script_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
