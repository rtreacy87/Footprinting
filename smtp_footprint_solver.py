#!/usr/bin/env python3

import argparse
import codecs
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Set


def run_cmd(cmd: List[str], timeout: int = 120) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (result.stdout or "") + (result.stderr or "")


def read_user_candidates(wordlist: str) -> List[str]:
    p = Path(wordlist)
    if not p.exists():
        return []
    users: List[str] = []
    for line in p.read_text(errors="ignore").splitlines():
        u = line.strip()
        if u and not u.startswith("#"):
            users.append(u)
    return users


def extract_banner_from_nmap(output: str) -> str:
    m = re.search(r'r\(Hello,\d+,"([^"]+)"\)', output)
    if m:
        decoded = codecs.decode(m.group(1), "unicode_escape")
        for line in decoded.splitlines():
            if line.startswith("220 "):
                return line.strip()

    m = re.search(r"(^220\s.+)$", output, flags=re.MULTILINE)
    if m:
        return m.group(1).strip()

    # Fallback: parse escaped service fingerprint snippet.
    m = re.search(r"220\\x20([^\"]+?)\\r\\n", output)
    if m:
        return ("220 " + m.group(1)).replace("\\x20", " ").replace("\\.", ".").strip()

    m = re.search(r"220\x20([^\"]+?)\r\n", output)
    if m:
        return ("220 " + m.group(1)).replace("\\x20", " ").replace("\\.", ".").strip()
    return "NOT_FOUND"


def get_banner(target: str, port: int) -> str:
    out = run_cmd(["nmap", "-Pn", "-sV", "-p", str(port), target], timeout=90)
    return extract_banner_from_nmap(out)


def parse_user_hits(output: str, candidates: Set[str]) -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()

    for line in output.splitlines():
        lower_line = line.lower()
        if "<no result>" in lower_line:
            continue
        for user in candidates:
            if re.search(rf"\b{re.escape(user)}\b", line, flags=re.IGNORECASE):
                if user not in seen:
                    seen.add(user)
                    found.append(user)
    return found


def smtp_user_enum(target: str, wordlist: str, workers: int) -> List[str]:
    candidates = set(read_user_candidates(wordlist))
    if not candidates:
        return []

    tool = shutil.which("smtp-user-enum")
    if tool:
        out = run_cmd([
            tool,
            "-M",
            "VRFY",
            "-U",
            wordlist,
            "-t",
            target,
            "-m",
            str(workers),
        ])
        hits = parse_user_hits(out, candidates)
        if hits:
            return hits

    local_tool = Path(__file__).resolve().parent / "smtp-user-enum.pl"
    if local_tool.exists():
        out = run_cmd([
            "perl",
            str(local_tool),
            "-M",
            "VRFY",
            "-U",
            wordlist,
            "-t",
            target,
            "-m",
            str(workers),
        ])
        hits = parse_user_hits(out, candidates)
        if hits:
            return hits

    # Fallback to nmap script parsing when smtp-user-enum is unavailable.
    out = run_cmd([
        "nmap",
        "-Pn",
        "-p25",
        "--script",
        "smtp-enum-users",
        "--script-args",
        f"smtp-enum-users.methods=VRFY,userdb={wordlist}",
        target,
    ], timeout=120)

    in_block = False
    hits: List[str] = []
    for line in out.splitlines():
        if "smtp-enum-users:" in line:
            in_block = True
            continue
        if in_block:
            if not line.strip().startswith("|"):
                break
            u = line.replace("|", "").replace("_", "").strip()
            if u in candidates:
                hits.append(u)

    # If everything matches, this is likely a false-positive permissive VRFY setup.
    if hits and len(set(hits)) == len(candidates):
        return []

    deduped: List[str] = []
    seen = set()
    for h in hits:
        if h not in seen:
            seen.add(h)
            deduped.append(h)
    return deduped


def choose_primary_user(users: List[str]) -> str:
    if not users:
        return "NOT_FOUND"
    for u in users:
        if u.lower() not in {"postmaster", "root"}:
            return u
    return users[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="SMTP host-based enumeration lab solver")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=25, help="SMTP port (default: 25)")
    parser.add_argument("--workers", type=int, default=60, help="smtp-user-enum worker count")
    parser.add_argument(
        "--wordlist",
        default="./footprinting-wordlist.txt",
        help="Wordlist path (default: ./footprinting-wordlist.txt)",
    )
    args = parser.parse_args()

    banner = get_banner(args.target, args.port)
    users = smtp_user_enum(args.target, args.wordlist, args.workers)
    primary = choose_primary_user(users)

    print(f"SMTP banner: {banner}")
    print(f"Existing username: {primary}")
    print(f"All discovered usernames: {', '.join(users) if users else 'NONE'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
