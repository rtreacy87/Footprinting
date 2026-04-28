#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import parsers
import render_markdown

VERSION = "0.1.0"

SNMP_SECTIONS = [
    ("system",         "1.3.6.1.2.1.1"),
    ("interfaces",     "1.3.6.1.2.1.2"),
    ("network",        "1.3.6.1.2.1.4"),
    ("tcp",            "1.3.6.1.2.1.6"),
    ("udp",            "1.3.6.1.2.1.7"),
    ("host_resources", "1.3.6.1.2.1.25"),
]

SNMP_WORDLISTS = [
    "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt",
    "/usr/share/seclists/Discovery/SNMP/snmp.txt",
    "/opt/useful/seclists/Discovery/SNMP/snmp.txt",
]

QUICK_COMMUNITIES = ["public", "private", "community", "snmp", "manager", "backup"]


def _run(cmd: List[str], timeout: int) -> Tuple[str, bool]:
    """
    Run a subprocess and return (combined stdout+stderr, success bool).
    Handles TimeoutExpired and missing executables gracefully.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        combined = result.stdout + result.stderr
        return combined, result.returncode == 0
    except subprocess.TimeoutExpired:
        return ("[timeout]", False)
    except FileNotFoundError:
        return (f"[tool not found: {cmd[0]}]", False)


def _snmpwalk_probe(
    target: str,
    community: str,
    version: str,
    timeout: int = 8,
) -> bool:
    """
    Probe target with snmpwalk using the given community string.
    Returns True only if output is non-empty and does not indicate a timeout/no-response.
    """
    cmd = [
        "snmpwalk",
        f"-v{version}",
        "-c", community,
        "-t", "2",
        "-r", "1",
        target,
        "1.3.6.1.2.1.1.1.0",
    ]
    output, _ = _run(cmd, timeout)
    if not output.strip():
        return False
    lower = output.lower()
    if "timeout" in lower or "no response" in lower:
        return False
    return True


def _snmpwalk(
    target: str,
    community: str,
    version: str,
    oid: str,
    timeout: int,
) -> str:
    """
    Run snmpwalk against target for the given OID.
    Omits the OID argument when oid is an empty string.
    Returns combined stdout+stderr output.
    """
    cmd = ["snmpwalk", f"-v{version}", "-c", community, target]
    if oid:
        cmd.append(oid)
    output, _ = _run(cmd, timeout)
    return output


def _resolve_wordlist(explicit: Optional[str]) -> Optional[Path]:
    """
    Return the path to a community-string wordlist.
    Tries the explicit path first, then each path in SNMP_WORDLISTS.
    """
    if explicit:
        p = Path(explicit)
        if p.exists():
            return p

    for candidate in SNMP_WORDLISTS:
        p = Path(candidate)
        if p.exists():
            return p

    return None


def check_tools(required: List[str]) -> None:
    """Exit with an error message if any required tools are not on PATH."""
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        print(f"[!] Missing required tools: {', '.join(missing)}", file=sys.stderr)
        print("[!] Install them and re-run.", file=sys.stderr)
        sys.exit(1)


def create_asset_dir(base_output: str, target_ip: str) -> Path:
    """
    Create output directory structure for the target asset.
    Returns the top-level asset directory Path.
    """
    asset_dir = Path(base_output) / target_ip
    for subdir in ("raw", "json", "markdown", "wordlists"):
        (asset_dir / subdir).mkdir(parents=True, exist_ok=True)
    return asset_dir


def run_nmap(target: str, raw_dir: Path, timeout: int) -> str:
    """
    Run an nmap UDP scan on port 161 and save results to raw_dir/nmap_snmp.txt.
    Returns the nmap output string.
    """
    cmd = ["sudo", "nmap", "-sU", "-p161", "--open", "-sV", target]
    print(f"[*] Running nmap UDP/161 scan against {target} ...")
    output, _ = _run(cmd, timeout)
    out_path = raw_dir / "nmap_snmp.txt"
    out_path.write_text(output, encoding="utf-8")

    if "161/udp" in output and "open" in output:
        print(f"[+] UDP/161 appears OPEN on {target}")
    else:
        print(f"[-] UDP/161 not confirmed open on {target} (check {out_path})")

    return output


def discover_communities(
    target: str,
    wordlist: Optional[str],
    raw_dir: Path,
    timeout: int,
    version: str = "2c",
) -> List[str]:
    """
    Attempt to discover valid SNMP community strings for the target.

    Strategy:
      1. Quick probe with common strings — return immediately on first hit.
      2. Use onesixtyone if available against resolved wordlist.
      3. Fall back to iterating the wordlist with snmpwalk probes.
    """
    print("[*] Probing quick community strings ...")
    for community in QUICK_COMMUNITIES:
        if _snmpwalk_probe(target, community, version):
            print(f"[+] Community string found (quick): {community}")
            return [community]

    wl_path = _resolve_wordlist(wordlist)
    if wl_path is None:
        print("[!] No SNMP wordlist found; skipping community discovery.", file=sys.stderr)
        return []

    print(f"[*] Using wordlist: {wl_path}")

    if shutil.which("onesixtyone"):
        print("[*] Running onesixtyone ...")
        cmd = ["onesixtyone", "-c", str(wl_path), target]
        output, _ = _run(cmd, timeout)
        out_path = raw_dir / "onesixtyone.txt"
        out_path.write_text(output, encoding="utf-8")

        found: List[str] = []
        for match in re.findall(r"\[(.+?)\]", output):
            community = match.strip()
            if community and community not in found:
                found.append(community)

        if found:
            print(f"[+] Communities found via onesixtyone: {', '.join(found)}")
            return found

        print("[-] onesixtyone found no communities.")
    else:
        print("[*] onesixtyone not found; iterating wordlist with snmpwalk probes ...")
        try:
            lines = wl_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            print(f"[!] Could not read wordlist: {exc}", file=sys.stderr)
            return []

        for line in lines:
            community = line.strip()
            if not community or community.startswith("#"):
                continue
            if _snmpwalk_probe(target, community, version):
                print(f"[+] Community string found (wordlist): {community}")
                return [community]

    print("[-] No valid SNMP community strings discovered.")
    return []


def collect_snmp_sections(
    target: str,
    community: str,
    version: str,
    raw_dir: Path,
    timeout: int,
) -> Dict[str, str]:
    """
    Walk each standard SNMP section OID, save raw output, and return a dict of outputs.
    """
    collected: Dict[str, str] = {}
    for label, oid in SNMP_SECTIONS:
        print(f"[*] Walking {label} ({oid}) ...")
        output = _snmpwalk(target, community, version, oid, timeout)
        out_path = raw_dir / f"snmpwalk_{label}.raw"
        out_path.write_text(output, encoding="utf-8")
        entry_count = sum(1 for line in output.splitlines() if " = " in line)
        print(f"    {entry_count} entries collected -> {out_path.name}")
        collected[label] = output
    return collected


def collect_full_walk(
    target: str,
    community: str,
    version: str,
    raw_dir: Path,
    timeout: int,
) -> str:
    """
    Perform a full MIB walk starting at .1, saving output to snmpwalk_full.raw.
    Timeout is capped to at least 600 seconds for large trees.
    """
    effective_timeout = max(timeout, 600)
    print(f"[*] Running full walk (.1) with timeout={effective_timeout}s ...")
    output = _snmpwalk(target, community, version, ".1", effective_timeout)
    out_path = raw_dir / "snmpwalk_full.raw"
    out_path.write_text(output, encoding="utf-8")
    entry_count = sum(1 for line in output.splitlines() if " = " in line)
    print(f"    Full walk: {entry_count} entries -> {out_path.name}")
    return output


def run_braa(
    target: str,
    community: str,
    raw_dir: Path,
    timeout: int,
) -> str:
    """
    Run braa for fast SNMP enumeration if available.
    Saves output to raw_dir/braa.raw and returns the output string.
    """
    if not shutil.which("braa"):
        print("[!] braa not found; skipping braa enumeration.")
        return ""

    print(f"[*] Running braa against {target} ...")
    cmd = ["braa", f"{community}@{target}:.1.3.6.*"]
    output, _ = _run(cmd, timeout)
    out_path = raw_dir / "braa.raw"
    out_path.write_text(output, encoding="utf-8")
    entry_count = sum(1 for line in output.splitlines() if line.strip())
    print(f"    braa: {entry_count} lines -> {out_path.name}")
    return output


def write_json(data: object, path: Path) -> None:
    """Serialise data to a pretty-printed JSON file using UTF-8 encoding."""
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def write_wordlists(wordlists: Dict[str, List[str]], wordlist_dir: Path) -> None:
    """Write each non-empty wordlist category to its own text file."""
    wordlist_dir.mkdir(parents=True, exist_ok=True)
    for name, items in wordlists.items():
        if items:
            out_path = wordlist_dir / f"{name}.txt"
            out_path.write_text("\n".join(items) + "\n", encoding="utf-8")
            print(f"[+] Wordlist: {out_path} ({len(items)} entries)")


def parse_args() -> argparse.Namespace:
    """Configure and parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="snmp_enum",
        description=f"SNMP Enumeration Tool v{VERSION}",
    )
    parser.add_argument(
        "target_ip",
        help="Target IP address or hostname.",
    )
    parser.add_argument(
        "--community",
        default=None,
        help="SNMP community string. If omitted, discovery is attempted.",
    )
    parser.add_argument(
        "--version",
        default="2c",
        choices=["1", "2c", "3"],
        help="SNMP version to use (default: 2c).",
    )
    parser.add_argument(
        "--output",
        default="./snmp-output",
        help="Base output directory (default: ./snmp-output).",
    )
    parser.add_argument(
        "--label",
        default="",
        help="Optional human-readable label for the target asset.",
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        help="Path to a community-string wordlist.",
    )
    parser.add_argument(
        "--full-walk",
        action="store_true",
        help="Perform a full MIB walk in addition to section walks.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Per-tool timeout in seconds (default: 120).",
    )
    parser.add_argument(
        "--no-braa",
        action="store_true",
        help="Skip braa enumeration.",
    )
    parser.add_argument(
        "--markdown-only",
        action="store_true",
        help="Re-render markdown from an existing findings JSON without re-scanning.",
    )
    return parser.parse_args()


def main() -> int:
    """
    Orchestrate the full SNMP enumeration pipeline:
      nmap -> community discovery -> section walks -> parse -> report.
    """
    args = parse_args()
    target_ip: str = args.target_ip
    label: str = args.label or target_ip

    asset_dir = create_asset_dir(args.output, target_ip)
    raw_dir      = asset_dir / "raw"
    json_dir     = asset_dir / "json"
    markdown_dir = asset_dir / "markdown"
    wordlist_dir = asset_dir / "wordlists"

    # --markdown-only: re-render existing findings without scanning
    if args.markdown_only:
        findings_path = json_dir / "all_findings.json"
        metadata_path = asset_dir / "metadata.json"

        if not findings_path.exists():
            print(f"[!] findings JSON not found: {findings_path}", file=sys.stderr)
            return 1
        if not metadata_path.exists():
            print(f"[!] metadata JSON not found: {metadata_path}", file=sys.stderr)
            return 1

        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        render_markdown.write_all(findings, metadata, markdown_dir)
        print(f"[+] Markdown re-rendered to {markdown_dir}")
        return 0

    # Normal pipeline
    check_tools(["nmap", "snmpwalk"])

    run_nmap(target_ip, raw_dir, args.timeout)

    if args.community:
        communities = [args.community]
        print(f"[*] Using supplied community string: {args.community}")
    else:
        communities = discover_communities(
            target=target_ip,
            wordlist=args.wordlist,
            raw_dir=raw_dir,
            timeout=args.timeout,
            version=args.version,
        )

    if not communities:
        print("[!] No valid SNMP community strings found. Aborting.", file=sys.stderr)
        return 1

    community = communities[0]
    all_raw: Dict[str, str] = {}

    for cs in communities:
        section_data = collect_snmp_sections(
            target=target_ip,
            community=cs,
            version=args.version,
            raw_dir=raw_dir,
            timeout=args.timeout,
        )
        all_raw.update(section_data)

        if args.full_walk:
            all_raw["full"] = collect_full_walk(
                target=target_ip,
                community=cs,
                version=args.version,
                raw_dir=raw_dir,
                timeout=args.timeout,
            )

        if not args.no_braa:
            run_braa(target_ip, cs, raw_dir, args.timeout)

    # Parse collected raw output
    combined_raw = "\n".join(all_raw.values())
    entries = parsers.parse_raw_output(combined_raw)
    print(f"[*] Parsed {len(entries)} SNMP entries total.")

    findings  = parsers.build_all_findings(entries, target_ip, label)
    wordlists = parsers.extract_wordlists(entries, target_ip)

    metadata = {
        "target_ip":    target_ip,
        "label":        label,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "snmp_version": args.version,
        "community":    community,
        "communities":  communities,
        "tools_used":   ["nmap", "snmpwalk"] + (["braa"] if not args.no_braa and shutil.which("braa") else []),
        "full_walk":    args.full_walk,
        "snmp_enum_version": VERSION,
    }

    # Write JSON artefacts
    write_json(metadata, asset_dir / "metadata.json")
    write_json({"communities": communities}, asset_dir / "communities.json")
    write_json(findings, json_dir / "all_findings.json")

    sections = {
        "system_identity":    findings.get("system_identity", {}),
        "network_interfaces": findings.get("network_interfaces", []),
        "ip_networking":      findings.get("ip_networking", []),
        "tcp":                findings.get("tcp", []),
        "udp":                findings.get("udp", []),
        "processes":          findings.get("processes", []),
        "installed_software": findings.get("installed_software", []),
        "storage":            findings.get("storage", []),
        "suspicious_strings": findings.get("suspicious_strings", []),
        "attack_paths":       findings.get("potential_attack_paths", []),
    }
    for section_name, section_data in sections.items():
        write_json(section_data, json_dir / f"{section_name}.json")

    write_wordlists(wordlists, wordlist_dir)

    render_markdown.write_all(findings, metadata, markdown_dir)

    print("\n[+] Enumeration complete.")
    print(f"    Asset directory : {asset_dir}")
    print(f"    Raw outputs     : {raw_dir}")
    print(f"    JSON findings   : {json_dir}")
    print(f"    Markdown report : {markdown_dir}")
    print(f"    Wordlists       : {wordlist_dir}")
    print(f"    Report entry    : {markdown_dir / 'README.md'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
