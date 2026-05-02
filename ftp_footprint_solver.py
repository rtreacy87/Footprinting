#!/usr/bin/env python3
"""FTP footprinting lab solver.

Uses ftp_enum_agent to run a structured enumeration, then extracts the flag
from any downloaded flag.txt.

The package handles: banner grab, anonymous login, recursive directory listing,
selective download, secret scanning, upload check, attack-path classification,
and JSON/Markdown reporting.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from ftp_enum_agent import FtpOrchestrator, ScanConfig
from ftp_enum_agent.clients.ftp_client import FTPClient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Solve the HTB FTP footprinting lab — find and print flag.txt."
    )
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=21, help="FTP port (default: 21)")
    parser.add_argument("--user", default=None, help="FTP username (tries anonymous by default)")
    parser.add_argument("--password", default=None, help="FTP password")
    parser.add_argument("--timeout", type=float, default=10.0, help="Socket timeout in seconds")
    parser.add_argument("--output", default="output/ftp", help="Output base directory")
    parser.add_argument("--check-upload", action="store_true", help="Enable upload capability test")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    config = ScanConfig(
        target=args.host,
        port=args.port,
        output_dir=Path(args.output),
        username=args.user,
        password=args.password,
        timeout=args.timeout,
        check_upload=args.check_upload,
        max_file_size_mb=5.0,
        max_total_download_mb=50.0,
    )

    print(f"\n=== FTP Lab Solver — {args.host}:{args.port} ===\n", file=sys.stderr)

    report = FtpOrchestrator(config).run()

    # Banner
    banner_result = report.result("banner")
    if not (banner_result and banner_result.success):
        print("FTP not reachable.", file=sys.stderr)
        return 1
    print(f"Banner: {banner_result.details.get('banner', '')}")

    # Login status
    anon_result = report.result("anonymous_login")
    if anon_result:
        print(f"Anonymous login: {'success' if anon_result.success else 'failed'}")

    # Listing
    listing_result = report.result("directory_listing")
    if listing_result:
        print(f"Files found: {listing_result.details.get('entry_count', 0)}")

    # Flag
    flag_value = _find_flag(report, config)
    if flag_value:
        print(f"\nFlag: {flag_value}")
    else:
        print("\nflag.txt not found in downloaded files.", file=sys.stderr)

    # Attack path summary
    paths = [f for f in report.findings if f.is_attack_path]
    if paths:
        print(f"\nAttack paths identified: {len(paths)}")
        for f in paths:
            print(f"  [{f.severity.upper()}] {f.title}")

    print(f"\nReports saved to: {config.target_dir}", file=sys.stderr)
    return 0 if flag_value else 1


def _find_flag(report, config: ScanConfig) -> str | None:
    """Return flag.txt content from already-downloaded files or via a direct retrieve."""
    # Already downloaded by the enumerator
    for entry in report.downloaded_files:
        if entry.name.lower() == "flag.txt" and entry.local_path:
            try:
                return Path(entry.local_path).read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                pass

    # flag.txt wasn't captured (filtered out by extension) — retrieve it directly
    flag_entries = [e for e in report.file_inventory if e.name.lower() == "flag.txt"]
    if not flag_entries:
        return None

    creds = (config.username, config.password or "") if config.username else config.anonymous_credentials[0]
    client = FTPClient(config.target, config.port, config.timeout)
    try:
        client.connect()
        client.login(*creds)
        for entry in flag_entries:
            try:
                content = client.retrieve_text(entry.path)
                local = config.downloads_path(entry.path.lstrip("/"))
                local.parent.mkdir(parents=True, exist_ok=True)
                local.write_text(content, encoding="utf-8")
                return content.strip()
            except Exception:
                continue
    except Exception:
        pass
    finally:
        client.close()

    return None


if __name__ == "__main__":
    sys.exit(main())
