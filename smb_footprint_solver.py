#!/usr/bin/env python3

import argparse
import tempfile
from pathlib import Path

from smb_enum import SmbEnumerator, ScanConfig, ScanProfile
from smb_enum.context import ScanContext
from smb_enum.core.runner import CommandRunner
from smb_enum.models import FileMetadata
from smb_enum.tools.smbclient_adapter import SmbClientAdapter


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SMB footprinting lab solver")
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("--output-dir", default="output", help="Output directory (default: output)")
    parser.add_argument(
        "--profile",
        default="standard",
        choices=["safe", "standard", "full"],
        help="Scan profile (default: standard)",
    )
    return parser.parse_args()


def find_flag_metadata(context: ScanContext) -> FileMetadata | None:
    for fm in context.file_metadata:
        if fm.path.lower().endswith("flag.txt"):
            return fm
    return None


def download_file(host: str, share: str, remote_path: str, output_base: Path) -> str | None:
    with tempfile.NamedTemporaryFile(prefix="smb_flag_", suffix=".txt", delete=False) as f:
        local_path = Path(f.name)

    try:
        adapter = SmbClientAdapter()
        runner = CommandRunner(output_base)
        spec = adapter.build_get_file_command(host, share, remote_path, local_path)
        runner.run(spec)
        if local_path.exists() and local_path.stat().st_size > 0:
            return local_path.read_text(encoding="utf-8", errors="replace").strip()
    finally:
        local_path.unlink(missing_ok=True)

    return None


def main() -> int:
    args = parse_args()

    config = ScanConfig(
        target=args.host,
        output_dir=Path(args.output_dir),
        profile=ScanProfile(args.profile),
    )

    enumerator = SmbEnumerator(config)
    context = enumerator.run()

    if context.smb_version_banner:
        print(f"SMB banner: {context.smb_version_banner}")

    accessible = context.get_accessible_shares()
    if not accessible:
        print("No accessible shares found")
        return 1

    share = accessible[0]
    print(f"Accessible share: {share.name}")

    flag_fm = find_flag_metadata(context)
    if flag_fm is None:
        print("flag.txt not found in share listing")
        return 1

    print(f"Flag path: {flag_fm.path}")

    flag_content = context.file_contents.get((flag_fm.share, flag_fm.path))
    if not flag_content:
        flag_content = download_file(args.host, flag_fm.share, flag_fm.path, config.output_base)

    if flag_content:
        print(f"Flag: {flag_content}")
    else:
        print("Could not read flag.txt")

    if context.domain:
        print(f"Domain: {context.domain}")

    details = context.share_details.get(share.name, {})
    if details.get("remark"):
        print(f"Share custom version: {details['remark']}")
    if details.get("unix_path"):
        print(f"Share system path: {details['unix_path']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
