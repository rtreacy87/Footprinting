"""Optional wrappers for nmap and wget."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class NmapFtpTool:
    def available(self) -> bool:
        return shutil.which("nmap") is not None

    def run_service_scan(self, target: str, port: int, save_path: Path | None = None) -> str:
        cmd = ["nmap", "-sV", "-sC", f"-p{port}", "-Pn", "--script", "ftp-anon,ftp-bounce,ftp-syst", target]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = proc.stdout + proc.stderr
            if save_path:
                save_path.parent.mkdir(parents=True, exist_ok=True)
                save_path.write_text(output, encoding="utf-8")
            return output
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""


class WgetMirrorTool:
    def available(self) -> bool:
        return shutil.which("wget") is not None

    def mirror(self, target: str, port: int, save_dir: Path) -> str:
        url = f"ftp://anonymous:anonymous@{target}:{port}"
        cmd = ["wget", "-m", "--no-passive", f"--directory-prefix={save_dir}", url]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return proc.stdout + proc.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""
