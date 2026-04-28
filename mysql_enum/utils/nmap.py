"""Nmap runner for MySQL discovery."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap_mysql(target: str, port: int, output_base: Path) -> dict:
    """Run nmap with MySQL NSE scripts. Returns parsed summary dict."""
    if not nmap_available():
        return {"available": False, "error": "nmap not found in PATH"}

    output_base.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "nmap", "-sV", "-sC", f"-p{port}",
        "--script", "mysql-info,mysql-empty-password,mysql-enum,mysql-users,mysql-variables",
        target,
        "-oA", str(output_base),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return {
            "available": True,
            "command": " ".join(cmd),
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"available": True, "error": "nmap timed out after 120s"}
    except Exception as e:
        return {"available": True, "error": str(e)}
