from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from ..context import ScanContext
from ..models import MountAttempt

_NFS_VERSIONS = ["4", "3", "2"]
_FAILURE_CLASSIFICATIONS = {
    "access denied": ("ACCESS_DENIED", "IP restriction or auth required", "pivot_required"),
    "permission denied": ("PERM_DENIED", "Insufficient permissions", "check_uid_gid"),
    "connection refused": ("CONN_REFUSED", "Service not accepting connections", "check_firewall"),
    "no route": ("NO_ROUTE", "Network unreachable", "check_network"),
    "timed out": ("TIMEOUT", "Connection timed out", "check_network"),
}


class MountManager:
    def run(self, context: ScanContext) -> None:
        if not context.config.options.attempt_mount:
            context.skip_step("mount_attempts", "attempt_mount disabled in config")
            return

        attempt_number = 0
        for export in context.exports:
            for version in _NFS_VERSIONS:
                attempt_number += 1
                attempt = self._try_mount(
                    context=context,
                    export_path=export.path,
                    nfs_version=version,
                    attempt_number=attempt_number,
                )
                context.mount_attempts.append(attempt)
                if attempt.success:
                    return

    def _try_mount(
        self,
        context: ScanContext,
        export_path: str,
        nfs_version: str,
        attempt_number: int,
    ) -> MountAttempt:
        attempt_dir = context.output_dir / "mount_attempts" / f"attempt_{attempt_number}"
        attempt_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="nfs_mount_") as tmpdir:
            mount_point = tmpdir
            cmd = [
                "mount", "-t", "nfs",
                f"-o", f"vers={nfs_version},nolock",
                f"{context.target}:{export_path}",
                mount_point,
            ]
            cmd_str = " ".join(cmd)

            (attempt_dir / "command.txt").write_text(cmd_str, encoding="utf-8")

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=context.config.options.mount_timeout_seconds,
                )
                stdout = proc.stdout or ""
                stderr = proc.stderr or ""
                success = proc.returncode == 0
            except subprocess.TimeoutExpired:
                stdout = ""
                stderr = f"mount timed out after {context.config.options.mount_timeout_seconds}s"
                success = False
            except FileNotFoundError:
                stdout = ""
                stderr = "mount command not found"
                success = False

            (attempt_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
            (attempt_dir / "stderr.txt").write_text(stderr, encoding="utf-8")

            error_msg: str | None = None
            failure_type: str | None = None
            next_step: str | None = None

            if not success:
                combined = (stdout + stderr).lower()
                for keyword, (ftype, reason, nstep) in _FAILURE_CLASSIFICATIONS.items():
                    if keyword in combined:
                        failure_type = ftype
                        error_msg = reason
                        next_step = nstep
                        break
                if not error_msg:
                    error_msg = (stderr or stdout).strip()[:200]

            result_data = {
                "status": "success" if success else "failed",
                "error": error_msg,
                "version": f"v{nfs_version}",
            }
            (attempt_dir / "result.json").write_text(
                json.dumps(result_data, indent=2), encoding="utf-8"
            )

            classification_data = {
                "failure_type": failure_type,
                "reason": error_msg,
                "next_step": next_step,
            } if not success else {"success": True}
            (attempt_dir / "classification.json").write_text(
                json.dumps(classification_data, indent=2), encoding="utf-8"
            )

            attempt = MountAttempt(
                attempt_number=attempt_number,
                export_path=export_path,
                nfs_version=nfs_version,
                command=cmd_str,
                stdout=stdout,
                stderr=stderr,
                success=success,
                error=error_msg,
                mount_point=mount_point if success else None,
                failure_type=failure_type,
                next_step=next_step,
            )

            if success:
                # Unmount immediately — extraction happens via NSE or separate step
                try:
                    subprocess.run(["umount", mount_point], timeout=15, capture_output=True)
                except Exception:
                    pass

            return attempt
