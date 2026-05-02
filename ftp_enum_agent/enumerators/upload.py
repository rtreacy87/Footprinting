from __future__ import annotations

import uuid

from ..clients.ftp_client import FTPClient
from ..config import ScanConfig
from ..models import EnumerationResult, Evidence, FileEntry
from ..utils.hashing import sha256_text

_PROBE_CONTENT = b"Authorized FTP upload capability test.\nNo executable payload.\n"


class UploadEnumerator:
    name = "upload"

    def run(
        self, client: FTPClient, config: ScanConfig, writable_dirs: list[str] | None = None
    ) -> tuple[EnumerationResult, list[Evidence]]:
        if not config.check_upload:
            return EnumerationResult(
                check_name=self.name,
                status="not_tested",
                success=False,
                summary="Upload check skipped (--check-upload not enabled)",
            ), []

        probe_name = f"ftp-enum-agent-upload-test-{uuid.uuid4().hex[:8]}.txt"
        dirs_to_try = writable_dirs or ["/"]
        transcript: list[str] = []
        evidence: list[Evidence] = []

        for directory in dirs_to_try:
            remote_path = f"{directory.rstrip('/')}/{probe_name}"
            transcript.append(f"Trying STOR {remote_path} ...")
            success = client.upload_bytes(remote_path, _PROBE_CONTENT)
            transcript.append(f"  => {'success' if success else 'failed'}")

            if success:
                raw = "\n".join(transcript)
                save_path = config.raw_path("upload_test.txt")
                save_path.write_text(raw, encoding="utf-8")
                evidence.append(Evidence(
                    evidence_id="ev-upload-test",
                    target=config.target,
                    collector="UploadEnumerator",
                    command_or_action=f"STOR {remote_path}",
                    raw_output_path=str(save_path),
                    sha256=sha256_text(raw),
                    notes=f"Upload succeeded at {remote_path}",
                ))
                return EnumerationResult(
                    check_name=self.name,
                    status="success",
                    success=True,
                    summary=f"Upload succeeded at {remote_path}",
                    details={
                        "upload_path": remote_path,
                        "probe_file": probe_name,
                        "cleanup_status": "not_cleaned" if not config.cleanup_upload_test else "cleanup_enabled",
                    },
                    evidence_ids=["ev-upload-test"],
                ), evidence

        return EnumerationResult(
            check_name=self.name,
            status="failed",
            success=False,
            summary="Upload denied in all tested directories",
            details={"dirs_tried": dirs_to_try},
        ), evidence
