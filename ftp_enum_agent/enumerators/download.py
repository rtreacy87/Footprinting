from __future__ import annotations

from pathlib import Path

from ..clients.ftp_client import FTPClient
from ..config import ScanConfig
from ..models import EnumerationResult, Evidence, FileEntry
from ..utils.hashing import sha256_bytes, sha256_text
from ..utils.size_limits import within_file_limit

_INTERESTING_EXTENSIONS = {
    ".conf", ".config", ".ini", ".env", ".yml", ".yaml", ".json", ".xml",
    ".sql", ".bak", ".backup", ".old", ".pem", ".key", ".txt", ".log",
    ".php", ".py", ".rb", ".sh", ".ps1", ".bat", ".md", ".csv",
}
_ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar"}

_SENSITIVE_NAMES = {
    ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "wp-config.php", "configuration.php", "settings.php",
    "web.config", "appsettings.json", "application.properties",
}


def _is_interesting(entry: FileEntry) -> bool:
    name_lower = entry.name.lower()
    if name_lower in _SENSITIVE_NAMES:
        return True
    suffix = Path(entry.name).suffix.lower()
    return suffix in _INTERESTING_EXTENSIONS


class DownloadEnumerator:
    name = "download"

    def run(
        self,
        client: FTPClient,
        config: ScanConfig,
        file_inventory: list[FileEntry],
    ) -> tuple[EnumerationResult, list[Evidence], list[FileEntry]]:

        downloaded: list[FileEntry] = []
        evidence: list[Evidence] = []
        errors: list[str] = []
        total_bytes = 0
        max_total = config.max_total_download_mb * 1024 * 1024
        max_file = config.max_file_size_mb * 1024 * 1024

        candidates = [e for e in file_inventory if not e.is_dir and _is_interesting(e)]
        if config.mirror:
            candidates = [e for e in file_inventory if not e.is_dir]

        for entry in candidates:
            if total_bytes >= max_total:
                errors.append(f"Total download limit ({config.max_total_download_mb} MB) reached")
                break

            if entry.size is not None and not within_file_limit(entry.size, max_file):
                errors.append(f"Skipped {entry.path}: size {entry.size} > limit")
                continue

            try:
                data = client.retrieve_bytes(entry.path)
                if len(data) > max_file:
                    errors.append(f"Skipped {entry.path}: download size {len(data)} > limit")
                    continue

                local = config.downloads_path(entry.path.lstrip("/"))
                local.parent.mkdir(parents=True, exist_ok=True)
                local.write_bytes(data)

                digest = sha256_bytes(data)
                total_bytes += len(data)

                downloaded_entry = FileEntry(
                    name=entry.name,
                    path=entry.path,
                    is_dir=False,
                    size=len(data),
                    modified=entry.modified,
                    permissions=entry.permissions,
                    local_path=str(local),
                    sha256=digest,
                )
                downloaded.append(downloaded_entry)

            except Exception as exc:
                errors.append(f"Failed to download {entry.path}: {exc}")

        ev_id = "ev-download-manifest"
        manifest_lines = [f"{e.path} -> {e.local_path} [{e.sha256}]" for e in downloaded]
        manifest_text = "\n".join(manifest_lines)
        manifest_path = config.raw_path("download_manifest.txt")
        manifest_path.write_text(manifest_text, encoding="utf-8")
        evidence.append(Evidence(
            evidence_id=ev_id,
            target=config.target,
            collector="DownloadEnumerator",
            command_or_action="RETR for each interesting file",
            raw_output_path=str(manifest_path),
            sha256=sha256_text(manifest_text),
            notes=f"{len(downloaded)} files downloaded ({total_bytes // 1024} KB)",
        ))

        return EnumerationResult(
            check_name=self.name,
            status="success" if downloaded else ("blocked" if not errors else "partial"),
            success=bool(downloaded),
            summary=f"Downloaded {len(downloaded)} files ({total_bytes // 1024} KB)",
            details={"downloaded_count": len(downloaded), "total_bytes": total_bytes},
            evidence_ids=[ev_id],
            errors=errors,
        ), evidence, downloaded
