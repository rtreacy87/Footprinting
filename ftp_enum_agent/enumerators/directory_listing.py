from __future__ import annotations

from ..clients.ftp_client import FTPClient
from ..config import ScanConfig
from ..models import EnumerationResult, Evidence, FileEntry
from ..utils.hashing import sha256_text

# Directories that warrant closer inspection during analysis
_INTERESTING_DIR_NAMES = {
    "backup", "backups", "config", "conf", "configuration", "home", "users",
    "www", "web", "html", "logs", "log", "ssh", "keys", "database", "db",
    "admin", "prod", "dev", "clients", "employees", "private", "secret",
    "data", "export", "import", "scripts", "cron", "jobs", "automation",
}


class DirectoryListingEnumerator:
    name = "directory_listing"

    def run(self, client: FTPClient, config: ScanConfig) -> tuple[EnumerationResult, list[Evidence], list[FileEntry]]:
        all_entries: list[FileEntry] = []
        listing_lines: list[str] = []
        errors: list[str] = []

        pending = ["/"]
        visited: set[str] = set()

        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)

            try:
                entries = list(client.list_entries(current))
                listing_lines.append(f"\n=== {current} ===")
                for entry in entries:
                    marker = "d" if entry.is_dir else "f"
                    listing_lines.append(f"  [{marker}] {entry.path}")
                    all_entries.append(entry)
                    if entry.is_dir:
                        pending.append(entry.path)
            except Exception as exc:
                errors.append(f"Could not list {current}: {exc}")

        raw = "\n".join(listing_lines)
        save_path = config.raw_path("recursive_listing.txt")
        save_path.write_text(raw, encoding="utf-8")

        evidence = [Evidence(
            evidence_id="ev-recursive-listing",
            target=config.target,
            collector="DirectoryListingEnumerator",
            command_or_action="Recursive LIST traversal",
            raw_output_path=str(save_path),
            sha256=sha256_text(raw),
            notes=f"{len(all_entries)} entries across {len(visited)} directories",
        )]

        success = len(all_entries) > 0
        return EnumerationResult(
            check_name=self.name,
            status="success" if success else ("blocked" if not errors else "error"),
            success=success,
            summary=f"Found {len(all_entries)} entries in {len(visited)} directories",
            details={
                "entry_count": len(all_entries),
                "directory_count": len(visited),
                "errors": errors,
            },
            evidence_ids=["ev-recursive-listing"],
            errors=errors,
        ), evidence, all_entries
