from __future__ import annotations

import os
import re

from ..models import FileMetadata, FileFinding
from .classifier_registry import register_classifier
from .file_classifier import FileClassifier

_BACKUP_EXTENSIONS = {
    ".bak", ".old", ".backup", ".zip", ".tar", ".gz", ".7z",
    ".rar", ".tgz", ".tar.gz", ".sql", ".dump",
}

_BACKUP_NAME_PATTERN = re.compile(
    r"(backup|dump|archive|copy|snapshot|export)",
    re.IGNORECASE,
)


@register_classifier
class BackupFileClassifier(FileClassifier):
    """Identifies backup and archive files that may contain sensitive data."""

    name = "backups"
    risk_score = 7

    def classify(self, file_metadata: FileMetadata) -> list[FileFinding]:
        filename = os.path.basename(file_metadata.path).lower()
        _, ext = os.path.splitext(filename)

        matched_rules: list[str] = []

        if ext in _BACKUP_EXTENSIONS:
            matched_rules.append(f"backup_extension:{ext}")

        if _BACKUP_NAME_PATTERN.search(filename):
            matched_rules.append("backup_keyword_in_filename")

        if matched_rules:
            return [FileFinding(
                path=file_metadata.path,
                share=file_metadata.share,
                file_type="backup",
                risk_score=self.risk_score,
                matched_rules=matched_rules,
            )]
        return []
