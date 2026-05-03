from __future__ import annotations

import os

from ..models import FileMetadata, FileFinding
from .classifier_registry import register_classifier
from .file_classifier import FileClassifier

_SCRIPT_EXTENSIONS = {
    ".ps1", ".bat", ".cmd", ".sh", ".py", ".pl", ".vbs",
    ".rb", ".js", ".php", ".asp", ".aspx", ".jsp",
}


@register_classifier
class ScriptFileClassifier(FileClassifier):
    """Identifies executable script files."""

    name = "scripts"
    risk_score = 5

    def classify(self, file_metadata: FileMetadata) -> list[FileFinding]:
        filename = os.path.basename(file_metadata.path).lower()
        _, ext = os.path.splitext(filename)

        if ext in _SCRIPT_EXTENSIONS:
            return [FileFinding(
                path=file_metadata.path,
                share=file_metadata.share,
                file_type="script",
                risk_score=self.risk_score,
                matched_rules=[f"script_extension:{ext}"],
            )]
        return []
