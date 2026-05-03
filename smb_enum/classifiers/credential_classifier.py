from __future__ import annotations

import os
import re

from ..models import FileMetadata, FileFinding
from .classifier_registry import register_classifier
from .file_classifier import FileClassifier

_KEYWORD_PATTERNS = re.compile(
    r"(password|passwd|cred|secret|token|api[_\-]?key|private[_\-]?key)",
    re.IGNORECASE,
)

_CREDENTIAL_EXTENSIONS = {
    ".kdbx", ".key", ".pem", ".ppk", ".pfx", ".p12",
    ".jks", ".keystore", ".der", ".crt", ".cer",
}


@register_classifier
class CredentialFileClassifier(FileClassifier):
    """Identifies files likely to contain credentials or private keys."""

    name = "credentials"
    risk_score = 9

    def classify(self, file_metadata: FileMetadata) -> list[FileFinding]:
        filename = os.path.basename(file_metadata.path).lower()
        _, ext = os.path.splitext(filename)

        matched_rules: list[str] = []

        if ext in _CREDENTIAL_EXTENSIONS:
            matched_rules.append(f"sensitive_extension:{ext}")

        if _KEYWORD_PATTERNS.search(filename):
            matched_rules.append("credential_keyword_in_filename")

        if matched_rules:
            return [FileFinding(
                path=file_metadata.path,
                share=file_metadata.share,
                file_type="credential",
                risk_score=self.risk_score,
                matched_rules=matched_rules,
            )]
        return []
