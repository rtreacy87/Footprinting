from __future__ import annotations

import os

from ..models import FileMetadata, FileFinding
from .classifier_registry import register_classifier
from .file_classifier import FileClassifier

_CONFIG_EXTENSIONS = {
    ".conf", ".config", ".ini", ".yaml", ".yml",
    ".json", ".xml", ".env", ".properties", ".toml",
}

_KNOWN_CONFIG_FILES = {
    "web.config", "appsettings.json", ".npmrc", ".pypirc",
    "config.php", "settings.py", "database.yml", "wp-config.php",
    "application.properties", "hibernate.cfg.xml", "context.xml",
}


@register_classifier
class ConfigFileClassifier(FileClassifier):
    """Identifies configuration files that may contain sensitive settings."""

    name = "configs"
    risk_score = 6

    def classify(self, file_metadata: FileMetadata) -> list[FileFinding]:
        filename = os.path.basename(file_metadata.path).lower()
        _, ext = os.path.splitext(filename)

        matched_rules: list[str] = []

        if ext in _CONFIG_EXTENSIONS:
            matched_rules.append(f"config_extension:{ext}")

        if filename in _KNOWN_CONFIG_FILES:
            matched_rules.append(f"known_config_file:{filename}")

        if matched_rules:
            return [FileFinding(
                path=file_metadata.path,
                share=file_metadata.share,
                file_type="config",
                risk_score=self.risk_score,
                matched_rules=matched_rules,
            )]
        return []
