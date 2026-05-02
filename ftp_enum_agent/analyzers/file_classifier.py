from __future__ import annotations

from pathlib import Path

from ..models import FileEntry

_SENSITIVE_NAMES = {
    ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa.pub",
    "wp-config.php", "configuration.php", "settings.php", "web.config",
    "appsettings.json", "application.properties",
}
_HIGH_INTEREST_EXTS = {".pem", ".key", ".kdbx", ".sql", ".bak", ".backup"}
_MEDIUM_INTEREST_EXTS = {
    ".conf", ".config", ".ini", ".env", ".yml", ".yaml",
    ".json", ".xml", ".php", ".sh", ".ps1",
}
_ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar"}
_HIGH_INTEREST_DIR_NAMES = {
    "backup", "backups", "config", "conf", "ssh", "keys",
    "database", "db", "admin", "private", "secret", "credentials",
}


def classify_entry(entry: FileEntry) -> tuple[str, str]:
    """Return (interest_level, reason): 'high'|'medium'|'low'|'none'."""
    name_lower = entry.name.lower()

    if name_lower in _SENSITIVE_NAMES:
        return "high", f"Sensitive filename: {entry.name}"

    ext = Path(entry.name).suffix.lower()
    if ext in _HIGH_INTEREST_EXTS:
        return "high", f"High-interest extension: {ext}"
    if ext in _ARCHIVE_EXTS:
        return "medium", f"Archive file may contain sensitive content: {ext}"
    if ext in _MEDIUM_INTEREST_EXTS:
        return "medium", f"Configuration-type extension: {ext}"

    if entry.is_dir and name_lower in _HIGH_INTEREST_DIR_NAMES:
        return "high", f"High-interest directory name: {entry.name}"

    return "low", "Standard file"
