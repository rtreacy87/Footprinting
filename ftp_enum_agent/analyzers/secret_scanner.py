"""Registry-based secret scanner. Each scanner looks for one class of secret."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..models import CredentialCandidate
from ..utils.redaction import redact_secret


class SecretScannerProtocol(Protocol):
    name: str
    def scan_text(self, text: str, file_path: str) -> list[CredentialCandidate]: ...


@dataclass
class ScannerRegistry:
    _scanners: list[SecretScannerProtocol] = field(default_factory=list)

    def register(self, scanner: SecretScannerProtocol) -> None:
        self._scanners.append(scanner)

    def scan_file(self, path: Path) -> list[CredentialCandidate]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        results: list[CredentialCandidate] = []
        for scanner in self._scanners:
            results.extend(scanner.scan_text(text, str(path)))
        return results


class PasswordAssignmentScanner:
    name = "password_assignment"
    _PATTERN = re.compile(
        r"(?:password|passwd|pwd|pass)\s*[=:]\s*['\"]?(\S+)['\"]?",
        re.IGNORECASE,
    )

    def scan_text(self, text: str, file_path: str) -> list[CredentialCandidate]:
        results = []
        for i, line in enumerate(text.splitlines(), 1):
            m = self._PATTERN.search(line)
            if m:
                raw = m.group(1).strip("'\"")
                results.append(CredentialCandidate(
                    file_path=file_path,
                    match_type="password_assignment",
                    redacted_value=redact_secret(raw),
                    raw_value=raw,
                    line_number=i,
                    confidence="medium",
                ))
        return results


class PrivateKeyScanner:
    name = "private_key"
    _PATTERN = re.compile(r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PRIVATE)\s+PRIVATE KEY-----", re.IGNORECASE)

    def scan_text(self, text: str, file_path: str) -> list[CredentialCandidate]:
        m = self._PATTERN.search(text)
        if m:
            return [CredentialCandidate(
                file_path=file_path,
                match_type="private_key",
                redacted_value="[PRIVATE KEY REDACTED]",
                raw_value="[PRIVATE KEY]",
                confidence="high",
            )]
        return []


class AWSKeyScanner:
    name = "aws_key"
    _PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")

    def scan_text(self, text: str, file_path: str) -> list[CredentialCandidate]:
        matches = self._PATTERN.findall(text)
        return [CredentialCandidate(
            file_path=file_path,
            match_type="aws_access_key",
            redacted_value=redact_secret(k),
            raw_value=k,
            confidence="high",
        ) for k in matches]


class DatabaseConnectionStringScanner:
    name = "db_connection_string"
    _PATTERN = re.compile(
        r"(?:mysql|postgresql|postgres|mongodb|mssql|sqlserver|redis|jdbc)"
        r"://[^\s\"'<>]+",
        re.IGNORECASE,
    )

    def scan_text(self, text: str, file_path: str) -> list[CredentialCandidate]:
        matches = self._PATTERN.findall(text)
        return [CredentialCandidate(
            file_path=file_path,
            match_type="database_connection_string",
            redacted_value=redact_secret(m, show_chars=8),
            raw_value=m,
            confidence="high",
        ) for m in matches]


class JWTScanner:
    name = "jwt"
    _PATTERN = re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}")

    def scan_text(self, text: str, file_path: str) -> list[CredentialCandidate]:
        matches = self._PATTERN.findall(text)
        return [CredentialCandidate(
            file_path=file_path,
            match_type="jwt_token",
            redacted_value=redact_secret(m, show_chars=10),
            raw_value=m,
            confidence="medium",
        ) for m in matches]


# Default registry with all scanners registered
DEFAULT_SCANNER_REGISTRY = ScannerRegistry()
DEFAULT_SCANNER_REGISTRY.register(PasswordAssignmentScanner())
DEFAULT_SCANNER_REGISTRY.register(PrivateKeyScanner())
DEFAULT_SCANNER_REGISTRY.register(AWSKeyScanner())
DEFAULT_SCANNER_REGISTRY.register(DatabaseConnectionStringScanner())
DEFAULT_SCANNER_REGISTRY.register(JWTScanner())
