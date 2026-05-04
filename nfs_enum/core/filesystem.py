from __future__ import annotations

from pathlib import Path


class NfsOutputPaths:
    def __init__(self, base: Path, target_id: str) -> None:
        self.root = base / target_id
        self.discovery = self.root / "discovery"
        self.enumeration = self.root / "enumeration"
        self.access_checks = self.root / "access_checks"
        self.mount_attempts = self.root / "mount_attempts"
        self.data_extraction = self.root / "data_extraction"
        self.permissions = self.root / "permissions"
        self.pivoting = self.root / "pivoting"
        self.vulnerabilities = self.root / "vulnerabilities"
        self.logs = self.root / "logs"
        self.summary = self.root / "summary"

    def setup(self) -> None:
        for d in (
            self.discovery, self.enumeration, self.access_checks,
            self.mount_attempts, self.data_extraction, self.permissions,
            self.pivoting, self.vulnerabilities, self.logs, self.summary,
        ):
            d.mkdir(parents=True, exist_ok=True)

    def mount_attempt_dir(self, attempt_number: int) -> Path:
        d = self.mount_attempts / f"attempt_{attempt_number}"
        d.mkdir(parents=True, exist_ok=True)
        return d
