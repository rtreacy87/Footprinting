from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .config import ScanConfig, ScanProfile
from .models import (
    AccessCheck,
    DiscoveryResult,
    EnumerationResult,
    ExtractionResult,
    MountAttempt,
    NfsReport,
    PermissionResult,
    Vulnerability,
)


@dataclass
class ScanContext:
    config: ScanConfig
    discovery: DiscoveryResult | None = None
    enumeration: EnumerationResult | None = None
    access_checks: list[AccessCheck] = field(default_factory=list)
    mount_attempts: list[MountAttempt] = field(default_factory=list)
    extraction: ExtractionResult | None = None
    permissions: list[PermissionResult] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_steps: list[dict] = field(default_factory=list)

    @property
    def target(self) -> str:
        return self.config.target

    @property
    def output_dir(self) -> Path:
        return self.config.target_output_dir

    @property
    def profile(self) -> ScanProfile:
        return self.config.profile

    @property
    def nfs_detected(self) -> bool:
        return self.discovery is not None and self.discovery.nfs_detected

    @property
    def exports(self):
        if self.enumeration is None:
            return []
        return self.enumeration.exports

    @property
    def successful_mounts(self) -> list[MountAttempt]:
        return [a for a in self.mount_attempts if a.success]

    @property
    def direct_access(self) -> bool:
        return any(a.success for a in self.mount_attempts)

    def path(self, section: str, filename: str) -> Path:
        return self.output_dir / section / filename

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    def skip_step(self, step: str, reason: str) -> None:
        self.skipped_steps.append({"step": step, "reason": reason})

    def to_report(self) -> NfsReport:
        return NfsReport(
            target=self.target,
            scan_profile=self.profile.value,
            discovery=self.discovery,
            enumeration=self.enumeration,
            access_checks=self.access_checks,
            mount_attempts=self.mount_attempts,
            extraction=self.extraction,
            permissions=self.permissions,
            vulnerabilities=self.vulnerabilities,
            direct_access=self.direct_access,
            pivot_required=not self.direct_access and self.nfs_detected,
            errors=self.errors,
            skipped_steps=self.skipped_steps,
        )
