from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .config import ScanConfig, ScanProfile
from .models import (
    CommandResult,
    CompanionService,
    CredentialFinding,
    HashFinding,
    IpmiFinding,
    RiskFinding,
    ScanReport,
)


@dataclass
class ScanContext:
    config: ScanConfig
    ipmi_finding: IpmiFinding | None = None
    companion_services: list[CompanionService] = field(default_factory=list)
    credentials: list[CredentialFinding] = field(default_factory=list)
    hashes: list[HashFinding] = field(default_factory=list)
    risk_findings: list[RiskFinding] = field(default_factory=list)
    command_results: list[CommandResult] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    skipped_steps: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

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
    def ipmi_detected(self) -> bool:
        return self.ipmi_finding is not None and self.ipmi_finding.ipmi_detected

    def raw_path(self, filename: str) -> Path:
        return self.output_dir / "raw" / filename

    def parsed_path(self, filename: str) -> Path:
        return self.output_dir / "parsed" / filename

    def hashes_path(self, filename: str) -> Path:
        return self.output_dir / "hashes" / filename

    def markdown_path(self, filename: str) -> Path:
        return self.output_dir / "markdown" / filename

    def add_evidence(self, ref: str) -> None:
        if ref not in self.evidence_refs:
            self.evidence_refs.append(ref)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    def skip_step(self, step: str, reason: str) -> None:
        self.skipped_steps.append({"step": step, "reason": reason})

    def to_report(self) -> ScanReport:
        return ScanReport(
            target=self.target,
            scan_profile=self.profile.value,
            ipmi=self.ipmi_finding,
            companion_services=self.companion_services,
            credentials=self.credentials,
            hashes=self.hashes,
            risk_findings=self.risk_findings,
            evidence_refs=self.evidence_refs,
            skipped_steps=self.skipped_steps,
            errors=self.errors,
        )
