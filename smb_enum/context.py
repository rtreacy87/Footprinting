from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .config import ScanConfig
from .models import (
    AttackPath,
    BlockedPath,
    CommandResult,
    ControlAssessment,
    Evidence,
    FileFinding,
    FileMetadata,
    Group,
    ProtocolSecurityInfo,
    Share,
    TestResult,
    User,
)


@dataclass
class ScanContext:
    config: ScanConfig
    shares: list[Share] = field(default_factory=list)
    users: list[User] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    test_results: list[TestResult] = field(default_factory=list)
    control_assessments: list[ControlAssessment] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    blocked_paths: list[BlockedPath] = field(default_factory=list)
    file_findings: list[FileFinding] = field(default_factory=list)
    file_metadata: list[FileMetadata] = field(default_factory=list)
    protocol_info: ProtocolSecurityInfo | None = None
    evidence: list[Evidence] = field(default_factory=list)
    command_results: list[CommandResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_steps: list[dict] = field(default_factory=list)
    os_info: str | None = None
    smb_version_banner: str | None = None
    domain: str | None = None
    # (share_name, file_path) -> file content string
    file_contents: dict[tuple[str, str], str] = field(default_factory=dict)
    # per-share rpcclient details: share_name -> {remark, win_path, unix_path}
    share_details: dict[str, dict] = field(default_factory=dict)

    @property
    def target(self) -> str:
        return self.config.target

    @property
    def output_base(self) -> Path:
        return self.config.output_base

    def add_evidence(self, ev: Evidence) -> None:
        """Add an Evidence object if its ID is not already present."""
        existing_ids = {e.evidence_id for e in self.evidence}
        if ev.evidence_id not in existing_ids:
            self.evidence.append(ev)

    def add_test_result(self, result: TestResult) -> None:
        """Add a TestResult, replacing any existing result with the same test_id."""
        self.test_results = [r for r in self.test_results if r.test_id != result.test_id]
        self.test_results.append(result)

    def add_control(self, assessment: ControlAssessment) -> None:
        """Add a ControlAssessment, replacing any existing entry with the same control_id."""
        self.control_assessments = [
            c for c in self.control_assessments if c.control_id != assessment.control_id
        ]
        self.control_assessments.append(assessment)

    def skip_step(self, step: str, reason: str) -> None:
        self.skipped_steps.append({"step": step, "reason": reason})

    def get_accessible_shares(self) -> list[Share]:
        """Return shares where readable is True."""
        return [s for s in self.shares if s.readable is True]

    def get_writable_shares(self) -> list[Share]:
        """Return shares where writable is True."""
        return [s for s in self.shares if s.writable is True]

    def has_anonymous_access(self) -> bool:
        """Return True if any share has anonymous_access=True."""
        return any(s.anonymous_access is True for s in self.shares)

    def get_test_result(self, test_id: str) -> TestResult | None:
        for r in self.test_results:
            if r.test_id == test_id:
                return r
        return None
