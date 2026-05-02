from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal


# ---------------------------------------------------------------------------
# Primitive building blocks
# ---------------------------------------------------------------------------

@dataclass
class Target:
    host: str
    port: int = 21
    protocol: str = "ftp"
    service_name: str = "ftp"
    scan_started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_completed_at: str | None = None
    resolved_hostname: str | None = None
    source_scope_label: str | None = None


@dataclass
class FileEntry:
    name: str
    path: str
    is_dir: bool
    size: int | None = None
    modified: str | None = None
    permissions: str | None = None
    owner: str | None = None
    local_path: str | None = None
    sha256: str | None = None


@dataclass
class Evidence:
    evidence_id: str
    target: str
    collector: str
    command_or_action: str
    raw_output_path: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sha256: str | None = None
    notes: str | None = None


# ---------------------------------------------------------------------------
# Enumeration result
# ---------------------------------------------------------------------------

EnumerationStatus = Literal[
    "not_tested", "not_reachable", "blocked", "success", "failed", "partial", "error"
]


@dataclass
class EnumerationResult:
    check_name: str
    status: EnumerationStatus
    success: bool
    summary: str
    details: dict = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Credential / secret scanning
# ---------------------------------------------------------------------------

@dataclass
class CredentialCandidate:
    file_path: str
    match_type: str
    redacted_value: str
    raw_value: str
    line_number: int | None = None
    confidence: Literal["low", "medium", "high"] = "medium"
    evidence_ref: str | None = None

    CredentialStatus = Literal[
        "not_found",
        "candidate_found_not_tested",
        "candidate_found_locked_down_unknown",
        "candidate_valid_for_ftp",
        "candidate_valid_for_other_service",
        "candidate_invalid",
        "candidate_reused",
        "candidate_expired_or_disabled",
    ]
    status: str = "candidate_found_not_tested"


# ---------------------------------------------------------------------------
# Attack path finding
# ---------------------------------------------------------------------------

@dataclass
class AttackPathFinding:
    finding_id: str
    title: str
    category: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    is_attack_path: bool
    attack_path_type: str
    description: str
    evidence_ids: list[str] = field(default_factory=list)
    recommended_next_steps: list[str] = field(default_factory=list)
    report_ready_summary: str = ""


# ---------------------------------------------------------------------------
# Top-level scan report
# ---------------------------------------------------------------------------

@dataclass
class ScanReport:
    target: Target
    enumeration_results: list[EnumerationResult] = field(default_factory=list)
    findings: list[AttackPathFinding] = field(default_factory=list)
    credential_candidates: list[CredentialCandidate] = field(default_factory=list)
    file_inventory: list[FileEntry] = field(default_factory=list)
    downloaded_files: list[FileEntry] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # Convenience flags consumed by the solver / downstream agents
    ftp_reachable: bool = False
    anonymous_login_success: bool = False
    listing_allowed: bool = False
    download_allowed: bool = False
    upload_allowed: bool = False
    credentials_or_configs_found: bool = False
    best_next_action: str = ""

    def result(self, check_name: str) -> EnumerationResult | None:
        for r in self.enumeration_results:
            if r.check_name == check_name:
                return r
        return None

    def highest_severity(self) -> str:
        order = ["critical", "high", "medium", "low", "info"]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return "info"
