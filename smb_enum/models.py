from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Target:
    host: str
    ports: list[int] = field(default_factory=lambda: [445, 139])
    domain: str | None = None


@dataclass
class Credential:
    username: str | None = None
    password: str | None = None
    domain: str | None = None
    ntlm_hash: str | None = None
    source: str = "manual"


@dataclass
class CommandSpec:
    tool_name: str
    argv: list[str]
    timeout_seconds: int = 120
    cwd: str | None = None
    env: dict[str, str] | None = None
    sensitive_args: list[str] = field(default_factory=list)


@dataclass
class CommandResult:
    command_id: str
    tool_name: str
    return_code: int
    stdout: str
    stderr: str
    stdout_path: str | None
    stderr_path: str | None
    started_at: str
    ended_at: str
    command: str = ""


@dataclass
class Share:
    name: str
    comment: str | None = None
    share_type: str | None = None
    readable: bool | None = None
    writable: bool | None = None
    anonymous_access: bool | None = None
    file_count: int = 0


@dataclass
class FileMetadata:
    path: str
    share: str
    size: int = 0
    modified: str | None = None


@dataclass
class FileFinding:
    path: str
    share: str
    file_type: str
    risk_score: int
    matched_rules: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    content_excerpt: str | None = None


@dataclass
class TestResult:
    test_id: str
    name: str
    category: str
    tool: str
    command: str
    status: str
    evidence_ids: list[str] = field(default_factory=list)
    confidence: str = "unknown"
    notes: str | None = None
    expected_secure_result: str | None = None
    actual_result: str | None = None


@dataclass
class Evidence:
    evidence_id: str
    source_tool: str
    raw_path: str
    parsed_path: str | None = None
    summary: str = ""
    confidence: str = "medium"


@dataclass
class ControlAssessment:
    control_id: str
    name: str
    status: str
    evidence_ids: list[str] = field(default_factory=list)
    confidence: str = "unknown"
    reason: str = ""


@dataclass
class AttackPath:
    path_id: str
    title: str
    description: str
    required_conditions: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    confidence: str = "medium"
    impact: str = ""
    next_steps: list[str] = field(default_factory=list)


@dataclass
class BlockedPath:
    path_id: str
    title: str
    blocked_by: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    confidence: str = "medium"
    reason: str = ""


@dataclass
class User:
    username: str
    rid: str | None = None
    full_name: str | None = None
    description: str | None = None
    flags: str | None = None


@dataclass
class Group:
    name: str
    rid: str | None = None
    members: list[str] = field(default_factory=list)


@dataclass
class ProtocolSecurityInfo:
    smb_versions: list[str] = field(default_factory=list)
    signing_enabled: bool | None = None
    signing_required: bool | None = None
    smb1_enabled: bool | None = None
    dialect: str | None = None


@dataclass
class ScanReport:
    target: str
    scan_profile: str
    shares: list[Share] = field(default_factory=list)
    users: list[User] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    test_results: list[TestResult] = field(default_factory=list)
    control_assessments: list[ControlAssessment] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    blocked_paths: list[BlockedPath] = field(default_factory=list)
    file_findings: list[FileFinding] = field(default_factory=list)
    protocol_info: ProtocolSecurityInfo | None = None
    errors: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
