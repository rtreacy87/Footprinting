from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


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
    parsed: bool = False


@dataclass
class IpmiFinding:
    target: str
    ipmi_detected: bool
    port: int = 623
    protocol_version: str | None = None
    user_auth: list[str] = field(default_factory=list)
    pass_auth: list[str] = field(default_factory=list)
    privilege_level: str | None = None
    vendor: str | None = None
    vendor_confidence: float | None = None
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class CredentialFinding:
    target: str
    username: str
    password: str | None
    status: Literal["valid", "invalid", "unknown", "hash_only", "cracked"]
    source: str
    privilege: str | None = None
    raw_hash: str | None = None
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class HashFinding:
    target: str
    username: str
    raw_hash: str
    hash_format: str = "ipmi2_rakp"
    cracked_password: str | None = None
    hashcat_file: str | None = None
    john_file: str | None = None


@dataclass
class CompanionService:
    port: int
    protocol: str
    service: str
    state: str
    banner: str | None = None
    vendor_hint: str | None = None


@dataclass
class RiskFinding:
    finding_id: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    description: str
    evidence: list[str] = field(default_factory=list)
    remediation: str | None = None


@dataclass
class ScanReport:
    target: str
    scan_profile: str
    ipmi: IpmiFinding | None = None
    companion_services: list[CompanionService] = field(default_factory=list)
    credentials: list[CredentialFinding] = field(default_factory=list)
    hashes: list[HashFinding] = field(default_factory=list)
    risk_findings: list[RiskFinding] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    skipped_steps: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
