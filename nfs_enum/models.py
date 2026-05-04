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


@dataclass
class RpcService:
    program: str
    version: str
    protocol: str
    port: int
    service_name: str


@dataclass
class NfsExport:
    path: str
    allowed_hosts: str
    nfs_version: str | None = None


@dataclass
class DiscoveryResult:
    target: str
    port_111_open: bool = False
    port_2049_open: bool = False
    nfs_detected: bool = False
    rpc_services: list[RpcService] = field(default_factory=list)
    nmap_raw: str = ""
    rpcinfo_raw: str = ""


@dataclass
class EnumerationResult:
    exports: list[NfsExport] = field(default_factory=list)
    showmount_raw: str = ""
    nfs_scripts_raw: str = ""


@dataclass
class AccessCheck:
    export_path: str
    export_visible: bool
    rpc_accessible: bool
    version_compatible: bool
    notes: str = ""


@dataclass
class MountAttempt:
    attempt_number: int
    export_path: str
    nfs_version: str
    command: str
    stdout: str
    stderr: str
    success: bool
    error: str | None = None
    mount_point: str | None = None
    failure_type: str | None = None
    next_step: str | None = None


@dataclass
class SensitiveFile:
    path: str
    category: Literal["ssh_key", "credential", "config", "flag", "other"]
    content_preview: str | None = None


@dataclass
class ExtractionResult:
    file_tree: str = ""
    sensitive_files: list[SensitiveFile] = field(default_factory=list)
    credentials_found: list[dict] = field(default_factory=list)


@dataclass
class PermissionResult:
    export_path: str
    writable: bool = False
    root_squash_enabled: bool = True
    uid_gid_notes: str = ""
    risk: Literal["low", "medium", "high", "critical"] = "low"


@dataclass
class Vulnerability:
    vuln_type: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    description: str
    exploitable: bool
    requires_pivot: bool = False
    evidence: str = ""


@dataclass
class NfsReport:
    target: str
    scan_profile: str
    discovery: DiscoveryResult | None = None
    enumeration: EnumerationResult | None = None
    access_checks: list[AccessCheck] = field(default_factory=list)
    mount_attempts: list[MountAttempt] = field(default_factory=list)
    extraction: ExtractionResult | None = None
    permissions: list[PermissionResult] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    direct_access: bool = False
    pivot_required: bool = False
    errors: list[str] = field(default_factory=list)
    skipped_steps: list[dict] = field(default_factory=list)
