from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class CheckResult:
    name: str
    target: str
    port: int
    status: Literal["success", "blocked", "failed", "inconclusive", "skipped"]
    summary: str
    raw_evidence_paths: list[str] = field(default_factory=list)
    normalized_output_paths: list[str] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)
    controls_observed: list[Any] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
