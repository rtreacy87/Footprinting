from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Phase:
    name: str
    description: str
    enabled: bool = True


@dataclass
class PhaseResult:
    phase_name: str
    success: bool
    skipped: bool = False
    error_message: str | None = None
