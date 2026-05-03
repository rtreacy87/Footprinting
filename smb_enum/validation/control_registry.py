from __future__ import annotations

from typing import Callable

from ..context import ScanContext
from ..models import ControlAssessment

# Maps control_id -> validator function
# Each function takes a ScanContext and returns a ControlAssessment
ControlValidatorFn = Callable[[ScanContext], ControlAssessment]

CONTROL_REGISTRY: dict[str, ControlValidatorFn] = {}


def register_control_validator(control_id: str):
    """Decorator to register a validator function for a control ID."""
    def decorator(fn: ControlValidatorFn) -> ControlValidatorFn:
        CONTROL_REGISTRY[control_id] = fn
        return fn
    return decorator
