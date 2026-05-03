from __future__ import annotations

from typing import Type

from .reporter import Reporter

REPORTER_REGISTRY: dict[str, Type[Reporter]] = {}


def register_reporter(key: str):
    """Decorator to register a reporter class under a given key."""
    def decorator(cls: Type[Reporter]) -> Type[Reporter]:
        REPORTER_REGISTRY[key] = cls
        return cls
    return decorator


# Trigger registration decorators
from . import markdown_reporter  # noqa: F401, E402
from . import json_reporter  # noqa: F401, E402
from . import executive_reporter  # noqa: F401, E402
