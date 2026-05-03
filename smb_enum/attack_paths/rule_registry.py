from __future__ import annotations

from typing import Type

from .rule import AttackPathRule

RULE_REGISTRY: list[Type[AttackPathRule]] = []


def register_rule(cls: Type[AttackPathRule]) -> Type[AttackPathRule]:
    """Class decorator that appends the rule class to RULE_REGISTRY."""
    RULE_REGISTRY.append(cls)
    return cls


# Trigger registration decorators
from . import credential_rules  # noqa: F401, E402
from . import writable_share_rules  # noqa: F401, E402
from . import relay_rules  # noqa: F401, E402
from . import lateral_movement_rules  # noqa: F401, E402
