from __future__ import annotations

from abc import ABC, abstractmethod

from ..context import ScanContext
from ..models import AttackPath, BlockedPath


class AttackPathRule(ABC):
    """Abstract base class for attack path evaluation rules."""

    @abstractmethod
    def evaluate(self, context: ScanContext) -> AttackPath | BlockedPath | None:
        """Evaluate the rule against the current context.

        Returns:
            - An ``AttackPath`` if the conditions for an attack are met.
            - A ``BlockedPath`` if the attack was specifically prevented.
            - ``None`` if this rule is not applicable.
        """
        ...
