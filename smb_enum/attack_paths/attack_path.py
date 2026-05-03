from __future__ import annotations

from ..context import ScanContext
from ..models import AttackPath, BlockedPath
from .rule_registry import RULE_REGISTRY


class AttackPathEvaluator:
    """Runs all registered attack path rules and collects results."""

    def evaluate_all(
        self, context: ScanContext
    ) -> tuple[list[AttackPath], list[BlockedPath]]:
        paths: list[AttackPath] = []
        blocked: list[BlockedPath] = []

        for rule_cls in RULE_REGISTRY:
            rule = rule_cls()
            result = rule.evaluate(context)
            if isinstance(result, AttackPath):
                paths.append(result)
            elif isinstance(result, BlockedPath):
                blocked.append(result)

        return paths, blocked
