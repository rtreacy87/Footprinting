"""Detect dangerous execution features (detect only, never enable)."""

from __future__ import annotations

from ..queries import QueryRunner

DANGEROUS_CONFIGS = (
    "xp_cmdshell",
    "Ole Automation Procedures",
    "clr enabled",
    "Ad Hoc Distributed Queries",
    "external scripts enabled",
)


class ExecutionPathsCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        dangerous = self._collect_dangerous_configs()
        return {"dangerous_features": dangerous}

    def _collect_dangerous_configs(self) -> list[dict]:
        names = ", ".join(f"'{n}'" for n in DANGEROUS_CONFIGS)
        result = self._runner.run(
            "dangerous_configs",
            f"""
            SELECT
                name,
                value,
                value_in_use,
                description
            FROM sys.configurations
            WHERE name IN ({names})
            ORDER BY name
            """,
        )
        for row in result.rows:
            row["enabled"] = bool(row.get("value_in_use", 0))
        return result.rows
