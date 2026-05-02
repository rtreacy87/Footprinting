"""Collect SQL Agent jobs and steps from msdb (when permitted)."""

from __future__ import annotations

from ..queries import QueryRunner


class AgentJobsCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        jobs = self._collect_jobs()
        steps = self._collect_job_steps() if jobs else []
        return {"jobs": jobs, "steps": steps}

    def _collect_jobs(self) -> list[dict]:
        result = self._runner.run(
            "agent_jobs",
            """
            SELECT
                j.name                                          AS job_name,
                CAST(j.enabled AS INT)                         AS enabled,
                SUSER_SNAME(j.owner_sid)                       AS owner_name,
                CONVERT(VARCHAR(30), j.date_created, 120)      AS date_created,
                CONVERT(VARCHAR(30), j.date_modified, 120)     AS date_modified
            FROM msdb.dbo.sysjobs j
            ORDER BY j.name
            """,
        )
        return result.rows

    def _collect_job_steps(self) -> list[dict]:
        result = self._runner.run(
            "agent_job_steps",
            """
            SELECT
                j.name        AS job_name,
                s.step_id,
                s.step_name,
                s.subsystem,
                s.command,
                s.database_name,
                s.proxy_id
            FROM msdb.dbo.sysjobs j
            JOIN msdb.dbo.sysjobsteps s
                ON j.job_id = s.job_id
            ORDER BY j.name, s.step_id
            """,
        )
        return result.rows
