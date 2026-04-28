"""Orchestrates writing all output artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..config import TargetConfig
from .json_writer import write_json, write_jsonl
from .markdown import write_summary, write_findings, write_llm_context


class OutputWriter:
    def __init__(self, config: TargetConfig) -> None:
        self._base = config.target_dir
        self._config = config

    def write_run_metadata(self, mode: str, password_supplied: bool) -> None:
        write_json(
            self._base / "run_metadata.json",
            {
                "target": self._config.target,
                "port": self._config.port,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "mode": mode,
                "package_version": "0.1.0",
                "safe_mode": self._config.safe_mode,
                "username": self._config.username,
                "password_supplied": password_supplied,
            },
        )

    def write_discovery(self, discovery: dict) -> None:
        write_json(self._base / "metadata" / "service.json", discovery)

    def write_service(self, service: dict) -> None:
        write_json(self._base / "metadata" / "service.json", service)

    def write_server_variables(self, variables: dict) -> None:
        write_json(self._base / "metadata" / "server_variables.json", variables)
        write_json(self._base / "metadata" / "security_findings.json", variables.get("security_variables", []))

    def write_authentication(self, auth: dict) -> None:
        write_json(self._base / "access" / "authentication.json", auth)
        write_json(self._base / "access" / "current_user.json", auth.get("identity", {}))

    def write_users(self, users: dict) -> None:
        write_json(self._base / "access" / "users.json", users.get("users", {}))
        write_json(self._base / "access" / "roles.json", users.get("roles", {}))
        write_json(self._base / "access" / "grants.json", {"grants": users.get("grants", [])})

    def write_schema(self, schema: dict) -> None:
        write_json(self._base / "schema" / "databases.json", schema.get("databases", []))
        write_json(self._base / "schema" / "tables.json", schema.get("tables", []))
        write_json(self._base / "schema" / "columns.json", schema.get("columns", []))
        write_json(self._base / "schema" / "indexes.json", schema.get("indexes", []))

    def write_routines(self, routines: dict) -> None:
        write_json(self._base / "schema" / "routines.json", routines)

    def write_privileges(self, privileges: dict) -> None:
        write_json(self._base / "access" / "privilege_summary.json", privileges)

    def write_findings(self, findings: list[dict]) -> None:
        write_json(self._base / "metadata" / "security_findings.json", findings)
        write_findings(self._base / "reports" / "findings.md", findings)

    def write_samples(self, samples: list[dict]) -> None:
        for sample in samples:
            db = sample["database"]
            table = sample["table"]
            write_json(
                self._base / "data" / "samples" / db / f"{table}.json",
                sample,
            )

    def write_query_log(self, log: list) -> None:
        records = [
            {
                "query_name": r.query_name,
                "sql": r.sql,
                "success": r.success,
                "error": r.error,
                "started_at": r.started_at.isoformat(),
                "finished_at": r.finished_at.isoformat(),
                "row_count": len(r.rows),
            }
            for r in log
        ]
        write_jsonl(self._base / "raw" / "mysql_query_log.jsonl", records)

    def write_reports(self, report_data: dict) -> None:
        write_summary(self._base / "reports" / "summary.md", report_data)
        write_llm_context(self._base / "reports" / "llm_review_context.md", report_data)
