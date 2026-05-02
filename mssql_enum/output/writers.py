"""Orchestrates all output artifact writes."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..config import TargetConfig
from .json_writer import write_json, write_jsonl
from .markdown import write_summary, write_findings


class OutputWriter:
    def __init__(self, config: TargetConfig) -> None:
        self._base = config.target_dir
        self._config = config

    def write_run_metadata(self, mode: str) -> None:
        write_json(
            self._base / "run_metadata.json",
            {
                "target": self._config.target,
                "port": self._config.port,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "mode": mode,
                "package_version": "0.1.0",
                "safe_mode": self._config.safe_mode,
                "auth_mode": self._config.auth_mode,
                "username": self._config.username,
            },
        )

    def write_server_info(self, data: dict) -> None:
        write_json(self._base / "normalized" / "server_identity.json", data.get("identity", {}))
        write_json(self._base / "normalized" / "auth_context.json", data.get("auth_context", {}))
        write_json(self._base / "normalized" / "server_config.json", data.get("config", []))

    def write_databases(self, data: dict) -> None:
        write_json(self._base / "normalized" / "databases.json", data.get("databases", []))
        write_json(self._base / "normalized" / "non_default_databases.json", data.get("non_default_databases", []))
        for db in data.get("non_default_databases", []):
            db_name = db["name"]
            write_json(self._base / "databases" / db_name / "metadata.json", db)
        write_json(self._base / "normalized" / "tables.json", data.get("tables", []))
        write_json(self._base / "normalized" / "columns.json", data.get("columns", []))

    def write_principals(self, data: dict) -> None:
        write_json(self._base / "normalized" / "server_principals.json", data.get("logins", []))
        write_json(self._base / "normalized" / "role_memberships.json", data.get("role_memberships", []))
        write_json(self._base / "normalized" / "privileged_members.json", data.get("privileged_members", []))

    def write_execution_paths(self, data: dict) -> None:
        write_json(self._base / "normalized" / "execution_paths.json", data.get("dangerous_features", []))

    def write_linked_servers(self, data: dict) -> None:
        write_json(self._base / "normalized" / "linked_servers.json", data.get("linked_servers", []))

    def write_agent_jobs(self, data: dict) -> None:
        write_json(self._base / "normalized" / "sql_agent_jobs.json", data.get("jobs", []))
        write_json(self._base / "normalized" / "sql_agent_steps.json", data.get("steps", []))

    def write_sensitive(self, tables: list[dict], columns: list[dict]) -> None:
        write_json(self._base / "findings" / "sensitive_tables.json", tables)
        write_json(self._base / "findings" / "sensitive_columns.json", columns)

    def write_findings(self, findings: list[dict]) -> None:
        write_json(self._base / "findings" / "risk_findings.json", findings)
        write_findings(self._base / "reports" / "findings.md", findings)

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
        write_jsonl(self._base / "raw" / "query_log.jsonl", records)

    def write_reports(self, report_data: dict) -> None:
        write_summary(self._base / "reports" / "summary.md", report_data)
