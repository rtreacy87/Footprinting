"""Security-relevant server variable collector."""

from __future__ import annotations

from ..queries import QueryRunner

_SECURITY_VARS = (
    "secure_file_priv",
    "local_infile",
    "sql_warnings",
    "log_error",
    "general_log",
    "general_log_file",
    "slow_query_log",
    "slow_query_log_file",
    "plugin_dir",
    "skip_name_resolve",
    "require_secure_transport",
    "have_ssl",
    "ssl_ca",
    "ssl_cert",
    "ssl_key",
)


class VariablesCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        security = self._collect_security_vars()
        status = self._collect_status()
        return {
            "security_variables": security,
            "status_summary": status,
        }

    def _collect_security_vars(self) -> list[dict]:
        names = ", ".join(f"'{v}'" for v in _SECURITY_VARS)
        result = self._runner.run(
            "security_variables",
            f"SHOW VARIABLES WHERE Variable_name IN ({names})",
        )
        return result.rows

    def _collect_status(self) -> dict:
        result = self._runner.run("server_status", "SHOW STATUS")
        interesting = {
            "Uptime", "Connections", "Threads_connected",
            "Aborted_connects", "Ssl_cipher",
        }
        return {
            row["Variable_name"]: row["Value"]
            for row in result.rows
            if row.get("Variable_name") in interesting
        }
