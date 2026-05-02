from __future__ import annotations
import shutil

from .config import ScanContext
from .checks.base import BaseCheck
from .reporters.json_reporter import JsonReporter
from .reporters.markdown_reporter import MarkdownReporter


class DecisionTreeRunner:
    def __init__(self, check_registry: dict, reporters: list | None = None) -> None:
        self._checks = check_registry
        self._reporters = reporters or [JsonReporter(), MarkdownReporter()]

    def run(self, context: ScanContext) -> ScanContext:
        context.decision_trace.append("Target validation completed.")
        self._validate_tools(context)

        self._run_check(context, "service_detection")

        if not context.oracle_detected():
            context.decision_trace.append("Oracle TNS not detected. Stopping scan.")
            return self._finalize(context)

        context.decision_trace.append("Oracle TNS detected. Continuing enumeration.")

        if not context.has_connection_identifiers():
            self._run_check(context, "sid_enum")

        if not context.has_connection_identifiers():
            context.decision_trace.append("No SID or service name discovered. Stopping scan.")
            return self._finalize(context)

        context.decision_trace.append(f"Connection identifiers available: {context.discovered_sids}")

        self._run_check(context, "auth_enum")

        if not context.valid_credentials:
            context.decision_trace.append("No valid credentials discovered. Stopping post-auth checks.")
            return self._finalize(context)

        context.decision_trace.append(f"Valid credentials found: {len(context.valid_credentials)}")

        if context.config.run_post_auth:
            self._run_check(context, "post_auth_enum")
            self._run_check(context, "abuse_path_review")

        context.decision_trace.append("Enumeration complete.")
        return self._finalize(context)

    def _validate_tools(self, context: ScanContext) -> None:
        tool_checks = {
            "nmap": "nmap",
            "odat": context.config.odat_path,
            "hydra": "hydra",
            "sqlplus": context.config.sqlplus_path,
        }
        for name, binary in tool_checks.items():
            available = shutil.which(binary) is not None
            context.tool_status[name] = available

        available = [k for k, v in context.tool_status.items() if v]
        missing = [k for k, v in context.tool_status.items() if not v]
        context.decision_trace.append(
            f"Tool validation: available={available}, missing={missing}"
        )

    def _run_check(self, context: ScanContext, name: str) -> None:
        if name not in self._checks:
            context.decision_trace.append(f"Check '{name}' not in registry. Skipped.")
            return

        check: BaseCheck = self._checks[name]()
        if not check.can_run(context):
            context.decision_trace.append(f"Check '{name}' prerequisites not met. Skipped.")
            return

        context.decision_trace.append(f"Running check: {name}")
        result = check.run(context)
        context.findings.extend(result.findings)
        context.decision_trace.append(f"Check '{name}' complete: {result.status} — {result.notes}")

    def _finalize(self, context: ScanContext) -> ScanContext:
        for reporter in self._reporters:
            try:
                reporter.write(context)
            except Exception as e:
                context.decision_trace.append(f"Reporter {reporter.__class__.__name__} failed: {e}")
        return context
