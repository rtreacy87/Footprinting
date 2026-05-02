from __future__ import annotations

from .base import BaseCheck
from ..config import ScanContext
from ..core.result import CheckResult
from ..models.finding import Finding
from ..tools.nmap import NmapTool


class ListenerEnumerationCheck(BaseCheck):
    name = "listener_enum"
    required_tools: list[str] = []

    def can_run(self, context: ScanContext) -> bool:
        return context.oracle_detected() and context.tool_status.get("nmap", False)

    def run(self, context: ScanContext) -> CheckResult:
        from ..models.target import Target
        target = Target(host=context.target_host, port=context.target_port)
        nmap = NmapTool()

        # Run TNS version probe
        save_path = context.config.output_base / context.target_host / "raw" / "nmap_tns_version.txt"
        result = nmap.service_detection(target, save_path=save_path)

        findings: list[Finding] = []
        import re
        version_m = re.search(r"Oracle TNS listener\s+([\d.]+)", result.output, re.IGNORECASE)
        if version_m:
            version = version_m.group(1)
            findings.append(Finding(
                id="ORACLE-TNS-LISTENER-001",
                title="Oracle TNS Listener Version Identified",
                severity="Informational",
                category="Service Information",
                description=f"Oracle TNS listener version {version} identified",
                evidence=[f"Version: {version}"],
                source_tool="nmap",
                recommended_next_steps=["Check for known vulnerabilities in this version"],
            ))

        return CheckResult(
            check_name=self.name,
            status="ok",
            findings=findings,
            notes=[f"Listener output: {len(result.output)} chars"],
        )
