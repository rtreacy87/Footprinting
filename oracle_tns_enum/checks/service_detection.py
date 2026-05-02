from __future__ import annotations

from .base import BaseCheck
from ..config import ScanContext
from ..core.result import CheckResult
from ..models.finding import Finding
from ..parsers.nmap_parser import NmapServiceDetectionParser
from ..tools.nmap import NmapTool


class ServiceDetectionCheck(BaseCheck):
    name = "service_detection"
    required_tools: list[str] = []

    def can_run(self, context: ScanContext) -> bool:
        return context.tool_status.get("nmap", False)

    def run(self, context: ScanContext) -> CheckResult:
        from ..models.target import Target
        target = Target(host=context.target_host, port=context.target_port)
        nmap = NmapTool()
        save_path = context.config.output_base / context.target_host / "raw" / "nmap_service_detection.txt"

        result = nmap.service_detection(target, save_path=save_path)
        parsed = NmapServiceDetectionParser().parse(result.output)

        context.config.output_base.mkdir(parents=True, exist_ok=True)
        import json
        parsed_path = context.config.output_base / context.target_host / "parsed" / "service_detection.json"
        parsed_path.parent.mkdir(parents=True, exist_ok=True)
        parsed_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")

        findings = []
        if parsed.get("oracle_detected"):
            context.tool_status["oracle_detected"] = True
            findings.append(Finding(
                id="ORACLE-TNS-001",
                title="Oracle TNS Listener Exposed",
                severity="Informational",
                category="Service Exposure",
                description=f"Oracle TNS listener detected on {target.host}:{target.port}",
                evidence=[
                    f"TCP/{target.port} open",
                    f"Service: {parsed.get('service')}",
                    f"Version: {parsed.get('version', 'unknown')}",
                ],
                source_tool="nmap",
                recommended_next_steps=[
                    "Enumerate SIDs and service names",
                    "Test default credentials",
                ],
            ))
        else:
            context.tool_status["oracle_detected"] = False

        return CheckResult(
            check_name=self.name,
            status="ok",
            findings=findings,
            notes=[f"Oracle detected: {parsed.get('oracle_detected')}"],
        )
