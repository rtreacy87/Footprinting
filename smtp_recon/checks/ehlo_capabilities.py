from __future__ import annotations

import json
import logging

from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext
from ..models.smtp_capability import SmtpCapability
from ..parsers.ehlo_parser import EhloParser
from ..tools.manual_smtp_tool import ManualSmtpTool
from .base import BaseCheck

logger = logging.getLogger(__name__)


class EhloCapabilitiesCheck(BaseCheck):
    name = "ehlo_capabilities"

    def run(self, context: ScanContext) -> CheckResult:
        if not context.open_ports:
            return self._skipped(context.target.ip, "No open ports detected")

        logger.info("[ehlo_capabilities] Running EHLO against %s", context.target.ip)

        sessions_dir = context.target_dir / "raw" / "manual_sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        norm_dir = context.target_dir / "normalized"
        norm_dir.mkdir(parents=True, exist_ok=True)

        tool = ManualSmtpTool(host=context.target.ip, timeout=context.timeout)
        parser = EhloParser()
        findings: list[Finding] = []
        evidence_paths: list[str] = []
        errors: list[str] = []
        all_caps: dict[int, list[dict]] = {}

        for port in context.open_ports:
            log_path = sessions_dir / f"ehlo_session_{port}.txt"
            try:
                banner, ehlo_resp = tool.run_ehlo(
                    port=port,
                    ehlo_domain="pentest.local",
                    session_log=log_path,
                )
                evidence_paths.append(str(log_path))
                ehlo_result = parser.parse(ehlo_resp)

                caps_serializable = [
                    {"keyword": c.keyword, "parameters": c.parameters}
                    for c in ehlo_result.capabilities
                ]
                all_caps[port] = caps_serializable
                logger.info(
                    "[ehlo_capabilities] Port %d: %d capabilities, auth=%s",
                    port,
                    len(ehlo_result.capabilities),
                    ehlo_result.auth_methods,
                )

                # Check for plaintext AUTH advertised without STARTTLS
                if ehlo_result.auth_methods and not ehlo_result.starttls:
                    findings.append(
                        Finding(
                            title=f"Plaintext AUTH advertised on port {port}",
                            severity="medium",
                            category="authentication",
                            description=(
                                f"AUTH {' '.join(ehlo_result.auth_methods)} offered without STARTTLS. "
                                "Credentials may be transmitted in plaintext."
                            ),
                            evidence=ehlo_resp[:500],
                            remediation="Enforce STARTTLS before advertising AUTH mechanisms.",
                            port=port,
                        )
                    )

                # Plain/LOGIN without TLS is high severity
                weak_auth = [m for m in ehlo_result.auth_methods if m in ("PLAIN", "LOGIN")]
                if weak_auth and not ehlo_result.starttls:
                    findings.append(
                        Finding(
                            title=f"Weak AUTH mechanism (no TLS) on port {port}",
                            severity="high",
                            category="authentication",
                            description=(
                                f"AUTH {' '.join(weak_auth)} transmits credentials in base64 "
                                "without encryption."
                            ),
                            evidence=ehlo_resp[:500],
                            remediation="Require STARTTLS or use port 465 (implicit TLS).",
                            port=port,
                        )
                    )

            except Exception as exc:
                err_msg = f"Port {port}: {exc}"
                errors.append(err_msg)
                logger.warning("[ehlo_capabilities] %s", err_msg)

        # Write normalized capabilities
        norm_path = norm_dir / "ehlo_capabilities.json"
        norm_path.write_text(json.dumps(all_caps, indent=2), encoding="utf-8")
        normalized_paths = [str(norm_path)]

        summary = f"EHLO capabilities collected from ports: {list(all_caps.keys())}"
        status = "success" if all_caps else "failed"
        logger.info("[ehlo_capabilities] Done — %s", summary)

        return CheckResult(
            name=self.name,
            target=context.target.ip,
            port=0,
            status=status,
            summary=summary,
            raw_evidence_paths=evidence_paths,
            normalized_output_paths=normalized_paths,
            findings=findings,
            errors=errors,
        )
