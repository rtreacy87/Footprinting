from __future__ import annotations

import dataclasses
import json
import logging

from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext
from ..models.tls_result import TlsResult
from ..tools.manual_smtp_tool import ManualSmtpTool
from .base import BaseCheck

logger = logging.getLogger(__name__)


class StartTlsCheck(BaseCheck):
    name = "starttls"

    def run(self, context: ScanContext) -> CheckResult:
        if not context.open_ports:
            return self._skipped(context.target.ip, "No open ports detected")

        logger.info("[starttls] Checking STARTTLS on %s", context.target.ip)

        sessions_dir = context.target_dir / "raw" / "manual_sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        norm_dir = context.target_dir / "normalized"
        norm_dir.mkdir(parents=True, exist_ok=True)

        tool = ManualSmtpTool(host=context.target.ip, timeout=context.timeout)
        findings: list[Finding] = []
        evidence_paths: list[str] = []
        errors: list[str] = []
        tls_results: list[TlsResult] = []

        for port in context.open_ports:
            log_path = sessions_dir / f"starttls_session_{port}.txt"
            try:
                result = tool.run_starttls(
                    port=port,
                    ehlo_domain="pentest.local",
                    session_log=log_path,
                )
                evidence_paths.append(str(log_path))

                tls_res = TlsResult(
                    port=port,
                    starttls_advertised=result["advertised"],
                    starttls_negotiated=result["negotiated"],
                    tls_version=result.get("tls_version", ""),
                    cipher_suite=result.get("cipher", ""),
                    certificate_cn=result.get("cert_cn", ""),
                    errors=[result["error"]] if result.get("error") else [],
                )

                if result["negotiated"]:
                    tls_res.status = "supported"
                elif result["advertised"]:
                    tls_res.status = "failed"
                    findings.append(
                        Finding(
                            title=f"STARTTLS advertised but negotiation failed on port {port}",
                            severity="medium",
                            category="tls",
                            description="Server advertises STARTTLS but TLS handshake failed.",
                            evidence=result.get("error", ""),
                            port=port,
                        )
                    )
                else:
                    tls_res.status = "not_supported"
                    # Not having STARTTLS on port 25/587 is notable
                    if port in (25, 587):
                        findings.append(
                            Finding(
                                title=f"STARTTLS not supported on port {port}",
                                severity="medium",
                                category="tls",
                                description=(
                                    f"Port {port} does not advertise STARTTLS. "
                                    "Mail may be transmitted without encryption."
                                ),
                                remediation="Enable STARTTLS on the SMTP server.",
                                port=port,
                            )
                        )

                tls_results.append(tls_res)
                logger.info(
                    "[starttls] Port %d: advertised=%s negotiated=%s version=%s",
                    port,
                    result["advertised"],
                    result["negotiated"],
                    result.get("tls_version", ""),
                )

            except Exception as exc:
                err_msg = f"Port {port}: {exc}"
                errors.append(err_msg)
                logger.warning("[starttls] %s", err_msg)

        # Write normalized
        norm_path = norm_dir / "tls_results.json"
        norm_path.write_text(
            json.dumps([dataclasses.asdict(r) for r in tls_results], indent=2),
            encoding="utf-8",
        )

        summary = (
            f"STARTTLS supported on ports: "
            f"{[r.port for r in tls_results if r.starttls_negotiated]}"
        )
        status = "success" if tls_results else "failed"
        logger.info("[starttls] Done — %s", summary)

        return CheckResult(
            name=self.name,
            target=context.target.ip,
            port=0,
            status=status,
            summary=summary,
            raw_evidence_paths=evidence_paths,
            normalized_output_paths=[str(norm_path)],
            findings=findings,
            controls_observed=tls_results,
            errors=errors,
        )
