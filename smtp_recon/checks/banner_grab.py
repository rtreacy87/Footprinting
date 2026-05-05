from __future__ import annotations

import logging

from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext
from ..tools.manual_smtp_tool import ManualSmtpTool
from .base import BaseCheck

logger = logging.getLogger(__name__)


class BannerGrabCheck(BaseCheck):
    name = "banner_grab"

    def run(self, context: ScanContext) -> CheckResult:
        if not context.open_ports:
            return self._skipped(context.target.ip, "No open ports detected")

        logger.info("[banner_grab] Grabbing banners from %s", context.target.ip)

        sessions_dir = context.target_dir / "raw" / "manual_sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)

        tool = ManualSmtpTool(host=context.target.ip, timeout=context.timeout)
        findings: list[Finding] = []
        evidence_paths: list[str] = []
        errors: list[str] = []
        banners: dict[int, str] = {}

        for port in context.open_ports:
            log_path = sessions_dir / f"banner_{port}.txt"
            try:
                banner = tool.get_banner(port=port, session_log=log_path)
                banners[port] = banner
                evidence_paths.append(str(log_path))
                logger.info("[banner_grab] Port %d: %s", port, banner[:80])

                # Analyze banner for info disclosure
                if banner:
                    findings.append(
                        Finding(
                            title=f"SMTP Banner on port {port}",
                            severity="info",
                            category="information_disclosure",
                            description=f"SMTP service identified on port {port}",
                            evidence=banner.split("\n")[0],
                            port=port,
                        )
                    )
                    # Check for version disclosure
                    banner_lower = banner.lower()
                    for keyword in ["postfix", "sendmail", "exim", "exchange", "lotus", "qmail"]:
                        if keyword in banner_lower:
                            findings.append(
                                Finding(
                                    title=f"MTA version disclosed on port {port}",
                                    severity="low",
                                    category="information_disclosure",
                                    description=f"Mail server software identified: {keyword}",
                                    evidence=banner.split("\n")[0],
                                    remediation="Consider suppressing banner version information.",
                                    port=port,
                                )
                            )
                            break
            except Exception as exc:
                err_msg = f"Port {port}: {exc}"
                errors.append(err_msg)
                logger.warning("[banner_grab] %s", err_msg)

        # Write normalized summary
        norm_dir = context.target_dir / "normalized"
        norm_dir.mkdir(parents=True, exist_ok=True)
        norm_path = norm_dir / "banners.txt"
        lines = [f"Port {p}: {b.split(chr(10))[0]}" for p, b in banners.items()]
        norm_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        normalized_paths = [str(norm_path)]

        summary = f"Captured banners from ports: {list(banners.keys())}"
        status = "success" if banners else "failed"
        logger.info("[banner_grab] Done — %s", summary)

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
