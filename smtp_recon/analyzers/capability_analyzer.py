from __future__ import annotations

import json
import logging
from pathlib import Path

from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)


class CapabilityAnalyzer:
    """
    Analyze EHLO/auth capability results to produce consolidated findings.
    Reads normalized ehlo_capabilities.json and auth_methods.json.
    """

    def analyze(self, context: ScanContext, results: list[CheckResult]) -> list[Finding]:
        findings: list[Finding] = []
        norm_dir = context.target_dir / "normalized"

        caps_file = norm_dir / "ehlo_capabilities.json"
        auth_file = norm_dir / "auth_methods.json"

        if caps_file.exists():
            try:
                caps = json.loads(caps_file.read_text(encoding="utf-8"))
                for port_str, cap_list in caps.items():
                    port = int(port_str)
                    keywords = [c.get("keyword", "") for c in cap_list]
                    if "PIPELINING" in keywords:
                        findings.append(
                            Finding(
                                title=f"PIPELINING enabled on port {port}",
                                severity="info",
                                category="capability",
                                description="PIPELINING allows batched commands; can speed up enumeration.",
                                port=port,
                            )
                        )
                    if "VRFY" in keywords:
                        findings.append(
                            Finding(
                                title=f"VRFY capability advertised on port {port}",
                                severity="medium",
                                category="user_enumeration",
                                description="Server explicitly advertises VRFY support.",
                                port=port,
                            )
                        )
            except Exception as exc:
                logger.warning("[capability_analyzer] Failed to read caps: %s", exc)

        if auth_file.exists():
            try:
                auth_list = json.loads(auth_file.read_text(encoding="utf-8"))
                plain_ports = [
                    a["port"] for a in auth_list
                    if a.get("method") in ("PLAIN", "LOGIN") and a.get("advertised_before_tls")
                ]
                for port in set(plain_ports):
                    findings.append(
                        Finding(
                            title=f"Cleartext AUTH (PLAIN/LOGIN) on port {port}",
                            severity="high",
                            category="authentication",
                            description="AUTH PLAIN or LOGIN advertised before TLS upgrade.",
                            remediation="Only advertise AUTH after STARTTLS.",
                            port=port,
                        )
                    )
            except Exception as exc:
                logger.warning("[capability_analyzer] Failed to read auth: %s", exc)

        return findings
