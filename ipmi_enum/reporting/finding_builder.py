from __future__ import annotations

from ..context import ScanContext
from ..models import RiskFinding


class FindingBuilder:
    """Generates risk findings from scan context."""

    REMEDIATION = {
        "ipmi_exposed": "Restrict UDP/623 to a dedicated management network segment. Block from user networks and internet.",
        "rakp_hash_retrievable": "Use long unique BMC passwords (16+ chars). Segment IPMI access. Consider disabling IPMI over LAN if not required.",
        "default_credential": "Change all default BMC credentials immediately. Use unique passwords per device.",
        "credential_cracked": "Change the cracked credential immediately. Audit all BMC accounts for weak passwords.",
        "web_console_exposed": "Restrict web console access to management networks. Enforce HTTPS.",
        "telnet_exposed": "Disable Telnet on the BMC. Use SSH or web console over HTTPS.",
    }

    def build(self, context: ScanContext) -> list[RiskFinding]:
        findings: list[RiskFinding] = []

        if context.ipmi_finding and context.ipmi_finding.ipmi_detected:
            findings.append(RiskFinding(
                finding_id="IPMI-001",
                title="IPMI Service Exposed on UDP/623",
                severity="medium",
                description=f"IPMI {context.ipmi_finding.protocol_version or ''} detected on {context.target}:623. "
                            "Exposed IPMI allows RAKP hash retrieval without authentication.",
                evidence=context.evidence_refs[:3],
                remediation=self.REMEDIATION["ipmi_exposed"],
            ))

            if context.ipmi_finding.protocol_version and "2.0" in context.ipmi_finding.protocol_version:
                findings.append(RiskFinding(
                    finding_id="IPMI-002",
                    title="IPMI 2.0 RAKP Hash Retrieval Possible",
                    severity="high",
                    description="IPMI 2.0 authentication flaw (CVE-2013-4786) allows retrieval of "
                                "salted HMAC-SHA1 password hashes for valid users without completing authentication.",
                    evidence=context.evidence_refs[:2],
                    remediation=self.REMEDIATION["rakp_hash_retrievable"],
                ))

        for cred in context.credentials:
            if cred.status == "cracked":
                findings.append(RiskFinding(
                    finding_id="IPMI-004",
                    title="BMC Password Cracked Offline",
                    severity="critical",
                    description=f"RAKP hash for user '{cred.username}' was cracked offline. "
                                "This grants full BMC access.",
                    evidence=cred.evidence_refs,
                    remediation=self.REMEDIATION["credential_cracked"],
                ))
            elif cred.status == "valid" and cred.source != "msf_ipmi_dumphashes":
                findings.append(RiskFinding(
                    finding_id="IPMI-003",
                    title="Default BMC Credential Valid",
                    severity="critical",
                    description=f"Default credential '{cred.username}' authenticated successfully.",
                    evidence=cred.evidence_refs,
                    remediation=self.REMEDIATION["default_credential"],
                ))

        for svc in context.companion_services:
            if svc.port == 23:
                findings.append(RiskFinding(
                    finding_id="IPMI-006",
                    title="Telnet Exposed on BMC",
                    severity="high",
                    description="TCP/23 (Telnet) is open on the BMC interface. Telnet transmits credentials in cleartext.",
                    remediation=self.REMEDIATION["telnet_exposed"],
                ))
            elif svc.port in (80, 443, 8080, 8443):
                findings.append(RiskFinding(
                    finding_id="IPMI-005",
                    title="BMC Web Console Exposed",
                    severity="high",
                    description=f"BMC web management console detected on TCP/{svc.port}.",
                    remediation=self.REMEDIATION["web_console_exposed"],
                ))

        return findings
