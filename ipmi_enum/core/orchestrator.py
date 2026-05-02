from __future__ import annotations

from ..config import ScanConfig, ScanProfile
from ..context import ScanContext
from ..core.runner import CommandRunner
from ..credentials.credential_audit import CredentialAuditor
from ..discovery.companion_services import CompanionServiceScanner
from ..discovery.ipmi_discovery import IpmiDiscovery
from ..fingerprinting.vendor_classifier import VendorClassifier
from ..hashes.rakp_dump import RakpDumper
from ..postauth.inventory import PostAuthInventory
from ..reporting.evidence_index import EvidenceIndex
from ..reporting.finding_builder import FindingBuilder
from ..reporting.json_report import JsonReporter
from ..reporting.markdown_report import MarkdownReporter
from ..tools.ipmitool import IpmiTool
from ..tools.metasploit import MetasploitTool
from ..tools.nmap import NmapIpmiTool


class IpmiOrchestrator:
    """Controls the enumeration workflow based on the scan profile."""

    def __init__(self, config: ScanConfig) -> None:
        self._config = config
        runner = CommandRunner(output_base=config.target_output_dir)
        self._nmap = NmapIpmiTool(runner)
        self._msf = MetasploitTool(runner)
        self._ipmitool = IpmiTool(runner)
        self._runner = runner

    def run(self) -> ScanContext:
        context = ScanContext(config=self._config)
        profile = self._config.profile

        # Level 1: Discovery (all profiles)
        IpmiDiscovery(self._nmap).run(context)

        if not context.ipmi_detected:
            context.skip_step("all_subsequent", "IPMI not detected on UDP/623")
            self._report(context)
            return context

        # Level 2: Companion services (standard+)
        if profile not in (ScanProfile.PASSIVE,):
            CompanionServiceScanner(self._nmap).run(context)

        # Level 3: Vendor classification
        VendorClassifier().apply_to_context(context)

        # Level 4: Default credential audit (default-credential-audit profile only)
        if profile == ScanProfile.DEFAULT_CREDENTIAL_AUDIT or self._config.options.enable_default_creds:
            CredentialAuditor(self._ipmitool).run(
                context,
                continue_on_success=self._config.options.continue_on_success,
            )

        # Level 5: RAKP hash retrieval (hash-audit profile or explicit enable)
        if profile == ScanProfile.HASH_AUDIT or self._config.options.enable_rakp:
            user_file = self._config.username_files[0] if self._config.username_files else None
            RakpDumper(self._msf).run(context, user_file=user_file)

        # Level 6: Post-auth inventory (credentialed profile)
        if profile == ScanProfile.CREDENTIALED or (
            self._config.credentials and profile in (ScanProfile.DEFAULT_CREDENTIAL_AUDIT,)
        ):
            valid_creds = [(c.username, c.password) for c in context.credentials
                          if c.status in ("valid", "cracked") and c.password]
            if not valid_creds:
                valid_creds = self._config.credentials
            for username, password in valid_creds[:1]:
                PostAuthInventory(self._ipmitool).run(context, username, password)

        # Build findings
        context.risk_findings = FindingBuilder().build(context)

        self._report(context)
        return context

    def _report(self, context: ScanContext) -> None:
        JsonReporter().write(context)
        MarkdownReporter(redact=self._config.options.redact_secrets).write(context)
        EvidenceIndex().write(context)
