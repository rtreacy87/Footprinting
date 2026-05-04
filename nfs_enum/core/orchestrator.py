from __future__ import annotations

from ..access.access_checker import AccessChecker
from ..config import ScanConfig, ScanProfile
from ..context import ScanContext
from ..core.runner import CommandRunner
from ..discovery.nmap_discovery import NmapDiscovery
from ..discovery.rpcinfo_scanner import RpcInfoScanner
from ..enumeration.showmount import ShowmountEnumerator
from ..extraction.file_extractor import FileExtractor
from ..mounts.mount_manager import MountManager
from ..permissions.permission_analyzer import PermissionAnalyzer
from ..reporting.json_reporter import JsonReporter
from ..reporting.markdown_reporter import MarkdownReporter
from ..tools.nmap import NmapNfsTool
from ..tools.rpcinfo import RpcInfoTool
from ..tools.showmount import ShowmountTool
from ..vulnerabilities.vuln_checker import VulnChecker


class NfsOrchestrator:
    def __init__(self, config: ScanConfig) -> None:
        self._config = config
        runner = CommandRunner(output_base=config.target_output_dir)
        self._nmap = NmapNfsTool(runner)
        self._rpcinfo = RpcInfoTool(runner)
        self._showmount = ShowmountTool(runner)

    def run(self) -> ScanContext:
        context = ScanContext(config=self._config)
        profile = self._config.profile

        # Phase 1: Discovery
        NmapDiscovery(self._nmap).run(context)

        if not context.nfs_detected:
            context.skip_step("all_subsequent", "NFS not detected on ports 111/2049")
            self._report(context)
            return context

        RpcInfoScanner(self._rpcinfo).run(context)

        # Phase 2: Enumeration
        ShowmountEnumerator(self._showmount, self._nmap).run(context)

        if not context.exports:
            context.skip_step("mount_attempts", "No exports found")
            self._report(context)
            return context

        # Phase 3: Access checks
        AccessChecker().run(context)

        # Phase 4: Mount attempts (standard+)
        if profile != ScanProfile.DISCOVERY:
            MountManager().run(context)

        # Phase 5: Permissions analysis
        PermissionAnalyzer().run(context)

        # Phase 6: Vulnerability checks
        VulnChecker().run(context)

        self._report(context)
        return context

    def _report(self, context: ScanContext) -> None:
        JsonReporter().write(context)
        MarkdownReporter().write(context)
