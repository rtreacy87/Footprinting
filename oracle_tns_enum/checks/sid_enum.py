from __future__ import annotations
import re

from .base import BaseCheck
from ..config import ScanContext
from ..core.result import CheckResult
from ..models.finding import Finding
from ..parsers.nmap_parser import NmapSidBruteParser
from ..tools.nmap import NmapTool


class SidEnumerationCheck(BaseCheck):
    name = "sid_enum"
    required_tools: list[str] = []

    def can_run(self, context: ScanContext) -> bool:
        return context.tool_status.get("nmap", False)

    def run(self, context: ScanContext) -> CheckResult:
        from ..models.target import Target
        target = Target(host=context.target_host, port=context.target_port)
        nmap = NmapTool()
        save_path = context.config.output_base / context.target_host / "raw" / "nmap_sid_brute.txt"

        result = nmap.sid_brute(target, save_path=save_path)
        parsed = NmapSidBruteParser().parse(result.output)

        new_sids = []
        for sid in parsed.get("sids", []):
            sid_upper = sid.upper()
            if sid_upper not in [s.upper() for s in context.discovered_sids]:
                context.discovered_sids.append(sid_upper)
                new_sids.append(sid_upper)

        # Also try common SIDs via wordlist if nmap found nothing
        if not context.discovered_sids and context.config.wordlist_sids.exists():
            wordlist_sids = _try_common_sids(target, context)
            for sid in wordlist_sids:
                if sid.upper() not in [s.upper() for s in context.discovered_sids]:
                    context.discovered_sids.append(sid.upper())
                    new_sids.append(sid.upper())

        import json
        parsed_path = context.config.output_base / context.target_host / "parsed" / "sids.json"
        parsed_path.parent.mkdir(parents=True, exist_ok=True)
        parsed_path.write_text(json.dumps({"sids": context.discovered_sids}, indent=2), encoding="utf-8")

        findings = []
        if new_sids:
            findings.append(Finding(
                id="ORACLE-TNS-002",
                title="SID Discovered Without Authentication",
                severity="Low",
                category="Information Disclosure",
                description=f"Oracle SIDs discovered: {', '.join(new_sids)}",
                evidence=[f"SID {s} found via nmap oracle-sid-brute" for s in new_sids],
                source_tool="nmap",
                recommended_next_steps=[
                    "Test discovered SIDs with default credentials",
                    "Monitor for repeated SID guessing attempts",
                ],
            ))

        return CheckResult(
            check_name=self.name,
            status="ok",
            findings=findings,
            notes=[f"Discovered SIDs: {context.discovered_sids}"],
        )


def _try_common_sids(target, context: ScanContext) -> list[str]:
    """Attempt TCP connection with common SIDs to find valid ones."""
    valid = []
    try:
        import socket
        from ..connection import OracleConnection, OracleConnectionError
        from ..config import ScanConfig
        lib_dir = context.config.oracle_client_lib

        sids = context.config.wordlist_sids.read_text().splitlines()
        sids = [s.strip() for s in sids if s.strip() and not s.startswith("#")]

        for sid in sids:
            try:
                conn = OracleConnection(
                    host=target.host,
                    port=target.port,
                    sid=sid,
                    username="invalid_user_probe",
                    password="invalid",
                    lib_dir=lib_dir,
                )
                conn.close()
                valid.append(sid)
            except OracleConnectionError as e:
                err = str(e)
                if "ORA-01017" in err or "ORA-28000" in err:
                    valid.append(sid)
                elif "ORA-12505" in err or "ORA-12514" in err:
                    pass  # SID/service not found
    except Exception:
        pass
    return valid
