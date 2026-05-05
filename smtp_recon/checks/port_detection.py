from __future__ import annotations

import logging
import socket

from ..executors.subprocess_executor import SubprocessExecutor
from ..models.result import CheckResult
from ..models.scan_context import ScanContext
from ..parsers.nmap_parser import NmapParser
from ..tools.nmap_tool import NmapSmtpTool
from .base import BaseCheck

logger = logging.getLogger(__name__)


class PortDetectionCheck(BaseCheck):
    name = "port_detection"

    def run(self, context: ScanContext) -> CheckResult:
        logger.info("[port_detection] Starting port scan against %s", context.target.ip)

        raw_dir = context.target_dir / "raw" / "nmap"
        raw_dir.mkdir(parents=True, exist_ok=True)
        nmap_out = raw_dir / "smtp_port_scan.txt"

        ports = context.target.ports
        open_ports: list[int] = []
        errors: list[str] = []
        evidence_paths: list[str] = []

        # --- nmap scan ---
        executor = SubprocessExecutor(timeout=context.timeout * 4)
        tool = NmapSmtpTool(executor=executor)
        nmap_result = tool.port_scan(
            target=context.target.ip,
            ports=ports,
            timeout=context.timeout * 4,
            output_path=nmap_out,
        )

        if nmap_result.return_code == -2:
            errors.append("nmap not found; falling back to socket connect")
        elif nmap_result.return_code != 0:
            errors.append(f"nmap exited {nmap_result.return_code}: {nmap_result.stderr[:200]}")
        else:
            evidence_paths.append(str(nmap_out))
            parser = NmapParser()
            parsed = parser.parse(nmap_result.stdout)
            nmap_open = [e.port for e in parsed.open_ports]
            logger.info("[port_detection] nmap found open ports: %s", nmap_open)
            open_ports.extend(nmap_open)

        # --- Socket connect fallback / verification ---
        for port in ports:
            if port in open_ports:
                continue
            try:
                with socket.create_connection(
                    (context.target.ip, port), timeout=context.timeout
                ):
                    open_ports.append(port)
                    logger.info("[port_detection] Socket connect: port %d open", port)
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

        open_ports = sorted(set(open_ports))

        # Store open ports in context for downstream checks
        context.open_ports = open_ports

        if not open_ports:
            status = "failed"
            summary = f"No SMTP ports open on {context.target.ip} (checked {ports})"
        else:
            status = "success"
            summary = f"Open SMTP ports: {open_ports}"

        logger.info("[port_detection] Done — %s", summary)
        return CheckResult(
            name=self.name,
            target=context.target.ip,
            port=0,
            status=status,
            summary=summary,
            raw_evidence_paths=evidence_paths,
            errors=errors,
        )
