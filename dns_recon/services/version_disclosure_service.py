from __future__ import annotations

import logging

from ..models.attempt import Attempt
from ..runners.dig_runner import DigRunner

logger = logging.getLogger(__name__)


class VersionDisclosureService:
    def __init__(self, runner: DigRunner) -> None:
        self._runner = runner

    def check(self, server: str) -> Attempt:
        logger.info("Checking version.bind on %s", server)
        result = self._runner.query_chaos("version.bind", server=server)
        raw = result.stdout + result.stderr

        if result.timed_out:
            status = "timeout"
        elif "version.bind" in raw.lower() and '"' in raw:
            status = "success"
        elif "REFUSED" in raw:
            status = "refused"
        elif result.returncode == 0:
            status = "failure"
        else:
            status = "error"

        version = ""
        if status == "success":
            for line in raw.splitlines():
                if "version.bind" in line.lower() and '"' in line:
                    parts = line.split('"')
                    if len(parts) >= 2:
                        version = parts[1]
                        break

        logger.info("  version.bind: %s (%s)", status, version or "n/a")
        return Attempt(
            category="version_disclosure",
            name=f"version.bind @{server}",
            target=server,
            status=status,
            detail=version or raw[:300],
            raw_output=raw,
        )
