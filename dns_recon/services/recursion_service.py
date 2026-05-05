from __future__ import annotations

import logging
import re

from ..models.attempt import Attempt
from ..runners.dig_runner import DigRunner

logger = logging.getLogger(__name__)

_RECURSION_AVAILABLE = re.compile(r"ra", re.IGNORECASE)
_RECURSION_DENIED = re.compile(r"Recursion Denied|REFUSED", re.IGNORECASE)


class RecursionService:
    def __init__(self, runner: DigRunner) -> None:
        self._runner = runner

    def check(self, server: str, test_name: str = "google.com") -> Attempt:
        logger.info("Checking recursion on %s", server)
        cmd = ["dig", f"@{server}", test_name, "A", "+recurse"]
        result = self._runner.run(name=test_name, record_type="A", server=server)
        raw = result.stdout + result.stderr

        if result.timed_out:
            status = "timeout"
        elif _RECURSION_DENIED.search(raw):
            status = "refused"
        elif result.returncode == 0 and result.stdout.strip():
            status = "success"
        else:
            status = "unknown"

        logger.info("  Recursion: %s", status)
        return Attempt(
            category="recursion",
            name=f"recursion_check @{server}",
            target=server,
            status=status,
            detail=raw[:400],
            raw_output=raw,
        )
