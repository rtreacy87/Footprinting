from __future__ import annotations

import logging
import random
import string

from ..models.attempt import Attempt
from ..parsers.dig_parser import DigParser
from ..runners.dig_runner import DigRunner

logger = logging.getLogger(__name__)


def _random_label(length: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class WildcardService:
    def __init__(self, runner: DigRunner, parser: DigParser, probes: int = 3) -> None:
        self._runner = runner
        self._parser = parser
        self._probes = probes

    def check(self, domain: str, server: str | None = None) -> Attempt:
        logger.info("Checking wildcard DNS for %s", domain)
        hits = 0
        for _ in range(self._probes):
            label = _random_label()
            name = f"{label}.{domain}"
            result = self._runner.query(name=name, record_type="A", server=server)
            records = self._parser.parse(result.stdout)
            if records:
                hits += 1

        if hits == self._probes:
            status = "success"
            detail = f"Wildcard detected: {hits}/{self._probes} random names resolved"
        elif hits > 0:
            status = "partial"
            detail = f"Possible wildcard: {hits}/{self._probes} random names resolved"
        else:
            status = "failure"
            detail = f"No wildcard: 0/{self._probes} random names resolved"

        logger.info("  %s", detail)
        return Attempt(
            category="wildcard_detection",
            name=f"wildcard_check {domain}",
            target=domain,
            status=status,
            detail=detail,
        )
