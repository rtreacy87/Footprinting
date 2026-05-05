from __future__ import annotations

import logging

from ..models.attempt import Attempt
from ..models.dns_record import DnsRecord
from ..parsers.zone_transfer_parser import ZoneTransferParser
from ..runners.dig_runner import DigRunner

logger = logging.getLogger(__name__)


class ZoneTransferService:
    def __init__(self, runner: DigRunner, parser: ZoneTransferParser) -> None:
        self._runner = runner
        self._parser = parser

    def attempt(
        self, zone: str, nameserver: str
    ) -> tuple[Attempt, list[DnsRecord]]:
        logger.info("Attempting AXFR: %s @%s", zone, nameserver)
        result = self._runner.query_axfr(zone=zone, server=nameserver)
        raw = result.stdout

        status = self._parser.classify_result(raw, result.returncode, result.timed_out)
        records = []
        if status == "success":
            records = self._parser.parse(raw, zone=zone)
            logger.info("  Zone transfer succeeded: %d records", len(records))
        else:
            logger.info("  Zone transfer %s", status)

        attempt = Attempt(
            category="zone_transfer",
            name=f"AXFR {zone} @{nameserver}",
            target=nameserver,
            status=status,
            detail=f"{len(records)} records" if status == "success" else raw[:300],
            raw_output=raw,
            records_found=[r.to_dict() for r in records],
        )
        return attempt, records

    def attempt_all(
        self, zone: str, nameservers: list[str]
    ) -> tuple[list[Attempt], list[DnsRecord]]:
        all_attempts: list[Attempt] = []
        all_records: list[DnsRecord] = []
        for ns in nameservers:
            attempt, records = self.attempt(zone, ns)
            all_attempts.append(attempt)
            all_records.extend(records)
            if attempt.status == "success":
                break
        return all_attempts, all_records
