from __future__ import annotations

import logging

from ..models.dns_record import DnsRecord
from ..parsers.dig_parser import DigParser
from ..registries.record_type_registry import BASELINE_RECORD_TYPES
from ..runners.dig_runner import DigRunner
from .record_query_service import RecordQueryService

logger = logging.getLogger(__name__)


class BaselineService:
    def __init__(self, runner: DigRunner, parser: DigParser) -> None:
        self._query_svc = RecordQueryService(runner, parser)

    def run(
        self,
        domain: str,
        server: str | None = None,
        record_types: list[str] | None = None,
    ) -> tuple[dict[str, list[DnsRecord]], dict[str, str]]:
        types = record_types or BASELINE_RECORD_TYPES
        records: dict[str, list[DnsRecord]] = {}
        raw_outputs: dict[str, str] = {}

        for rtype in types:
            logger.info("Querying %s %s", rtype, domain)
            recs, raw = self._query_svc.query(domain, rtype, server)
            records[rtype] = recs
            raw_outputs[rtype] = raw
            logger.debug("  %d records found", len(recs))

        return records, raw_outputs
