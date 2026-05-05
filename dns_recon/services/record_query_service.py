from __future__ import annotations

from ..models.dns_record import DnsRecord
from ..parsers.dig_parser import DigParser
from ..runners.dig_runner import DigRunner


class RecordQueryService:
    def __init__(self, runner: DigRunner, parser: DigParser) -> None:
        self._runner = runner
        self._parser = parser

    def query(
        self,
        name: str,
        record_type: str,
        server: str | None = None,
    ) -> tuple[list[DnsRecord], str]:
        result = self._runner.query(name=name, record_type=record_type, server=server)
        raw = result.stdout + result.stderr
        records = self._parser.parse(result.stdout, zone=name if record_type == "SOA" else None)
        return records, raw
