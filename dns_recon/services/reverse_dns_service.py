from __future__ import annotations

import ipaddress
import logging

from ..models.dns_record import DnsRecord
from ..parsers.dig_parser import DigParser
from ..runners.dig_runner import DigRunner

logger = logging.getLogger(__name__)


class ReverseDnsService:
    def __init__(self, runner: DigRunner, parser: DigParser) -> None:
        self._runner = runner
        self._parser = parser

    def ptr_lookup(self, ip: str, server: str | None = None) -> DnsRecord | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        reverse = addr.reverse_pointer
        result = self._runner.query(name=reverse, record_type="PTR", server=server)
        records = self._parser.parse(result.stdout)
        if records:
            return records[0]
        return None

    def sweep(
        self,
        ip_range: str,
        server: str | None = None,
    ) -> list[DnsRecord]:
        found: list[DnsRecord] = []
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            logger.warning("Invalid IP range: %s", ip_range)
            return found

        hosts = list(network.hosts())
        logger.info("PTR sweep of %d IPs in %s", len(hosts), ip_range)
        for addr in hosts:
            rec = self.ptr_lookup(str(addr), server)
            if rec:
                found.append(rec)

        logger.info("PTR sweep found %d records", len(found))
        return found
