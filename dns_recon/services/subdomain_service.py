from __future__ import annotations

import logging
from pathlib import Path

from ..models.dns_record import DnsRecord
from ..parsers.dig_parser import DigParser
from ..runners.dig_runner import DigRunner
from ..runners.dnsenum_runner import DnsenumRunner

logger = logging.getLogger(__name__)


class SubdomainService:
    def __init__(
        self,
        dig_runner: DigRunner,
        dig_parser: DigParser,
        dnsenum_runner: DnsenumRunner | None = None,
    ) -> None:
        self._dig = dig_runner
        self._parser = dig_parser
        self._dnsenum = dnsenum_runner

    def brute_force(
        self,
        domain: str,
        wordlist: str | Path,
        server: str | None = None,
        limit: int = 5000,
    ) -> list[DnsRecord]:
        wl = Path(wordlist)
        if not wl.exists():
            logger.warning("Wordlist not found: %s", wl)
            return []

        words = []
        for line in wl.read_text(errors="ignore").splitlines():
            w = line.strip()
            if w and not w.startswith("#"):
                words.append(w)
                if len(words) >= limit:
                    break

        found: list[DnsRecord] = []
        logger.info("Brute-forcing %d words against %s", len(words), domain)
        for word in words:
            fqdn = f"{word}.{domain}"
            result = self._dig.query(name=fqdn, record_type="A", server=server)
            records = self._parser.parse(result.stdout)
            if records:
                found.extend(records)
                logger.debug("  Found: %s", fqdn)

        logger.info("Brute-force found %d records", len(found))
        return found

    def run_dnsenum(
        self,
        domain: str,
        server: str | None = None,
        wordlist: str | None = None,
        threads: int = 10,
    ) -> tuple[list[DnsRecord], str]:
        if self._dnsenum is None:
            return [], ""
        result = self._dnsenum.enumerate(
            domain=domain, server=server, wordlist=wordlist, threads=threads
        )
        records = self._parser.parse(result.stdout)
        return records, result.stdout
