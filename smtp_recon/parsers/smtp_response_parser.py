from __future__ import annotations

import re
from dataclasses import dataclass

from .base import BaseParser


@dataclass
class SmtpLine:
    code: int
    continued: bool  # True if the line uses dash (250-), False for final (250 )
    text: str

    def __str__(self) -> str:
        sep = "-" if self.continued else " "
        return f"{self.code}{sep}{self.text}"


class SmtpResponseParser(BaseParser):
    """
    Parse raw multi-line SMTP response text into SmtpLine objects.

    Example input:
        250-SIZE 20480000
        250-STARTTLS
        250 OK
    """

    _LINE_RE = re.compile(r"^(\d{3})([-\s])(.*)")

    def parse(self, raw: str) -> list[SmtpLine]:
        lines = []
        for raw_line in raw.splitlines():
            raw_line = raw_line.strip()
            m = self._LINE_RE.match(raw_line)
            if m:
                code = int(m.group(1))
                continued = m.group(2) == "-"
                text = m.group(3).strip()
                lines.append(SmtpLine(code=code, continued=continued, text=text))
        return lines

    def first_code(self, raw: str) -> int:
        """Return the response code from the first parseable line, or 0."""
        lines = self.parse(raw)
        return lines[0].code if lines else 0

    def all_texts(self, raw: str) -> list[str]:
        """Return all text portions of parsed lines."""
        return [line.text for line in self.parse(raw)]
