from __future__ import annotations
import re

from .base import BaseParser


class OdatAllParser(BaseParser):
    name = "odat_all"

    def parse(self, raw_text: str) -> dict:
        return {
            "raw_output": raw_text[:2000],
            "modules_run": self._extract_modules(raw_text),
            "findings": self._extract_findings(raw_text),
        }

    def _extract_modules(self, text: str) -> list[str]:
        return re.findall(r"\[\+\]\s+(\w+)\s+module", text)

    def _extract_findings(self, text: str) -> list[str]:
        return re.findall(r"\[\+\]\s+(.+)", text)


class OdatSidGuesserParser(BaseParser):
    name = "odat_sidguesser"

    def parse(self, raw_text: str) -> dict:
        sids = re.findall(r"\[\+\]\s+SID[:\s]+(\S+)", raw_text, re.IGNORECASE)
        sids += re.findall(r"'([A-Z][A-Z0-9]{1,29})'\s+is\s+(?:a valid|valid)", raw_text, re.IGNORECASE)
        return {
            "sids": list(dict.fromkeys(sids)),
            "source": "odat_sidguesser",
        }


class OdatPasswordGuesserParser(BaseParser):
    name = "odat_passwordguesser"

    def parse(self, raw_text: str) -> dict:
        valid: list[dict] = []
        for m in re.finditer(r"\[\+\]\s+(\w+)/(\S+)\s+is\s+(?:a\s+)?valid", raw_text, re.IGNORECASE):
            valid.append({"username": m.group(1), "password": m.group(2)})
        return {"valid_credentials": valid, "source": "odat_passwordguesser"}
