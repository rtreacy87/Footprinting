from __future__ import annotations
import re

from .base import BaseParser


class NmapServiceDetectionParser(BaseParser):
    name = "nmap_service_detection"

    def parse(self, raw_text: str) -> dict:
        result = {
            "oracle_detected": False,
            "port": None,
            "state": None,
            "service": None,
            "version": None,
        }

        port_match = re.search(r"(\d+)/tcp\s+(open|filtered|closed)\s+(\S+)\s*(.*)", raw_text)
        if port_match:
            result["port"] = int(port_match.group(1))
            result["state"] = port_match.group(2)
            result["service"] = port_match.group(3)
            result["version"] = port_match.group(4).strip()

        oracle_indicators = ["oracle", "tns", "1521"]
        text_lower = raw_text.lower()
        if any(ind in text_lower for ind in oracle_indicators) and result["state"] == "open":
            result["oracle_detected"] = True

        version_match = re.search(r"Oracle TNS listener\s+([\d.]+)", raw_text, re.IGNORECASE)
        if version_match:
            result["version"] = f"Oracle TNS listener {version_match.group(1)}"

        return result


class NmapSidBruteParser(BaseParser):
    name = "nmap_sid_brute"

    def parse(self, raw_text: str) -> dict:
        sids: list[str] = []
        for m in re.finditer(r"Found oracle SID:\s*(\S+)", raw_text, re.IGNORECASE):
            sids.append(m.group(1).strip())

        # Also capture from oracle-sid-brute output format
        for m in re.finditer(r"^\s+(\w+)\s*$", raw_text, re.MULTILINE):
            candidate = m.group(1).strip()
            if 2 <= len(candidate) <= 30 and candidate.isalnum():
                if candidate not in sids and candidate.upper() not in [s.upper() for s in sids]:
                    sids.append(candidate)

        return {
            "sids": sids,
            "confidence": "high" if sids else "none",
            "source": "nmap_oracle_sid_brute",
        }


class NmapOracleBruteParser(BaseParser):
    name = "nmap_oracle_brute"

    def parse(self, raw_text: str) -> dict:
        valid: list[dict] = []
        locked: list[dict] = []

        for m in re.finditer(r"(\w+):(\S+)\s+-\s+([^\n]+)", raw_text):
            user, pwd, status = m.group(1), m.group(2), m.group(3).strip()
            entry = {"username": user, "password": pwd, "status": status}
            if "Account is locked" in status:
                locked.append(entry)
            elif "Login correct" in status or "Valid" in status:
                valid.append(entry)

        return {"valid": valid, "locked": locked}
