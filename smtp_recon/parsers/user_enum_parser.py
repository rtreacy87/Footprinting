from __future__ import annotations

from typing import Literal

from ..models.smtp_user import SmtpUser
from .base import BaseParser
from .smtp_response_parser import SmtpResponseParser


class UserEnumParser(BaseParser):
    """
    Parse VRFY / EXPN / RCPT TO responses into SmtpUser records.
    Handles canary detection.
    """

    CANARY_USERS = {"notarealuser-canary", "zzz-smtp-recon-canary"}

    def parse(self, raw: str) -> int:
        """Return the numeric response code from a raw SMTP response."""
        p = SmtpResponseParser()
        return p.first_code(raw)

    def classify(self, code: int) -> Literal["confirmed", "rejected", "ambiguous", "blocked"]:
        if code in (250, 251):
            return "confirmed"
        if code in (550, 551, 553):
            return "rejected"
        if code == 252:
            return "ambiguous"
        if code in (502, 500):
            return "blocked"
        return "blocked"

    def build_user(
        self,
        username: str,
        raw_response: str,
        method: Literal["VRFY", "EXPN", "RCPT_TO"],
        port: int,
        canary_confirmed: bool = False,
    ) -> SmtpUser:
        code = self.parse(raw_response)
        is_canary = username.lower() in self.CANARY_USERS

        if canary_confirmed:
            status: Literal["confirmed", "rejected", "ambiguous", "blocked", "unreliable"] = "unreliable"
        else:
            status = self.classify(code)

        return SmtpUser(
            username=username,
            method=method,
            response_code=code,
            response_text=raw_response.split("\n")[0],
            status=status,
            port=port,
            is_canary=is_canary,
        )

    def detect_canary_false_positive(
        self, canary_responses: list[tuple[str, str]]
    ) -> bool:
        """
        Return True if any canary user got a 250/251 response,
        indicating the server confirms all users indiscriminately.
        """
        p = SmtpResponseParser()
        for _user, raw in canary_responses:
            code = p.first_code(raw)
            if code in (250, 251):
                return True
        return False
