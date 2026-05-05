from __future__ import annotations

from .smtp_response_parser import SmtpResponseParser


class RelayParser:
    """Parse relay and spoofing test results."""

    def __init__(self) -> None:
        self._p = SmtpResponseParser()

    def is_accepted(self, rcpt_resp: str) -> bool:
        code = self._p.first_code(rcpt_resp)
        return code == 250

    def describe_scenario(
        self,
        mail_from_domain: str,
        rcpt_to_domain: str,
        target_domain: str,
    ) -> str:
        """
        Return human-readable relay scenario label.
        Treats target_domain as 'internal'.
        """
        from_internal = target_domain and target_domain in mail_from_domain
        to_internal = target_domain and target_domain in rcpt_to_domain

        if not from_internal and not to_internal:
            return "external->external"
        if from_internal and not to_internal:
            return "internal->external"
        if not from_internal and to_internal:
            return "external->internal"
        return "internal->internal"
