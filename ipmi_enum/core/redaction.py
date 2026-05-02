from __future__ import annotations

import re


class Redactor:
    _PASSWORD_PATTERN = re.compile(r"(?i)(password[:\s=]+)\S+")
    _HASH_PATTERN = re.compile(r"[0-9a-f]{20,}", re.IGNORECASE)

    def __init__(self, redact_passwords: bool = True, redact_hashes: bool = True) -> None:
        self.redact_passwords = redact_passwords
        self.redact_hashes = redact_hashes

    def redact(self, text: str, extra_secrets: list[str] | None = None) -> str:
        result = text
        if self.redact_passwords:
            result = self._PASSWORD_PATTERN.sub(r"\1[REDACTED]", result)
        if self.redact_hashes:
            result = self._HASH_PATTERN.sub("[HASH_REDACTED]", result)
        if extra_secrets:
            for secret in extra_secrets:
                if secret:
                    result = result.replace(secret, "[REDACTED]")
        return result
