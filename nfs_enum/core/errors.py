from __future__ import annotations


class NfsEnumError(Exception):
    pass


class CommandTimeoutError(NfsEnumError):
    def __init__(self, tool: str, timeout: int) -> None:
        super().__init__(f"{tool} timed out after {timeout}s")
        self.tool = tool
        self.timeout = timeout


class NfsNotDetectedError(NfsEnumError):
    pass


class NoExportsError(NfsEnumError):
    pass
