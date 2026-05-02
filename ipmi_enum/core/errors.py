class IpmiEnumError(Exception):
    pass


class ToolMissingError(IpmiEnumError):
    def __init__(self, tool: str) -> None:
        super().__init__(f"Required tool not found: {tool}")
        self.tool = tool


class CommandTimeoutError(IpmiEnumError):
    def __init__(self, tool: str, timeout: int) -> None:
        super().__init__(f"{tool} timed out after {timeout}s")
        self.tool = tool
        self.timeout = timeout


class ParseError(IpmiEnumError):
    def __init__(self, parser: str, detail: str) -> None:
        super().__init__(f"Parser {parser} failed: {detail}")
        self.parser = parser


class CredentialRejectedError(IpmiEnumError):
    def __init__(self, username: str) -> None:
        super().__init__(f"Credential rejected for user: {username}")
        self.username = username


class UnsafeCommandBlockedError(IpmiEnumError):
    def __init__(self, command: str) -> None:
        super().__init__(f"Unsafe command blocked: {command}")
        self.command = command


class UnsupportedProfileError(IpmiEnumError):
    def __init__(self, profile: str) -> None:
        super().__init__(f"Unsupported execution profile: {profile}")
        self.profile = profile
