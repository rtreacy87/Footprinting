from __future__ import annotations

import re
from typing import Any

from ..models import Group, User
from .parser import Parser
from .parser_registry import register_parser


@register_parser("rpcclient:users")
class RpcClientUserParser(Parser):
    """Parses rpcclient ``enumdomusers`` output into User objects.

    Example line::
        user:[Administrator] rid:[0x1f4]
    """

    def parse(self, raw_output: str) -> list[User]:
        users: list[User] = []
        for line in raw_output.splitlines():
            m = re.search(r"user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", line, re.IGNORECASE)
            if m:
                users.append(User(
                    username=m.group(1).strip(),
                    rid=m.group(2).strip(),
                ))
        return users


@register_parser("rpcclient:groups")
class RpcClientGroupParser(Parser):
    """Parses rpcclient ``enumdomgroups`` output into Group objects.

    Example line::
        group:[Domain Admins] rid:[0x200]
    """

    def parse(self, raw_output: str) -> list[Group]:
        groups: list[Group] = []
        for line in raw_output.splitlines():
            m = re.search(r"group:\[([^\]]+)\]\s+rid:\[([^\]]+)\]", line, re.IGNORECASE)
            if m:
                groups.append(Group(
                    name=m.group(1).strip(),
                    rid=m.group(2).strip(),
                ))
        return groups


@register_parser("rpcclient:domain")
class RpcClientDomainParser(Parser):
    """Parses rpcclient ``querydominfo`` output for Domain name.

    Example line::
        Domain:		INLANEFREIGHT
    """

    def parse(self, raw_output: str) -> list[str]:
        for line in raw_output.splitlines():
            m = re.match(r"Domain:\s*(.+)", line, re.IGNORECASE)
            if m:
                return [m.group(1).strip()]
        return []


@register_parser("rpcclient:share_info")
class RpcClientShareInfoParser(Parser):
    """Parses rpcclient ``netsharegetinfo`` output.

    Returns a list containing a single dict with keys:
        remark, win_path, unix_path
    """

    def parse(self, raw_output: str) -> list[dict]:
        info: dict = {}
        for line in raw_output.splitlines():
            # netname / remark / path
            m = re.match(r"\s*remark\s*:\s*(.*)", line, re.IGNORECASE)
            if m:
                info["remark"] = m.group(1).strip()
                continue
            m = re.match(r"\s*path\s*:\s*(.*)", line, re.IGNORECASE)
            if m:
                path_val = m.group(1).strip()
                info["win_path"] = path_val
                # Convert Windows path to Unix approximation
                info["unix_path"] = path_val.replace("\\", "/").lstrip("/")
                continue
        return [info] if info else []
