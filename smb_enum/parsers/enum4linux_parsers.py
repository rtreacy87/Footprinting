from __future__ import annotations

import re
from typing import Any

from ..models import Share, User
from .parser import Parser
from .parser_registry import register_parser


@register_parser("enum4linux:shares")
class Enum4LinuxShareParser(Parser):
    """Parses enum4linux / enum4linux-ng share output into Share objects.

    Looks for lines like::
        //target/ShareName  Mapping: OK  Listing: OK
    and also the tabular format from enum4linux-ng JSON output.
    """

    def parse(self, raw_output: str) -> list[Share]:
        shares: list[Share] = []
        seen: set[str] = set()

        for line in raw_output.splitlines():
            # enum4linux classic: //host/sharename  Mapping: ...
            m = re.search(r"//[^/]+/(\S+)\s+Mapping:\s*(\w+)\s+Listing:\s*(\w+)", line, re.IGNORECASE)
            if m:
                name = m.group(1)
                readable = m.group(2).upper() == "OK"
                if name not in seen:
                    shares.append(Share(name=name, readable=readable))
                    seen.add(name)
                continue

            # enum4linux-ng may print: [+] Share: name, ...
            m = re.search(r"\[+\]\s+Share:\s+(\S+)", line, re.IGNORECASE)
            if m:
                name = m.group(1).strip(",")
                if name not in seen:
                    shares.append(Share(name=name))
                    seen.add(name)

        return shares


@register_parser("enum4linux:users")
class Enum4LinuxUserParser(Parser):
    """Parses enum4linux user enumeration output.

    Looks for lines like::
        user:[username] rid:[0x...]
    or the enum4linux-ng YAML/JSON style.
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
