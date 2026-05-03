from __future__ import annotations

import re
from typing import Any

from .parser import Parser
from .parser_registry import register_parser


@register_parser("smbmap:permissions")
class SmbMapPermissionParser(Parser):
    """Parses smbmap tabular output into a permission map.

    Example smbmap output::

        [+] Guest session   	IP: 10.129.14.128:445	Name: 10.129.14.128
            Disk                                                  	Permissions	Comment
            ----                                                  	-----------	-------
            print$                                            	NO ACCESS
            sambashare                                        	READ ONLY
            DEV                                               	READ, WRITE
            IPC$                                              	NO ACCESS	IPC Service

    Returns a dict: share_name -> {"readable": bool, "writable": bool}
    """

    def parse(self, raw_output: str) -> list[dict]:
        """Returns a list containing a single dict: {share_name: {readable, writable}}."""
        permission_map: dict[str, dict] = {}
        in_table = False

        for line in raw_output.splitlines():
            # Detect header row
            if re.search(r"Disk\s+Permissions", line, re.IGNORECASE):
                in_table = True
                continue
            if in_table and re.match(r"\s*-+\s*-+", line):
                continue

            if in_table:
                # Empty line may end one session block; but smbmap can have multiple
                # Just continue parsing — lines with share info are indented
                stripped = line.strip()
                if not stripped:
                    continue

                # Match: share_name  <spaces>  PERMISSION  <optional comment>
                m = re.match(
                    r"^\s*(\S.*?)\s{2,}(READ,\s*WRITE|READ ONLY|NO ACCESS|READ, WRITE|WRITE ONLY)\s*(.*)$",
                    line,
                    re.IGNORECASE,
                )
                if m:
                    share_name = m.group(1).strip()
                    perm = m.group(2).strip().upper()
                    readable = "READ" in perm
                    writable = "WRITE" in perm
                    permission_map[share_name] = {
                        "readable": readable,
                        "writable": writable,
                    }

        return [permission_map]
