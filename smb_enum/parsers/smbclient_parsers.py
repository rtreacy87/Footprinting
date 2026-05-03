from __future__ import annotations

import re
from typing import Any

from ..models import FileMetadata, Share
from .parser import Parser
from .parser_registry import register_parser


@register_parser("smbclient:share_list")
class SmbClientShareListParser(Parser):
    """Parses ``smbclient -N -L //host`` output into a list of Share objects.

    Example smbclient output block::

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        sambashare      Disk      InFreight SMB v3.1
        IPC$            IPC       IPC Service (InlaneFreight SMB server)

    Lines may also appear as tab-separated fields starting with a leading tab.
    """

    def parse(self, raw_output: str) -> list[Share]:
        shares: list[Share] = []
        in_block = False

        for line in raw_output.splitlines():
            # Detect start of share block
            if re.search(r"Sharename\s+Type\s+Comment", line, re.IGNORECASE):
                in_block = True
                continue
            if in_block and re.match(r"^[-\s]+$", line):
                continue

            if in_block:
                # End of share block
                if not line.strip():
                    continue
                # Lines like: "    ShareName       Disk      Comment here"
                # or with leading tab: "\tShareName\tDisk\tComment"
                stripped = line.strip()
                if not stripped:
                    continue
                # Split on 2+ whitespace to handle aligned columns
                parts = re.split(r"\s{2,}", stripped)
                if len(parts) >= 2:
                    name = parts[0].strip()
                    share_type = parts[1].strip() if len(parts) > 1 else None
                    comment = parts[2].strip() if len(parts) > 2 else None
                    if name and not name.startswith("-"):
                        shares.append(Share(
                            name=name,
                            comment=comment,
                            share_type=share_type,
                        ))

        return shares


@register_parser("smbclient:file_list")
class SmbClientFileListParser(Parser):
    """Parses ``smbclient -c 'recurse;ls'`` output into FileMetadata objects.

    Example output::

      \\Users\\Public
        .                                   D        0  Mon Jan  1 00:00:00 2024
        ..                                  D        0  Mon Jan  1 00:00:00 2024
        Desktop                             D        0  Mon Jan  1 00:00:00 2024
        flag.txt                            N    12345  Mon Jan  1 12:34:56 2024

    Directory context lines start with ``\\`` or ``\\.``.
    File lines are indented with 2 spaces and contain a name, type flag, size,
    and timestamp.
    """

    def parse(self, raw_output: str) -> list[FileMetadata]:
        files: list[FileMetadata] = []
        current_dir = ""

        for line in raw_output.splitlines():
            # Directory context: lines starting with backslash (no leading space)
            # e.g.  \directory\path  OR  \\directory\path
            if line.startswith("\\") or line.startswith("\\."):
                current_dir = line.strip().replace("\\\\", "\\")
                continue

            # File entry lines start with whitespace
            if not line.startswith(" ") and not line.startswith("\t"):
                continue

            stripped = line.strip()
            if not stripped or stripped in (".", ".."):
                continue

            # Pattern: name<spaces>type_flag<spaces>size<spaces>timestamp
            # e.g.  flag.txt                            N    12345  Mon Jan  1 12:34:56 2024
            m = re.match(
                r"^(.+?)\s{2,}([DNHR]+|-)\s+(-?\d+)\s+(.+)$",
                stripped,
            )
            if m:
                filename = m.group(1).strip()
                size_str = m.group(3).strip()
                modified = m.group(4).strip()

                if filename in (".", ".."):
                    continue

                try:
                    size = int(size_str)
                except ValueError:
                    size = 0

                path = f"{current_dir}\\{filename}" if current_dir else f"\\{filename}"
                path = path.replace("\\\\", "\\")

                files.append(FileMetadata(
                    path=path,
                    share="",  # caller fills in share name
                    size=size,
                    modified=modified,
                ))

        return files
