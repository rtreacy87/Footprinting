from __future__ import annotations

import json
import re

from ..context import ScanContext
from ..models import EnumerationResult, NfsExport
from ..tools.nmap import NmapNfsTool
from ..tools.showmount import ShowmountTool

_SHOWMOUNT_LINE_RE = re.compile(r"^(/\S+)\s*(.*)")
_NMAP_EXPORT_RE = re.compile(r"\|\s+(/[^\s]+)")


class ShowmountEnumerator:
    def __init__(self, showmount: ShowmountTool, nmap: NmapNfsTool) -> None:
        self._showmount = showmount
        self._nmap = nmap

    def run(self, context: ScanContext) -> None:
        enum = EnumerationResult()

        # showmount -e
        sm_result = self._showmount.show_exports(context.target)
        raw_path = context.path("enumeration", "showmount_raw.txt")
        raw_path.write_text(sm_result.stdout + sm_result.stderr, encoding="utf-8")
        enum.showmount_raw = sm_result.stdout

        exports = self._parse_showmount(sm_result.stdout)

        # nmap nfs-showmount as fallback/supplement
        nmap_result = self._nmap.showmount_script(
            context.target,
            timeout=context.config.options.nmap_timeout_seconds,
        )
        context.path("enumeration", "nfs_scripts_raw.txt").write_text(
            nmap_result.stdout + nmap_result.stderr, encoding="utf-8"
        )
        enum.nfs_scripts_raw = nmap_result.stdout

        if not exports:
            exports = self._parse_nmap_showmount(nmap_result.stdout)

        enum.exports = exports

        context.path("enumeration", "exports.json").write_text(
            json.dumps(
                {"exports": [{"path": e.path, "allowed_hosts": e.allowed_hosts} for e in exports]},
                indent=2,
            ),
            encoding="utf-8",
        )

        context.enumeration = enum

    def _parse_showmount(self, output: str) -> list[NfsExport]:
        exports: list[NfsExport] = []
        in_list = False
        for line in output.splitlines():
            if "Export list" in line:
                in_list = True
                continue
            if in_list:
                m = _SHOWMOUNT_LINE_RE.match(line.strip())
                if m:
                    exports.append(NfsExport(path=m.group(1), allowed_hosts=m.group(2).strip() or "*"))
        return exports

    def _parse_nmap_showmount(self, output: str) -> list[NfsExport]:
        exports: list[NfsExport] = []
        in_block = False
        for line in output.splitlines():
            if "nfs-showmount" in line:
                in_block = True
                continue
            if in_block:
                stripped = line.strip()
                if stripped.startswith("|"):
                    m = _NMAP_EXPORT_RE.search(stripped)
                    if m:
                        path = m.group(1).rstrip()
                        exports.append(NfsExport(path=path, allowed_hosts="*"))
                else:
                    in_block = False
        return exports
