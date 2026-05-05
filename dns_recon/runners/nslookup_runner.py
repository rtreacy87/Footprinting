from __future__ import annotations

from .base import BaseRunner, RunResult


class NslookupRunner(BaseRunner):
    @property
    def tool_name(self) -> str:
        return "nslookup"

    def build_command(
        self,
        name: str,
        record_type: str = "A",
        server: str | None = None,
    ) -> list[str]:
        cmd = ["nslookup", f"-type={record_type}", name]
        if server:
            cmd.append(server)
        return cmd

    def query(self, name: str, record_type: str = "A", server: str | None = None) -> RunResult:
        return self.run(name=name, record_type=record_type, server=server)
