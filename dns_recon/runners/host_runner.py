from __future__ import annotations

from .base import BaseRunner, RunResult


class HostRunner(BaseRunner):
    @property
    def tool_name(self) -> str:
        return "host"

    def build_command(self, target: str, server: str | None = None) -> list[str]:
        cmd = ["host", target]
        if server:
            cmd.append(server)
        return cmd

    def lookup(self, target: str, server: str | None = None) -> RunResult:
        return self.run(target=target, server=server)

    def reverse_lookup(self, ip: str, server: str | None = None) -> RunResult:
        return self.run(target=ip, server=server)
