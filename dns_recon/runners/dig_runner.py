from __future__ import annotations

from .base import BaseRunner, RunResult


class DigRunner(BaseRunner):
    @property
    def tool_name(self) -> str:
        return "dig"

    def build_command(
        self,
        name: str,
        record_type: str = "A",
        server: str | None = None,
        chaos: bool = False,
        axfr: bool = False,
    ) -> list[str]:
        cmd = ["dig"]
        if server:
            cmd.append(f"@{server}")
        if chaos:
            cmd += ["-c", "CHAOS"]
        cmd += [name, record_type]
        if axfr:
            cmd = ["dig", f"@{server}", name, "AXFR"] if server else ["dig", name, "AXFR"]
        cmd += ["+noall", "+answer", "+authority", "+additional"]
        return cmd

    def query(
        self,
        name: str,
        record_type: str = "A",
        server: str | None = None,
    ) -> RunResult:
        return self.run(name=name, record_type=record_type, server=server)

    def query_chaos(self, name: str, server: str | None = None) -> RunResult:
        return self.run(name=name, record_type="TXT", server=server, chaos=True)

    def query_axfr(self, zone: str, server: str) -> RunResult:
        return self.run(name=zone, record_type="AXFR", server=server, axfr=True)

    def query_any(self, name: str, server: str | None = None) -> RunResult:
        return self.run(name=name, record_type="ANY", server=server)
