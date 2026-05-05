from __future__ import annotations

from .base import BaseRunner, RunResult


class NmapRunner(BaseRunner):
    @property
    def tool_name(self) -> str:
        return "nmap"

    def build_command(
        self,
        target: str,
        scripts: list[str] | None = None,
        port: int = 53,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        scripts = scripts or ["dns-nsid", "dns-recursion", "dns-service-discovery"]
        script_str = ",".join(scripts)
        cmd = ["nmap", "-sU", "-p", str(port), f"--script={script_str}", target]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def run_dns_scripts(self, target: str, port: int = 53) -> RunResult:
        return self.run(target=target, port=port)

    def run_version_scan(self, target: str, port: int = 53) -> RunResult:
        return self.run(
            target=target,
            port=port,
            scripts=["dns-nsid"],
            extra_args=["-sV"],
        )
