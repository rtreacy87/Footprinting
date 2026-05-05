from __future__ import annotations

from .base import BaseRunner, RunResult


class DnsenumRunner(BaseRunner):
    @property
    def tool_name(self) -> str:
        return "dnsenum"

    def build_command(
        self,
        domain: str,
        server: str | None = None,
        wordlist: str | None = None,
        threads: int = 10,
        no_reverse: bool = True,
    ) -> list[str]:
        cmd = ["dnsenum", "--nocolor"]
        if server:
            cmd += ["--dnsserver", server]
        if wordlist:
            cmd += ["-f", wordlist, "--threads", str(threads)]
        if no_reverse:
            cmd.append("--noreverse")
        cmd.append(domain)
        return cmd

    def enumerate(
        self,
        domain: str,
        server: str | None = None,
        wordlist: str | None = None,
        threads: int = 10,
    ) -> RunResult:
        return self.run(domain=domain, server=server, wordlist=wordlist, threads=threads)
