"""Top-level enumerator — orchestrates all collection phases."""

from __future__ import annotations

import socket

from rich.console import Console

from .config import TargetConfig
from .connection import MSSQLConnection, ImpacketConnection, ConnectionError, open_connection
from .queries import QueryRunner
from .collectors.server_info import ServerInfoCollector
from .collectors.databases import DatabaseCollector
from .collectors.principals import PrincipalsCollector
from .collectors.execution_paths import ExecutionPathsCollector
from .collectors.linked_servers import LinkedServerCollector
from .collectors.agent_jobs import AgentJobsCollector
from .analyzers.findings import FindingsEngine
from .analyzers.sensitive import find_sensitive_tables, find_sensitive_columns
from .output.writers import OutputWriter

console = Console(stderr=True)


class EnumerationResult:
    def __init__(self) -> None:
        self.reachable: bool = False
        self.authenticated: bool = False
        self.identity: dict = {}
        self.auth_context: dict = {}
        self.databases: list[dict] = []
        self.non_default_databases: list[dict] = []
        self.tables: list[dict] = []
        self.columns: list[dict] = []
        self.logins: list[dict] = []
        self.role_memberships: list[dict] = []
        self.linked_servers: list[dict] = []
        self.agent_jobs: list[dict] = []
        self.dangerous_features: list[dict] = []
        self.findings: list[dict] = []
        self.error: str | None = None


class MSSQLEnumerator:
    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._writer = OutputWriter(config)

    def check_reachable(self) -> bool:
        try:
            with socket.create_connection(
                (self._config.target, self._config.port),
                timeout=self._config.timeout_seconds,
            ):
                return True
        except OSError:
            return False

    def run_discover(self) -> EnumerationResult:
        result = EnumerationResult()
        console.print(f"[bold cyan][*][/] Probing {self._config.target}:{self._config.port}")
        self._writer.write_run_metadata("discover")

        result.reachable = self.check_reachable()
        if not result.reachable:
            result.error = "TCP connection refused or timed out"
            console.print(f"[red][-][/] {result.error}")
        else:
            console.print(f"[green][+][/] Port {self._config.port} is open")
        return result

    def run_enum(self) -> EnumerationResult:
        result = EnumerationResult()
        console.print(f"[bold cyan][*][/] Enumerating {self._config.target}:{self._config.port}")
        self._writer.write_run_metadata("enum")

        result.reachable = self.check_reachable()
        if not result.reachable:
            result.error = "TCP connection refused or timed out"
            console.print(f"[red][-][/] {result.error}")
            return result

        try:
            with open_connection(self._config) as conn:
                result.authenticated = True
                backend = "impacket" if isinstance(conn, ImpacketConnection) else "pymssql"
                console.print(f"[green][+][/] Authenticated as {self._config.username} (backend: {backend})")
                runner = QueryRunner(conn)
                self._collect_all(runner, result)
        except ConnectionError as e:
            result.error = str(e)
            result.authenticated = False
            console.print(f"[red][-][/] Authentication failed: {e}")

        return result

    def _collect_all(self, runner: QueryRunner, result: EnumerationResult) -> None:
        server_data = ServerInfoCollector(runner).collect()
        result.identity = server_data.get("identity", {})
        result.auth_context = server_data.get("auth_context", {})
        self._writer.write_server_info(server_data)
        console.print(f"[green][+][/] Host: {result.identity.get('machine_name', 'N/A')} — Version: {result.identity.get('product_version', 'N/A')}")

        db_data = DatabaseCollector(runner).collect()
        result.databases = db_data.get("databases", [])
        result.non_default_databases = db_data.get("non_default_databases", [])
        result.tables = db_data.get("tables", [])
        result.columns = db_data.get("columns", [])
        self._writer.write_databases(db_data)
        console.print(f"[green][+][/] Databases: {len(result.databases)} total, {len(result.non_default_databases)} non-default")

        principals_data = PrincipalsCollector(runner).collect()
        result.logins = principals_data.get("logins", [])
        result.role_memberships = principals_data.get("role_memberships", [])
        self._writer.write_principals(principals_data)

        exec_data = ExecutionPathsCollector(runner).collect()
        result.dangerous_features = exec_data.get("dangerous_features", [])
        self._writer.write_execution_paths(exec_data)

        linked_data = LinkedServerCollector(runner).collect()
        result.linked_servers = linked_data.get("linked_servers", [])
        self._writer.write_linked_servers(linked_data)

        agent_data = AgentJobsCollector(runner).collect()
        result.agent_jobs = agent_data.get("jobs", [])
        self._writer.write_agent_jobs(agent_data)

        sensitive_tables = find_sensitive_tables(result.tables)
        sensitive_columns = find_sensitive_columns(result.columns)
        self._writer.write_sensitive(sensitive_tables, sensitive_columns)

        engine = FindingsEngine()
        findings = engine.analyze(
            auth_context=result.auth_context,
            config=server_data.get("config", []),
            logins=result.logins,
            role_memberships=result.role_memberships,
            linked_servers=result.linked_servers,
            agent_jobs=result.agent_jobs,
            agent_steps=agent_data.get("steps", []),
            dangerous_features=result.dangerous_features,
        )
        result.findings = [f.model_dump() for f in findings]
        self._writer.write_findings(result.findings)
        console.print(f"[yellow][!][/] Findings: {len(result.findings)}")

        self._writer.write_query_log(runner.log())
        self._writer.write_reports({
            "target": self._config.target,
            "port": self._config.port,
            "auth_mode": self._config.auth_mode,
            "identity": result.identity,
            "auth_context": result.auth_context,
            "non_default_databases": result.non_default_databases,
            "findings": result.findings,
        })
