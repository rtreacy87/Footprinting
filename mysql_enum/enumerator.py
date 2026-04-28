"""Top-level enumerator — orchestrates all phases."""

from __future__ import annotations

from rich.console import Console

from .config import TargetConfig
from .connection import MySQLConnection, ConnectionError, open_connection
from .discovery import discover
from .queries import QueryRunner
from .collectors.service import ServiceCollector
from .collectors.variables import VariablesCollector
from .collectors.schema import SchemaCollector
from .collectors.users import UsersCollector
from .collectors.privileges import PrivilegesCollector
from .collectors.routines import RoutinesCollector
from .collectors.data import DataCollector
from .analyzers.findings import FindingsEngine
from .analyzers.sensitive_columns import find_high_value_tables, find_sensitive_columns
from .output.writers import OutputWriter

console = Console(stderr=True)


class EnumerationResult:
    def __init__(self) -> None:
        self.reachable: bool = False
        self.authenticated: bool = False
        self.identity: dict = {}
        self.version: str = ""
        self.databases: list[dict] = []
        self.tables: list[dict] = []
        self.columns: list[dict] = []
        self.grants: list[str] = []
        self.findings: list[dict] = []
        self.samples: list[dict] = []
        self.error: str | None = None


class MySQLEnumerator:
    def __init__(self, config: TargetConfig) -> None:
        self._config = config
        self._writer = OutputWriter(config)

    def run_discover(self) -> EnumerationResult:
        result = EnumerationResult()
        console.print(f"[bold cyan][*][/] Discovering {self._config.target}:{self._config.port}")

        self._writer.write_run_metadata("discover", bool(self._config.password))

        discovery = discover(self._config, run_nmap=True)
        result.reachable = discovery.reachable

        self._writer.write_discovery(discovery.to_dict())

        if not result.reachable:
            result.error = discovery.error
            console.print(f"[red][-][/] Target unreachable: {result.error}")
        else:
            console.print(f"[green][+][/] Target reachable (latency: {discovery.latency_ms}ms)")

        return result

    def run_metadata(self) -> EnumerationResult:
        result = EnumerationResult()
        console.print(f"[bold cyan][*][/] Metadata enumeration of {self._config.target}:{self._config.port}")

        self._writer.write_run_metadata("metadata", bool(self._config.password))

        discovery = discover(self._config, run_nmap=True)
        result.reachable = discovery.reachable
        self._writer.write_discovery(discovery.to_dict())

        if not result.reachable:
            result.error = discovery.error
            console.print(f"[red][-][/] Target unreachable: {result.error}")
            return result

        console.print(f"[green][+][/] Target reachable (latency: {discovery.latency_ms}ms)")

        try:
            with open_connection(self._config) as conn:
                result.authenticated = True
                console.print(f"[green][+][/] Authenticated as {self._config.username}")
                runner = QueryRunner(conn)
                self._enumerate_all(runner, result)
        except ConnectionError as e:
            result.error = str(e)
            result.authenticated = False
            console.print(f"[red][-][/] Authentication failed: {e}")

        return result

    def run_sample(self) -> EnumerationResult:
        result = self.run_metadata()
        if not result.authenticated:
            return result

        console.print("[cyan][*][/] Sampling high-value tables ...")
        try:
            with open_connection(self._config) as conn:
                runner = QueryRunner(conn)
                collector = DataCollector(runner, self._config)
                samples = collector.collect_samples(result.tables)
                result.samples = samples
                self._writer.write_samples(samples)
                console.print(f"[green][+][/] Sampled {len(samples)} tables")
                self._writer.write_query_log(runner.log())
        except ConnectionError:
            pass

        return result

    def _enumerate_all(self, runner: QueryRunner, result: EnumerationResult) -> None:
        svc = ServiceCollector(runner).collect()
        identity = svc.get("identity", {})
        result.identity = identity
        result.version = identity.get("version", "")
        self._writer.write_service(svc)
        self._writer.write_authentication({"identity": identity})
        console.print(f"[green][+][/] Version: {result.version}")

        vars_data = VariablesCollector(runner).collect()
        self._writer.write_server_variables(vars_data)

        users_data = UsersCollector(runner).collect()
        result.grants = users_data.get("grants", [])
        self._writer.write_users(users_data)

        schema_data = SchemaCollector(runner).collect()
        result.databases = schema_data.get("databases", [])
        result.tables = schema_data.get("tables", [])
        result.columns = schema_data.get("columns", [])
        self._writer.write_schema(schema_data)

        routines = RoutinesCollector(runner).collect()
        self._writer.write_routines(routines)

        privileges = PrivilegesCollector(runner).collect()
        self._writer.write_privileges(privileges)

        engine = FindingsEngine()
        findings = engine.analyze(
            identity=identity,
            grants=result.grants,
            tables=result.tables,
            columns=result.columns,
            security_vars=vars_data.get("security_variables", []),
            users=users_data.get("users", {}),
        )
        result.findings = [f.model_dump() for f in findings]
        self._writer.write_findings(result.findings)

        high_value = find_high_value_tables(result.tables)
        sensitive_cols = find_sensitive_columns(result.columns)

        self._writer.write_query_log(runner.log())
        self._writer.write_reports({
            "target": self._config.target,
            "port": self._config.port,
            "identity": identity,
            "databases": result.databases,
            "tables": result.tables,
            "grants": result.grants,
            "findings": result.findings,
            "security_variables": vars_data.get("security_variables", []),
            "high_value_tables": high_value,
            "sensitive_columns": sensitive_cols,
        })

        console.print(f"[green][+][/] Found {len(result.databases)} databases, {len(result.tables)} tables")
        console.print(f"[yellow][!][/] Findings: {len(result.findings)}")
