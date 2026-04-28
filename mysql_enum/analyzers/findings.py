"""Security findings engine."""

from __future__ import annotations

from ..config import Finding
from .privilege_risk import find_dangerous_privileges, is_root_equivalent, has_file_privilege
from .sensitive_columns import find_high_value_tables, find_sensitive_columns


class FindingsEngine:
    def __init__(self) -> None:
        self._findings: list[Finding] = []

    def analyze(
        self,
        identity: dict,
        grants: list[str],
        tables: list[dict],
        columns: list[dict],
        security_vars: list[dict],
        users: dict,
    ) -> list[Finding]:
        self._findings.clear()
        self._check_authentication(identity)
        self._check_privileges(identity, grants)
        self._check_high_value_tables(tables)
        self._check_sensitive_columns(columns)
        self._check_security_variables(security_vars)
        self._check_user_table(users)
        return list(self._findings)

    def _add(self, finding: Finding) -> None:
        self._findings.append(finding)

    def _check_authentication(self, identity: dict) -> None:
        if not identity:
            return
        self._add(Finding(
            severity="info",
            title="MySQL service authenticated successfully",
            description=f"Connected as {identity.get('login_user')} on {identity.get('server_hostname')}",
            evidence={"identity": identity},
        ))

    def _check_privileges(self, identity: dict, grants: list[str]) -> None:
        if is_root_equivalent(identity, grants):
            self._add(Finding(
                severity="critical",
                title="Authenticated as root or DBA-equivalent",
                description="The current session has root or ALL PRIVILEGES level access.",
                evidence={"grants": grants[:5]},
                recommendation="Restrict database access to least privilege accounts.",
            ))

        dangerous = find_dangerous_privileges(grants)
        if dangerous:
            self._add(Finding(
                severity="critical",
                title=f"Current user has dangerous privileges: {', '.join(dangerous)}",
                description="These privileges may allow file read/write, user creation, or full server control.",
                evidence={"dangerous_privileges": dangerous, "grants": grants[:5]},
                recommendation="Audit and revoke unnecessary privileges.",
            ))

        if has_file_privilege(grants):
            self._add(Finding(
                severity="critical",
                title="Current user has FILE privilege",
                description="FILE privilege may allow reading files with LOAD_FILE or writing with INTO OUTFILE.",
                evidence={"grants": [g for g in grants if "FILE" in g.upper()]},
                recommendation="Revoke FILE privilege unless explicitly required.",
            ))

    def _check_high_value_tables(self, tables: list[dict]) -> None:
        flagged = find_high_value_tables(tables)
        for t in flagged:
            self._add(Finding(
                severity="high",
                title=f"High-value table visible: {t['database']}.{t['table']}",
                description="This table name suggests it may contain authentication, user, or sensitive data.",
                evidence=t,
                recommendation="Review table contents and restrict access to least privilege.",
            ))

    def _check_sensitive_columns(self, columns: list[dict]) -> None:
        flagged = find_sensitive_columns(columns)
        seen: set[str] = set()
        for c in flagged:
            key = f"{c['database']}.{c['table']}"
            if key not in seen:
                seen.add(key)
                self._add(Finding(
                    severity="high",
                    title=f"Sensitive columns in {c['database']}.{c['table']}",
                    description=f"Column '{c['column']}' matches sensitive data pattern.",
                    evidence=c,
                ))

    def _check_security_variables(self, security_vars: list[dict]) -> None:
        var_map = {row["Variable_name"]: row["Value"] for row in security_vars if "Variable_name" in row}

        if var_map.get("local_infile", "OFF").upper() == "ON":
            self._add(Finding(
                severity="high",
                title="local_infile is enabled",
                description="local_infile=ON allows LOAD DATA LOCAL INFILE, a known attack vector.",
                evidence={"local_infile": "ON"},
                recommendation="Set local_infile=OFF in MySQL configuration.",
            ))

        sfp = var_map.get("secure_file_priv", "")
        if sfp == "" or sfp is None:
            self._add(Finding(
                severity="high",
                title="secure_file_priv is empty",
                description="No directory restriction on file read/write operations.",
                evidence={"secure_file_priv": sfp},
                recommendation="Set secure_file_priv to a restricted directory.",
            ))

        if var_map.get("require_secure_transport", "OFF").upper() == "OFF":
            self._add(Finding(
                severity="medium",
                title="TLS not required (require_secure_transport=OFF)",
                description="Connections may be made without encryption.",
                evidence={"require_secure_transport": "OFF"},
                recommendation="Enable require_secure_transport=ON.",
            ))

        if var_map.get("general_log", "OFF").upper() == "ON":
            self._add(Finding(
                severity="medium",
                title="General query log is enabled",
                description=f"Log file: {var_map.get('general_log_file', 'unknown')}",
                evidence={"general_log": "ON", "general_log_file": var_map.get("general_log_file")},
            ))

        version = var_map.get("version", "")
        if version:
            self._add(Finding(
                severity="info",
                title=f"MySQL/MariaDB version: {version}",
                description="Service version detected.",
                evidence={"version": version},
            ))

    def _check_user_table(self, users: dict) -> None:
        if not users.get("visible"):
            return
        rows = users.get("rows", [])
        for row in rows:
            host = row.get("host", "")
            user = row.get("user", "")
            if user.lower() == "root" and host == "%":
                self._add(Finding(
                    severity="critical",
                    title="Remote root user with wildcard host detected",
                    description="root@% allows root login from any host.",
                    evidence={"user": user, "host": host},
                    recommendation="Restrict root to localhost only.",
                ))
            if host == "%":
                self._add(Finding(
                    severity="high",
                    title=f"User '{user}' has wildcard host '%'",
                    description="Wildcard host allows connections from any IP.",
                    evidence={"user": user, "host": host},
                ))
