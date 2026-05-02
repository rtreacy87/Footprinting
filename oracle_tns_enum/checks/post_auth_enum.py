from __future__ import annotations

from .base import BaseCheck
from ..config import ScanContext
from ..core.result import CheckResult
from ..models.finding import Finding
from ..connection import OracleConnection, OracleConnectionError

SAFE_QUERIES = {
    "users": "SELECT username FROM all_users ORDER BY username",
    "session_privs": "SELECT privilege FROM session_privs ORDER BY privilege",
    "role_privs": "SELECT granted_role FROM user_role_privs ORDER BY granted_role",
    "tables": "SELECT owner, table_name FROM all_tables WHERE ROWNUM <= 50 ORDER BY owner, table_name",
    "version": "SELECT * FROM v$version WHERE ROWNUM <= 3",
}

DBA_QUERIES = {
    "dbsnmp_hash": "SELECT name, password, spare4 FROM sys.user$ WHERE name='DBSNMP'",
    "all_hashes": "SELECT name, password, spare4 FROM sys.user$ WHERE spare4 IS NOT NULL ORDER BY name",
}


class PostAuthEnumerationCheck(BaseCheck):
    name = "post_auth_enum"
    required_tools: list[str] = []

    def can_run(self, context: ScanContext) -> bool:
        return bool(context.valid_credentials)

    def run(self, context: ScanContext) -> CheckResult:
        notes = []
        findings = []

        for cred in context.valid_credentials:
            sid = cred.sid or context.discovered_sids[0] if context.discovered_sids else "XE"
            data = _enumerate_as(context, sid, cred.username, cred.password)
            context.post_auth_data[f"{cred.username}@{sid}"] = data
            notes.append(f"Enumerated as {cred.username}@{sid}: {list(data.keys())}")

            if data.get("dbsnmp_hash"):
                row = data["dbsnmp_hash"][0] if data["dbsnmp_hash"] else {}
                hash_val = row.get("spare4") or row.get("password", "")
                findings.append(Finding(
                    id="ORACLE-TNS-004",
                    title="DBSNMP Password Hash Retrieved",
                    severity="High",
                    category="Credential Exposure",
                    description=f"Password hash for DBSNMP retrieved from sys.user$",
                    evidence=[f"DBSNMP hash: {hash_val}"],
                    source_tool="oracledb",
                    recommended_next_steps=[
                        "Attempt to crack the hash offline",
                        "Rotate DBSNMP credentials immediately",
                    ],
                ))

            if data.get("privilege_abuse"):
                findings.append(Finding(
                    id="ORACLE-TNS-005",
                    title="Excessive Privileges Detected",
                    severity="High",
                    category="Authorization",
                    description=f"User {cred.username} has DBA or dangerous privileges",
                    evidence=data.get("privilege_abuse", []),
                    source_tool="oracledb",
                    recommended_next_steps=["Review and revoke unnecessary privileges"],
                ))

        import json
        out_path = context.config.output_base / context.target_host / "parsed" / "post_auth.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(context.post_auth_data, indent=2, default=str), encoding="utf-8")

        return CheckResult(check_name=self.name, status="ok", findings=findings, notes=notes)


def _enumerate_as(context: ScanContext, sid: str, user: str, pwd: str) -> dict:
    data: dict = {}
    try:
        conn = OracleConnection(
            host=context.target_host,
            port=context.target_port,
            sid=sid,
            username=user,
            password=pwd,
            lib_dir=context.config.oracle_client_lib,
        )

        for key, sql in SAFE_QUERIES.items():
            try:
                rows = conn.query(sql)
                data[key] = rows
            except OracleConnectionError:
                pass

        # Try DBA queries
        for key, sql in DBA_QUERIES.items():
            try:
                rows = conn.query(sql)
                data[key] = rows
                # Flag privilege abuse
                dangerous = ["DBA", "SELECT ANY DICTIONARY", "SELECT ANY TABLE"]
                privs = [r.get("privilege", "") for r in data.get("session_privs", [])]
                data["privilege_abuse"] = [p for p in privs if any(d in p for d in dangerous)]
            except OracleConnectionError:
                pass

        conn.close()
    except OracleConnectionError:
        pass
    return data
