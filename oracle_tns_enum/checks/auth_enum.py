from __future__ import annotations

from .base import BaseCheck
from ..config import ScanContext
from ..core.result import CheckResult
from ..models.credential import Credential
from ..models.finding import Finding
from ..connection import OracleConnection, OracleConnectionError


class AuthenticationEnumerationCheck(BaseCheck):
    name = "auth_enum"
    required_tools: list[str] = []

    def can_run(self, context: ScanContext) -> bool:
        return context.has_connection_identifiers()

    def run(self, context: ScanContext) -> CheckResult:
        creds_to_try = _load_credentials(context)
        sids = context.discovered_sids or ["XE"]
        valid: list[Credential] = []

        for sid in sids:
            for user, pwd in creds_to_try:
                if context.valid_credentials and not context.config.aggressive:
                    break  # one valid cred is enough in non-aggressive mode
                cred = _try_credential(context, sid, user, pwd)
                if cred:
                    context.valid_credentials.append(cred)
                    valid.append(cred)

        import json
        creds_path = context.config.output_base / context.target_host / "parsed" / "credentials.json"
        creds_path.parent.mkdir(parents=True, exist_ok=True)
        creds_path.write_text(
            json.dumps([c.model_dump() for c in context.valid_credentials], indent=2),
            encoding="utf-8",
        )

        findings = []
        for cred in valid:
            findings.append(Finding(
                id="ORACLE-TNS-003",
                title="Default Oracle Credentials Accepted",
                severity="High",
                category="Authentication",
                description=f"Credential {cred.username}:{cred.password} valid for SID {cred.sid}",
                evidence=[f"{cred.username}:{cred.password} valid for SID {cred.sid}"],
                source_tool="oracledb",
                recommended_next_steps=[
                    "Rotate the account password",
                    "Check whether credentials are reused elsewhere",
                    "Enumerate privileges for this account",
                ],
            ))

        return CheckResult(
            check_name=self.name,
            status="ok",
            findings=findings,
            notes=[f"Valid credentials found: {len(context.valid_credentials)}"],
        )


def _load_credentials(context: ScanContext) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    cred_file = context.config.wordlist_credentials
    if cred_file.exists():
        for line in cred_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "/" not in line:
                continue
            user, pwd = line.split("/", 1)
            pairs.append((user.strip(), pwd.strip()))
    if not pairs:
        pairs = [
            ("scott", "tiger"),
            ("sys", "oracle"),
            ("system", "oracle"),
            ("dbsnmp", "dbsnmp"),
            ("system", "manager"),
            ("sys", "change_on_install"),
        ]
    return pairs


def _try_credential(context: ScanContext, sid: str, user: str, pwd: str) -> Credential | None:
    try:
        conn = OracleConnection(
            host=context.target_host,
            port=context.target_port,
            sid=sid,
            username=user,
            password=pwd,
            lib_dir=context.config.oracle_client_lib,
        )
        # Check DBA access
        has_dba = False
        try:
            conn.query("SELECT name FROM sys.user$ WHERE ROWNUM=1")
            has_dba = True
        except OracleConnectionError:
            pass
        conn.close()
        return Credential(username=user, password=pwd, sid=sid, source="wordlist", valid=True, has_dba=has_dba)
    except OracleConnectionError as e:
        err = str(e)
        if "ORA-28000" in err:
            return Credential(username=user, password=pwd, sid=sid, source="wordlist", valid=False)
        return None
