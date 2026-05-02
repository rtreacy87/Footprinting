from __future__ import annotations

from .base import BaseCheck
from ..config import ScanContext
from ..core.result import CheckResult
from ..models.finding import Finding


class AbusePathReviewCheck(BaseCheck):
    name = "abuse_path_review"
    required_tools: list[str] = []

    def can_run(self, context: ScanContext) -> bool:
        return bool(context.valid_credentials or context.post_auth_data)

    def run(self, context: ScanContext) -> CheckResult:
        findings: list[Finding] = []

        for cred in context.valid_credentials:
            if cred.has_dba:
                findings.append(Finding(
                    id="ORACLE-TNS-ABU-001",
                    title="DBA Privileges Available",
                    severity="Critical",
                    category="Excessive Privileges",
                    description=f"Account {cred.username} has DBA-level access (sys.user$ readable)",
                    evidence=[f"{cred.username}:{cred.password} can read sys.user$"],
                    source_tool="oracledb",
                    recommended_next_steps=[
                        "Dump sys.user$ for all password hashes",
                        "Attempt privilege escalation to OS level via UTL_FILE or DBMS_SCHEDULER",
                    ],
                ))

        for key, data in context.post_auth_data.items():
            utl_file_privs = [
                r for r in data.get("role_privs", [])
                if "UTL_FILE" in str(r).upper()
            ]
            if utl_file_privs:
                findings.append(Finding(
                    id="ORACLE-TNS-ABU-002",
                    title="UTL_FILE Access Detected",
                    severity="Medium",
                    category="File Access Potential",
                    description=f"Account {key.split('@')[0]} has UTL_FILE execute privilege",
                    evidence=[f"UTL_FILE EXECUTE granted to {key.split('@')[0]}"],
                    source_tool="oracledb",
                    recommended_next_steps=[
                        "Check Oracle directory objects for readable paths",
                        "Attempt to read sensitive files via UTL_FILE",
                    ],
                ))

        return CheckResult(check_name=self.name, status="ok", findings=findings)
