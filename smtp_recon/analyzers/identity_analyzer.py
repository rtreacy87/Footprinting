from __future__ import annotations

import json
import logging
from pathlib import Path

from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)


class IdentityAnalyzer:
    """
    Consolidate user enumeration findings across VRFY, EXPN, RCPT TO methods.
    """

    def analyze(self, context: ScanContext, results: list[CheckResult]) -> list[Finding]:
        findings: list[Finding] = []
        id_dir = context.target_dir / "identity_enumeration"

        confirmed_users: dict[str, list[str]] = {}  # username -> methods

        for method_file in ("vrfy_users.json", "expn_users.json", "rcpt_to_users.json"):
            path = id_dir / method_file
            if not path.exists():
                continue
            try:
                users = json.loads(path.read_text(encoding="utf-8"))
                for u in users:
                    if u.get("status") == "confirmed":
                        username = u["username"]
                        method = u["method"]
                        confirmed_users.setdefault(username, []).append(method)
            except Exception as exc:
                logger.warning("[identity_analyzer] Failed to read %s: %s", method_file, exc)

        if confirmed_users:
            findings.append(
                Finding(
                    title="Valid email accounts enumerated",
                    severity="high",
                    category="user_enumeration",
                    description=(
                        f"Found {len(confirmed_users)} valid account(s) via SMTP enumeration: "
                        + ", ".join(confirmed_users.keys())
                    ),
                    evidence=json.dumps(confirmed_users, indent=2),
                    remediation=(
                        "Disable VRFY/EXPN. Configure RCPT TO to return identical "
                        "responses for valid and invalid recipients."
                    ),
                    tags=["user_enum", "credential_target"],
                )
            )

        # Write consolidated user list
        out_path = id_dir / "confirmed_users.json"
        out_path.write_text(
            json.dumps(confirmed_users, indent=2), encoding="utf-8"
        )

        return findings
