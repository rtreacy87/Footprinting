from __future__ import annotations

from ..models.attempt import Attempt


def build_secure_findings_report(attempts: list[Attempt]) -> str:
    lines = ["# Secure Findings", "", "Controls that appear properly restricted:", ""]

    zt_denied = [
        a for a in attempts
        if a.category == "zone_transfer" and a.status in ("refused", "failure", "timeout")
    ]
    for a in zt_denied:
        lines.append(f"- Zone transfer denied by `{a.target}` (status: {a.status})")

    recursion_denied = [
        a for a in attempts
        if a.category == "recursion" and a.status in ("refused", "failure")
    ]
    for a in recursion_denied:
        lines.append(f"- Recursion denied by `{a.target}`")

    version_hidden = [
        a for a in attempts
        if a.category == "version_disclosure" and a.status in ("refused", "failure")
    ]
    for a in version_hidden:
        lines.append(f"- version.bind not disclosed by `{a.target}`")

    wildcard_clean = [
        a for a in attempts
        if a.category == "wildcard_detection" and a.status == "failure"
    ]
    for a in wildcard_clean:
        lines.append(f"- No wildcard DNS behavior detected for `{a.target}`")

    if len(lines) == 4:
        lines.append("No confirmed secure controls — all checks either succeeded or were inconclusive.")

    return "\n".join(lines)
