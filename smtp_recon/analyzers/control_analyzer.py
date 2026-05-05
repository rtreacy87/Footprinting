from __future__ import annotations

import logging

from ..models.control import Control
from ..models.result import CheckResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)


class ControlAnalyzer:
    """
    Identify security controls observed during the scan.
    Reads check results and extracts controls_observed fields.
    """

    def analyze(self, context: ScanContext, results: list[CheckResult]) -> list[Control]:
        controls: list[Control] = []
        seen: set[str] = set()

        for result in results:
            for ctrl in result.controls_observed:
                if isinstance(ctrl, Control):
                    key = f"{ctrl.name}:{ctrl.port}"
                    if key not in seen:
                        controls.append(ctrl)
                        seen.add(key)

        # Check for VRFY/EXPN block
        for result in results:
            if result.name in ("vrfy_user_enum", "expn_user_enum"):
                for finding in result.findings:
                    if "blocked" in finding.title.lower():
                        ctrl = Control(
                            name=f"{result.name.upper()}_BLOCKED",
                            control_type="block",
                            port=result.port,
                            description=finding.description,
                            evidence=finding.evidence,
                        )
                        key = f"{ctrl.name}:{ctrl.port}"
                        if key not in seen:
                            controls.append(ctrl)
                            seen.add(key)

        # Check TLS results for required TLS controls
        for result in results:
            if result.name == "starttls":
                for tls in result.controls_observed:
                    if hasattr(tls, "starttls_negotiated") and tls.starttls_negotiated:
                        ctrl = Control(
                            name="STARTTLS",
                            control_type="tls_required",
                            port=tls.port,
                            description="STARTTLS available and successfully negotiated.",
                        )
                        key = f"STARTTLS:{tls.port}"
                        if key not in seen:
                            controls.append(ctrl)
                            seen.add(key)

        logger.info("[control_analyzer] Identified %d controls", len(controls))
        return controls
