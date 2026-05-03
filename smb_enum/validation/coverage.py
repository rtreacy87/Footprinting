from __future__ import annotations

from dataclasses import dataclass, field

from ..context import ScanContext
from ..core.enums import ControlStatus, TestStatus


@dataclass
class CoverageReport:
    tests_run: int = 0
    tests_skipped: int = 0
    tests_inconclusive: int = 0
    controls_assessed: int = 0
    controls_passed: int = 0
    controls_failed: int = 0
    controls_not_tested: int = 0
    test_ids_run: list[str] = field(default_factory=list)
    test_ids_skipped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tests_run": self.tests_run,
            "tests_skipped": self.tests_skipped,
            "tests_inconclusive": self.tests_inconclusive,
            "controls_assessed": self.controls_assessed,
            "controls_passed": self.controls_passed,
            "controls_failed": self.controls_failed,
            "controls_not_tested": self.controls_not_tested,
            "test_ids_run": self.test_ids_run,
            "test_ids_skipped": self.test_ids_skipped,
        }


def build_coverage_report(context: ScanContext) -> CoverageReport:
    """Build a CoverageReport from the current ScanContext state."""
    report = CoverageReport()

    for tr in context.test_results:
        if tr.status in (TestStatus.NOT_RUN.value,):
            report.tests_skipped += 1
            report.test_ids_skipped.append(tr.test_id)
        else:
            report.tests_run += 1
            report.test_ids_run.append(tr.test_id)
        if tr.status == TestStatus.INCONCLUSIVE.value:
            report.tests_inconclusive += 1

    for skipped in context.skipped_steps:
        report.tests_skipped += 1

    report.controls_assessed = len(context.control_assessments)
    for ca in context.control_assessments:
        if ca.status == ControlStatus.PASSED.value:
            report.controls_passed += 1
        elif ca.status == ControlStatus.FAILED.value:
            report.controls_failed += 1
        elif ca.status == ControlStatus.NOT_TESTED.value:
            report.controls_not_tested += 1

    return report
