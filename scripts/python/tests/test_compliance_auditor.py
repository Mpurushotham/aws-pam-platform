"""Unit tests for compliance_auditor reporting/scoring logic."""

from compliance_auditor import CheckResult, build_report, highest_failed_severity


def _result(passed: bool, severity: str) -> CheckResult:
    return CheckResult(
        control_id="X",
        title="t",
        frameworks=["cis"],
        severity=severity,
        passed=passed,
        detail="",
    )


def test_build_report_scores():
    results = [_result(True, "high"), _result(False, "medium"), _result(True, "low")]
    report = build_report(results)
    assert report["total_checks"] == 3
    assert report["passed"] == 2
    assert report["failed"] == 1
    assert report["score_pct"] == 66.7


def test_build_report_empty():
    report = build_report([])
    assert report["score_pct"] == 0.0


def test_highest_failed_severity_returns_worst():
    results = [_result(False, "low"), _result(False, "high"), _result(True, "medium")]
    assert highest_failed_severity(results) == "high"


def test_highest_failed_severity_none_when_all_pass():
    results = [_result(True, "high"), _result(True, "low")]
    assert highest_failed_severity(results) is None
