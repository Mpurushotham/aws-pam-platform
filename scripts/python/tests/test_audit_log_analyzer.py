"""Unit tests for audit_log_analyzer detection heuristics."""

import json

from audit_log_analyzer import build_report, detect


def _event(name: str, detail: dict) -> dict:
    return {"EventName": name, "CloudTrailEvent": json.dumps(detail)}


def test_detect_root_usage():
    events = [_event("DescribeInstances", {"userIdentity": {"type": "Root"}})]
    findings = detect(events)
    assert any(f.rule == "root-usage" and f.severity == "high" for f in findings)


def test_detect_login_without_mfa():
    events = [
        _event(
            "ConsoleLogin",
            {
                "additionalEventData": {"MFAUsed": "No"},
                "responseElements": {"ConsoleLogin": "Success"},
            },
        )
    ]
    findings = detect(events)
    assert any(f.rule == "login-without-mfa" for f in findings)


def test_detect_sensitive_action():
    events = [_event("StopLogging", {})]
    findings = detect(events)
    assert any(f.rule == "sensitive-action" for f in findings)


def test_detect_mass_deletion_threshold():
    events = [
        {"EventName": "DeleteObject", "Username": "mallory", "CloudTrailEvent": "{}"}
        for _ in range(12)
    ]
    findings = detect(events)
    assert any(f.rule == "mass-deletion" and f.count == 12 for f in findings)


def test_detect_repeated_access_denied():
    events = [
        _event("GetObject", {"errorCode": "AccessDenied"}) | {"Username": "probe"}
        for _ in range(6)
    ]
    findings = detect(events)
    assert any(f.rule == "repeated-access-denied" for f in findings)


def test_build_report_severity_counts():
    events = [_event("StopLogging", {})]
    report = build_report(detect(events))
    assert report["total_findings"] >= 1
    assert "medium" in report["by_severity"]


def test_clean_log_has_no_findings():
    events = [_event("DescribeInstances", {"userIdentity": {"type": "IAMUser"}})]
    assert detect(events) == []
