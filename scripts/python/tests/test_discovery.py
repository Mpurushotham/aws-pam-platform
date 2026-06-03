"""Unit tests for pam_privileged_account_discovery pure logic."""

from pam_privileged_account_discovery import (
    PrivilegedAccount,
    _classify,
    to_export,
)


def test_classify_critical_when_admin_and_no_mfa():
    assert _classify(["admin managed policy: AdministratorAccess"], False) == "critical"


def test_classify_high_when_admin_with_mfa():
    assert _classify(["wildcard action"], True) == "high"


def test_classify_high_when_no_mfa_only():
    assert _classify(["no MFA device"], False) == "high"


def test_classify_medium_for_other_reasons():
    assert _classify(["storage not encrypted"], None) == "medium"


def test_classify_low_when_no_reasons():
    assert _classify([], True) == "low"


def test_to_export_json_summary_counts():
    accounts = [
        PrivilegedAccount("a", "iam_user", "arn:a", risk="critical"),
        PrivilegedAccount("b", "iam_role", "arn:b", risk="low"),
    ]
    out = to_export(accounts, "json")
    assert out["summary"]["total"] == 2
    assert out["summary"]["by_risk"]["critical"] == 1
    assert len(out["accounts"]) == 2


def test_to_export_cyberark_shape():
    accounts = [PrivilegedAccount("svc", "iam_user", "arn:svc", risk="high")]
    out = to_export(accounts, "cyberark")
    assert out["accounts"][0]["safe"] == "PAM-HIGH"
    assert out["accounts"][0]["name"] == "svc"


def test_to_export_beyondtrust_shape():
    accounts = [
        PrivilegedAccount("svc", "iam_user", "arn:svc", reasons=["no MFA device"])
    ]
    out = to_export(accounts, "beyondtrust")
    assert out["ManagedAccounts"][0]["AccountName"] == "svc"
    assert "no MFA" in out["ManagedAccounts"][0]["Description"]
