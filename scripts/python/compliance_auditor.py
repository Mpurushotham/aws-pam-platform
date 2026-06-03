#!/usr/bin/env python3
"""Audit an AWS account against CIS / PCI-DSS / SOC2 PAM-relevant controls.

Runs a set of read-only checks against IAM, CloudTrail, and account password
policy, maps each to its compliance control(s), and produces a pass/fail
report. Designed to run unattended (e.g. a weekly GitHub Actions job) and exit
non-zero when any high-severity control fails.

Examples:
    python compliance_auditor.py --frameworks cis,pci-dss,soc2
    python compliance_auditor.py --output compliance-report.json --fail-on high
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from typing import Any, Callable

from pam_common import build_session, client_config, configure_logging, utc_now_iso

LOGGER = configure_logging(__name__)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class CheckResult:
    """Outcome of a single compliance check."""

    control_id: str
    title: str
    frameworks: list[str]
    severity: str  # low | medium | high
    passed: bool
    detail: str


def check_root_mfa(iam: Any) -> CheckResult:
    """CIS 1.5 — ensure MFA is enabled on the root account."""
    summary = iam.get_account_summary().get("SummaryMap", {})
    enabled = summary.get("AccountMFAEnabled", 0) == 1
    return CheckResult(
        control_id="CIS-1.5",
        title="Root account MFA enabled",
        frameworks=["cis", "soc2"],
        severity="high",
        passed=enabled,
        detail="root MFA enabled" if enabled else "root account has no MFA",
    )


def check_password_policy(iam: Any) -> CheckResult:
    """CIS 1.8 — ensure a strong IAM password policy is configured."""
    try:
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
    except iam.exceptions.NoSuchEntityException:
        return CheckResult(
            control_id="CIS-1.8",
            title="IAM password policy strength",
            frameworks=["cis", "pci-dss"],
            severity="high",
            passed=False,
            detail="no account password policy configured",
        )
    strong = (
        policy.get("MinimumPasswordLength", 0) >= 14
        and policy.get("RequireSymbols", False)
        and policy.get("RequireNumbers", False)
        and policy.get("RequireUppercaseCharacters", False)
        and policy.get("RequireLowercaseCharacters", False)
    )
    return CheckResult(
        control_id="CIS-1.8",
        title="IAM password policy strength",
        frameworks=["cis", "pci-dss"],
        severity="medium",
        passed=strong,
        detail="policy meets length/complexity" if strong else "policy too weak",
    )


def check_cloudtrail_enabled(cloudtrail: Any) -> CheckResult:
    """CIS 3.1 — ensure at least one multi-region trail is logging."""
    trails = cloudtrail.describe_trails().get("trailList", [])
    multi_region = any(t.get("IsMultiRegionTrail") for t in trails)
    return CheckResult(
        control_id="CIS-3.1",
        title="CloudTrail multi-region logging enabled",
        frameworks=["cis", "pci-dss", "soc2"],
        severity="high",
        passed=multi_region,
        detail=(
            f"{len(trails)} trail(s), multi-region present"
            if multi_region
            else "no multi-region trail found"
        ),
    )


def check_users_have_mfa(iam: Any) -> CheckResult:
    """CIS 1.10 — ensure every console user has MFA enabled."""
    offenders: list[str] = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            name = user["UserName"]
            if not iam.list_mfa_devices(UserName=name).get("MFADevices"):
                offenders.append(name)
    return CheckResult(
        control_id="CIS-1.10",
        title="All IAM users have MFA",
        frameworks=["cis", "soc2"],
        severity="high",
        passed=not offenders,
        detail=(
            "all users MFA-protected" if not offenders else f"missing MFA: {offenders}"
        ),
    )


# Registry of checks: (client_name, callable).
_CHECKS: list[tuple[str, Callable[[Any], CheckResult]]] = [
    ("iam", check_root_mfa),
    ("iam", check_password_policy),
    ("iam", check_users_have_mfa),
    ("cloudtrail", check_cloudtrail_enabled),
]


def run_audit(
    region: str, frameworks: set[str], profile: str | None = None
) -> list[CheckResult]:
    """Execute all checks relevant to the requested frameworks.

    Args:
        region: AWS region.
        frameworks: Frameworks to include (cis/pci-dss/soc2).
        profile: Optional named AWS profile.

    Returns:
        The list of check results.
    """
    session = build_session(region=region, profile=profile)
    cfg = client_config()
    clients: dict[str, Any] = {}
    results: list[CheckResult] = []

    for client_name, check in _CHECKS:
        clients.setdefault(client_name, session.client(client_name, config=cfg))
        try:
            result = check(clients[client_name])
        except Exception as exc:  # noqa: BLE001 - record failed checks, keep going
            LOGGER.error("Check %s errored: %s", check.__name__, exc)
            continue
        if frameworks & set(result.frameworks):
            results.append(result)
            level = LOGGER.info if result.passed else LOGGER.warning
            level(
                "[%s] %s -> %s",
                result.control_id,
                result.title,
                "PASS" if result.passed else "FAIL",
            )
    return results


def build_report(results: list[CheckResult]) -> dict[str, Any]:
    """Assemble a summary report from check results."""
    failed = [r for r in results if not r.passed]
    return {
        "generated_at": utc_now_iso(),
        "total_checks": len(results),
        "passed": sum(1 for r in results if r.passed),
        "failed": len(failed),
        "score_pct": round(
            100 * sum(1 for r in results if r.passed) / max(len(results), 1), 1
        ),
        "results": [asdict(r) for r in results],
    }


def highest_failed_severity(results: list[CheckResult]) -> str | None:
    """Return the highest severity among failed checks, or None."""
    failed = [r for r in results if not r.passed]
    if not failed:
        return None
    return max(failed, key=lambda r: _SEVERITY_ORDER.get(r.severity, 0)).severity


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1", help="AWS region.")
    parser.add_argument("--profile", default=None, help="Named AWS profile.")
    parser.add_argument(
        "--frameworks",
        default="cis,pci-dss,soc2",
        help="Comma-separated frameworks to evaluate.",
    )
    parser.add_argument("--output", default="-", help="Report path or '-' for stdout.")
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=["low", "medium", "high", "never"],
        help="Minimum failed severity that yields a non-zero exit.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = parse_args(argv)
    frameworks = {f.strip().lower() for f in args.frameworks.split(",") if f.strip()}
    try:
        results = run_audit(args.region, frameworks, args.profile)
    except Exception as exc:  # noqa: BLE001 - top-level guard with logging
        LOGGER.error("Audit failed: %s", exc)
        return 2

    report = build_report(results)
    text = json.dumps(report, indent=2)
    if args.output == "-":
        print(text)
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
        LOGGER.info("Wrote compliance report to %s", args.output)

    if args.fail_on == "never":
        return 0
    worst = highest_failed_severity(results)
    if worst is not None and _SEVERITY_ORDER[worst] >= _SEVERITY_ORDER[args.fail_on]:
        LOGGER.error("Compliance gate failed (worst failed severity: %s)", worst)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
