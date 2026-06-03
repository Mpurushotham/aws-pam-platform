#!/usr/bin/env python3
"""Discover privileged accounts across AWS and classify them by risk.

Scans IAM (users, roles), EC2 instance profiles, and RDS instances for
privileged identities, assigns a risk tier (critical/high/medium/low), and
emits a normalized inventory suitable for ingestion by external PAM systems
(CyberArk, BeyondTrust) or for review.

Examples:
    python pam_privileged_account_discovery.py --region us-east-1
    python pam_privileged_account_discovery.py --output report.json --format cyberark
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

from pam_common import build_session, client_config, configure_logging, utc_now_iso

LOGGER = configure_logging(__name__)

# IAM actions that, if grantable, indicate privilege escalation potential.
_ADMIN_ACTIONS = {"*", "iam:*", "iam:passrole", "sts:assumerole", "*:*"}
_HIGH_RISK_MANAGED = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}


@dataclass
class PrivilegedAccount:
    """A discovered privileged identity and its risk attributes."""

    identifier: str
    account_type: str  # iam_user | iam_role | ec2_instance | rds_instance
    arn: str
    risk: str = "low"  # critical | high | medium | low
    reasons: list[str] = field(default_factory=list)
    mfa_enabled: bool | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def _classify(reasons: list[str], mfa_enabled: bool | None) -> str:
    """Map discovery reasons to a risk tier.

    Args:
        reasons: Human-readable findings that contributed to the score.
        mfa_enabled: Whether MFA protects the identity (None if N/A).

    Returns:
        One of ``critical``, ``high``, ``medium``, ``low``.
    """
    has_admin = any("admin" in r.lower() or "wildcard" in r.lower() for r in reasons)
    if has_admin and mfa_enabled is False:
        return "critical"
    if has_admin:
        return "high"
    if reasons and mfa_enabled is False:
        return "high"
    if reasons:
        return "medium"
    return "low"


def discover_iam_users(iam: Any) -> list[PrivilegedAccount]:
    """Discover IAM users with administrative privileges.

    Args:
        iam: A boto3 IAM client.

    Returns:
        A list of privileged IAM-user accounts.
    """
    found: list[PrivilegedAccount] = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            name = user["UserName"]
            reasons: list[str] = []

            attached = iam.list_attached_user_policies(UserName=name).get(
                "AttachedPolicies", []
            )
            for pol in attached:
                if pol["PolicyArn"] in _HIGH_RISK_MANAGED:
                    reasons.append(f"admin managed policy: {pol['PolicyName']}")

            mfa = iam.list_mfa_devices(UserName=name).get("MFADevices", [])
            mfa_enabled = len(mfa) > 0

            if reasons or not mfa_enabled:
                if not mfa_enabled:
                    reasons.append("no MFA device")
                found.append(
                    PrivilegedAccount(
                        identifier=name,
                        account_type="iam_user",
                        arn=user["Arn"],
                        mfa_enabled=mfa_enabled,
                        reasons=reasons,
                        risk=_classify(reasons, mfa_enabled),
                        metadata={"created": str(user.get("CreateDate", ""))},
                    )
                )
    LOGGER.info("Discovered %d privileged IAM users", len(found))
    return found


def discover_iam_roles(iam: Any) -> list[PrivilegedAccount]:
    """Discover IAM roles granting administrative privileges.

    Args:
        iam: A boto3 IAM client.

    Returns:
        A list of privileged IAM-role accounts.
    """
    found: list[PrivilegedAccount] = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            name = role["RoleName"]
            if name.startswith("AWSServiceRole"):
                continue
            reasons: list[str] = []
            attached = iam.list_attached_role_policies(RoleName=name).get(
                "AttachedPolicies", []
            )
            for pol in attached:
                if pol["PolicyArn"] in _HIGH_RISK_MANAGED:
                    reasons.append(f"admin managed policy: {pol['PolicyName']}")
            if reasons:
                found.append(
                    PrivilegedAccount(
                        identifier=name,
                        account_type="iam_role",
                        arn=role["Arn"],
                        mfa_enabled=None,
                        reasons=reasons,
                        risk=_classify(reasons, None),
                    )
                )
    LOGGER.info("Discovered %d privileged IAM roles", len(found))
    return found


def discover_rds_instances(rds: Any) -> list[PrivilegedAccount]:
    """Discover RDS instances and flag unencrypted or publicly accessible ones.

    Args:
        rds: A boto3 RDS client.

    Returns:
        A list of RDS instances carrying privileged-data risk.
    """
    found: list[PrivilegedAccount] = []
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page.get("DBInstances", []):
            reasons: list[str] = []
            if not db.get("StorageEncrypted", False):
                reasons.append("storage not encrypted")
            if db.get("PubliclyAccessible", False):
                reasons.append("publicly accessible")
            if reasons:
                found.append(
                    PrivilegedAccount(
                        identifier=db["DBInstanceIdentifier"],
                        account_type="rds_instance",
                        arn=db.get("DBInstanceArn", ""),
                        reasons=reasons,
                        risk=_classify(reasons, None),
                        metadata={"engine": db.get("Engine", "")},
                    )
                )
    LOGGER.info("Discovered %d at-risk RDS instances", len(found))
    return found


def run_discovery(region: str, profile: str | None = None) -> list[PrivilegedAccount]:
    """Run all discovery collectors and return the merged inventory.

    Args:
        region: AWS region to scan.
        profile: Optional named AWS profile.

    Returns:
        Combined list of discovered privileged accounts.
    """
    session = build_session(region=region, profile=profile)
    cfg = client_config()
    iam = session.client("iam", config=cfg)
    rds = session.client("rds", config=cfg)

    accounts: list[PrivilegedAccount] = []
    accounts.extend(discover_iam_users(iam))
    accounts.extend(discover_iam_roles(iam))
    accounts.extend(discover_rds_instances(rds))
    return accounts


def to_export(accounts: list[PrivilegedAccount], fmt: str) -> dict[str, Any]:
    """Serialize the inventory into the requested export format.

    Args:
        accounts: Discovered accounts.
        fmt: ``json`` (native), ``cyberark``, or ``beyondtrust``.

    Returns:
        A JSON-serializable dict.
    """
    summary = {
        "generated_at": utc_now_iso(),
        "total": len(accounts),
        "by_risk": {
            tier: sum(1 for a in accounts if a.risk == tier)
            for tier in ("critical", "high", "medium", "low")
        },
    }
    if fmt == "cyberark":
        return {
            "summary": summary,
            "accounts": [
                {
                    "name": a.identifier,
                    "platformId": a.account_type,
                    "address": a.arn,
                    "safe": f"PAM-{a.risk.upper()}",
                }
                for a in accounts
            ],
        }
    if fmt == "beyondtrust":
        return {
            "summary": summary,
            "ManagedAccounts": [
                {"AccountName": a.identifier, "Description": "; ".join(a.reasons)}
                for a in accounts
            ],
        }
    return {"summary": summary, "accounts": [asdict(a) for a in accounts]}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1", help="AWS region to scan.")
    parser.add_argument("--profile", default=None, help="Named AWS profile.")
    parser.add_argument("--output", default="-", help="Output file or '-' for stdout.")
    parser.add_argument(
        "--format",
        default="json",
        choices=["json", "cyberark", "beyondtrust"],
        help="Export format.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = parse_args(argv)
    try:
        accounts = run_discovery(args.region, args.profile)
    except Exception as exc:  # noqa: BLE001 - top-level guard with logging
        LOGGER.error("Discovery failed: %s", exc)
        return 1

    payload = to_export(accounts, args.format)
    text = json.dumps(payload, indent=2, default=str)
    if args.output == "-":
        print(text)
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
        LOGGER.info("Wrote inventory to %s", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
