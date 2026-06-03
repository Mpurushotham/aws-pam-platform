#!/usr/bin/env python3
"""Time-bound privileged access provisioning with an approval workflow.

Backs self-service access requests with a DynamoDB table. A request moves
through ``pending`` -> ``approved`` -> ``active`` -> ``expired``/``revoked``.
On approval the requester is added to the target IAM group for a bounded
duration; an expiry sweep removes membership once the grant lapses.

Examples:
    python pam_access_provisioner.py request --user alice \
        --role break-glass-admin --hours 2 --reason "incident 4821"
    python pam_access_provisioner.py approve --request-id 1a2b3c --approver bob
    python pam_access_provisioner.py expire-sweep
"""

from __future__ import annotations

import argparse
import secrets
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from pam_common import build_session, client_config, configure_logging

LOGGER = configure_logging(__name__)

_TABLE_DEFAULT = "pam-access-requests"
_MAX_HOURS = 12


def _table(region: str, profile: str | None, name: str) -> Any:
    """Return a DynamoDB Table resource."""
    ddb = build_session(region=region, profile=profile).resource(
        "dynamodb", config=client_config()
    )
    return ddb.Table(name)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_request(
    table: Any, user: str, role: str, hours: int, reason: str
) -> dict[str, Any]:
    """Create a pending access request.

    Args:
        table: DynamoDB Table resource.
        user: IAM user requesting access.
        role: Logical privileged role / IAM group to grant.
        hours: Requested grant duration (1..12).
        reason: Business justification (required for audit).

    Returns:
        The persisted request item.

    Raises:
        ValueError: If duration is out of range or reason is empty.
    """
    if not 1 <= hours <= _MAX_HOURS:
        raise ValueError(f"hours must be between 1 and {_MAX_HOURS}")
    if not reason.strip():
        raise ValueError("a justification reason is required")

    request_id = secrets.token_hex(6)
    item = {
        "request_id": request_id,
        "user": user,
        "role": role,
        "duration_hours": hours,
        "reason": reason,
        "status": "pending",
        "created_at": _now().isoformat(),
    }
    table.put_item(Item=item)
    LOGGER.info("Created access request %s for %s -> %s", request_id, user, role)
    return item


def approve_request(
    table: Any, iam: Any, request_id: str, approver: str
) -> dict[str, Any]:
    """Approve a pending request and grant time-bound IAM group membership.

    Args:
        table: DynamoDB Table resource.
        iam: boto3 IAM client.
        request_id: Request to approve.
        approver: Identity granting approval (must differ from requester).

    Returns:
        The updated request item.

    Raises:
        ValueError: If the request is missing, not pending, or self-approved.
    """
    resp = table.get_item(Key={"request_id": request_id})
    item = resp.get("Item")
    if not item:
        raise ValueError(f"request {request_id} not found")
    if item["status"] != "pending":
        raise ValueError(f"request {request_id} is {item['status']}, not pending")
    if item["user"] == approver:
        raise ValueError("self-approval is not permitted (separation of duties)")

    expires = _now() + timedelta(hours=int(item["duration_hours"]))
    iam.add_user_to_group(GroupName=item["role"], UserName=item["user"])

    item.update(
        {
            "status": "active",
            "approver": approver,
            "approved_at": _now().isoformat(),
            "expires_at": expires.isoformat(),
        }
    )
    table.put_item(Item=item)
    LOGGER.info(
        "Approved %s by %s; %s active until %s",
        request_id,
        approver,
        item["user"],
        item["expires_at"],
    )
    return item


def revoke_request(table: Any, iam: Any, request_id: str) -> dict[str, Any]:
    """Revoke an active grant immediately.

    Args:
        table: DynamoDB Table resource.
        iam: boto3 IAM client.
        request_id: Request to revoke.

    Returns:
        The updated request item.

    Raises:
        ValueError: If the request is not found.
    """
    item = table.get_item(Key={"request_id": request_id}).get("Item")
    if not item:
        raise ValueError(f"request {request_id} not found")
    _remove_membership(iam, item)
    item["status"] = "revoked"
    item["revoked_at"] = _now().isoformat()
    table.put_item(Item=item)
    LOGGER.warning("Revoked access request %s", request_id)
    return item


def _remove_membership(iam: Any, item: dict[str, Any]) -> None:
    """Best-effort removal of a user from the granted group."""
    try:
        iam.remove_user_from_group(GroupName=item["role"], UserName=item["user"])
    except iam.exceptions.NoSuchEntityException:
        LOGGER.debug("membership already absent for %s", item["request_id"])


def expire_sweep(table: Any, iam: Any) -> int:
    """Expire all active grants past their ``expires_at`` timestamp.

    Args:
        table: DynamoDB Table resource.
        iam: boto3 IAM client.

    Returns:
        The number of grants expired.
    """
    now = _now()
    expired = 0
    scan_kwargs: dict[str, Any] = {
        "FilterExpression": "#s = :active",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":active": "active"},
    }
    while True:
        page = table.scan(**scan_kwargs)
        for item in page.get("Items", []):
            if datetime.fromisoformat(item["expires_at"]) <= now:
                _remove_membership(iam, item)
                item["status"] = "expired"
                item["expired_at"] = now.isoformat()
                table.put_item(Item=item)
                expired += 1
                LOGGER.info("Expired grant %s", item["request_id"])
        if "LastEvaluatedKey" not in page:
            break
        scan_kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    LOGGER.info("Expiry sweep complete: %d grant(s) expired", expired)
    return expired


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1", help="AWS region.")
    parser.add_argument("--profile", default=None, help="Named AWS profile.")
    parser.add_argument("--table", default=_TABLE_DEFAULT, help="DynamoDB table name.")
    sub = parser.add_subparsers(dest="command", required=True)

    req = sub.add_parser("request", help="Create an access request.")
    req.add_argument("--user", required=True)
    req.add_argument("--role", required=True)
    req.add_argument("--hours", type=int, default=1)
    req.add_argument("--reason", required=True)

    app = sub.add_parser("approve", help="Approve a pending request.")
    app.add_argument("--request-id", required=True)
    app.add_argument("--approver", required=True)

    rev = sub.add_parser("revoke", help="Revoke an active grant.")
    rev.add_argument("--request-id", required=True)

    sub.add_parser("expire-sweep", help="Expire lapsed grants.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = parse_args(argv)
    table = _table(args.region, args.profile, args.table)
    iam = build_session(region=args.region, profile=args.profile).client(
        "iam", config=client_config()
    )
    try:
        if args.command == "request":
            create_request(table, args.user, args.role, args.hours, args.reason)
        elif args.command == "approve":
            approve_request(table, iam, args.request_id, args.approver)
        elif args.command == "revoke":
            revoke_request(table, iam, args.request_id)
        elif args.command == "expire-sweep":
            expire_sweep(table, iam)
    except Exception as exc:  # noqa: BLE001 - top-level guard with logging
        LOGGER.error("Command '%s' failed: %s", args.command, exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
