#!/usr/bin/env python3
"""Rotate AWS Secrets Manager secrets with rollback support.

Implements the four-step Secrets Manager rotation contract (createSecret,
setSecret, testSecret, finishSecret) and a CLI to trigger rotation on demand.
Generates cryptographically strong replacement values, stages them under the
``AWSPENDING`` label, verifies them, and promotes to ``AWSCURRENT`` — keeping
the previous value as ``AWSPREVIOUS`` so a rollback is always possible.

Examples:
    python pam_secret_rotation.py --secret-id pam-dev/app-api-key
    python pam_secret_rotation.py --secret-id pam-dev/rds-master --rollback
"""

from __future__ import annotations

import argparse
import json
import secrets
import string
import sys
from typing import Any

from pam_common import build_session, client_config, configure_logging

LOGGER = configure_logging(__name__)

_DEFAULT_LENGTH = 32
# Exclude characters that commonly break connection strings / shells.
_SAFE_PUNCTUATION = "!#%*+-_=?"


def generate_secret(length: int = _DEFAULT_LENGTH) -> str:
    """Generate a cryptographically strong random secret.

    Guarantees at least one lower, upper, digit, and safe punctuation char.

    Args:
        length: Desired length (minimum 16).

    Returns:
        The generated secret string.

    Raises:
        ValueError: If ``length`` is below 16.
    """
    if length < 16:
        raise ValueError("secret length must be at least 16")
    alphabet = string.ascii_letters + string.digits + _SAFE_PUNCTUATION
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in candidate)
            and any(c.isupper() for c in candidate)
            and any(c.isdigit() for c in candidate)
            and any(c in _SAFE_PUNCTUATION for c in candidate)
        ):
            return candidate


def _current_value(client: Any, secret_id: str) -> dict[str, Any]:
    """Return the current secret value parsed as a dict (JSON or wrapped)."""
    resp = client.get_secret_value(SecretId=secret_id, VersionStage="AWSCURRENT")
    raw = resp.get("SecretString", "{}")
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"value": raw}
    except json.JSONDecodeError:
        return {"value": raw}


def rotate_secret(secret_id: str, region: str, profile: str | None = None) -> str:
    """Rotate a secret end-to-end and promote the new value.

    Args:
        secret_id: Secret name or ARN.
        region: AWS region.
        profile: Optional named AWS profile.

    Returns:
        The new version ID that became ``AWSCURRENT``.

    Raises:
        RuntimeError: If verification of the staged value fails.
    """
    client = build_session(region=region, profile=profile).client(
        "secretsmanager", config=client_config()
    )

    current = _current_value(client, secret_id)
    new_value = dict(current)
    # Rotate the password-like field; preserve username/host/etc.
    field = "password" if "password" in current else "value"
    new_value[field] = generate_secret()

    pending_version = secrets.token_hex(16)
    LOGGER.info("Staging new value for %s (version=%s)", secret_id, pending_version)
    client.put_secret_value(
        SecretId=secret_id,
        ClientRequestToken=pending_version,
        SecretString=json.dumps(new_value),
        VersionStages=["AWSPENDING"],
    )

    # testSecret: re-read the pending value and confirm it round-trips.
    staged = client.get_secret_value(
        SecretId=secret_id, VersionId=pending_version, VersionStage="AWSPENDING"
    )
    if json.loads(staged["SecretString"])[field] != new_value[field]:
        raise RuntimeError("staged secret verification failed; aborting rotation")

    # finishSecret: move AWSCURRENT to the pending version.
    described = client.describe_secret(SecretId=secret_id)
    current_version = next(
        (
            vid
            for vid, stages in described.get("VersionIdsToStages", {}).items()
            if "AWSCURRENT" in stages
        ),
        None,
    )
    client.update_secret_version_stage(
        SecretId=secret_id,
        VersionStage="AWSCURRENT",
        MoveToVersionId=pending_version,
        RemoveFromVersionId=current_version,
    )
    LOGGER.info("Promoted %s to AWSCURRENT for %s", pending_version, secret_id)
    return pending_version


def rollback_secret(secret_id: str, region: str, profile: str | None = None) -> str:
    """Roll back a secret by promoting ``AWSPREVIOUS`` to ``AWSCURRENT``.

    Args:
        secret_id: Secret name or ARN.
        region: AWS region.
        profile: Optional named AWS profile.

    Returns:
        The version ID restored to ``AWSCURRENT``.

    Raises:
        RuntimeError: If no ``AWSPREVIOUS`` version exists to roll back to.
    """
    client = build_session(region=region, profile=profile).client(
        "secretsmanager", config=client_config()
    )
    described = client.describe_secret(SecretId=secret_id)
    stages = described.get("VersionIdsToStages", {})
    previous = next((v for v, s in stages.items() if "AWSPREVIOUS" in s), None)
    current = next((v for v, s in stages.items() if "AWSCURRENT" in s), None)
    if previous is None:
        raise RuntimeError("no AWSPREVIOUS version available for rollback")

    client.update_secret_version_stage(
        SecretId=secret_id,
        VersionStage="AWSCURRENT",
        MoveToVersionId=previous,
        RemoveFromVersionId=current,
    )
    LOGGER.warning("Rolled back %s to previous version %s", secret_id, previous)
    return previous


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-id", required=True, help="Secret name or ARN.")
    parser.add_argument("--region", default="us-east-1", help="AWS region.")
    parser.add_argument("--profile", default=None, help="Named AWS profile.")
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Roll back to AWSPREVIOUS instead of rotating.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = parse_args(argv)
    try:
        if args.rollback:
            version = rollback_secret(args.secret_id, args.region, args.profile)
            LOGGER.info("Rollback complete: %s", version)
        else:
            version = rotate_secret(args.secret_id, args.region, args.profile)
            LOGGER.info("Rotation complete: %s", version)
    except Exception as exc:  # noqa: BLE001 - top-level guard with logging
        LOGGER.error("Operation failed for %s: %s", args.secret_id, exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
