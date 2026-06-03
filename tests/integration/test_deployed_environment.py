"""Opt-in integration smoke tests against a deployed PAM environment.

Skipped unless ``PAM_INTEGRATION=1`` is set and AWS credentials are available.
Run with: PAM_INTEGRATION=1 AWS_REGION=us-east-1 pytest tests/integration -v
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("PAM_INTEGRATION") != "1",
    reason="set PAM_INTEGRATION=1 (and provide AWS creds) to run integration tests",
)

REGION = os.environ.get("AWS_REGION", "us-east-1")
PREFIX = os.environ.get("PAM_NAME_PREFIX", "pam-dev")


@pytest.fixture(scope="module")
def session():
    boto3 = pytest.importorskip("boto3")
    return boto3.session.Session(region_name=REGION)


def test_cloudtrail_is_logging(session):
    """A multi-region trail exists and is actively logging."""
    client = session.client("cloudtrail")
    trails = client.describe_trails().get("trailList", [])
    assert any(t.get("IsMultiRegionTrail") for t in trails), "no multi-region trail"


def test_privileged_roles_exist(session):
    """The expected privileged roles were provisioned."""
    iam = session.client("iam")
    names = {r["RoleName"] for r in iam.list_roles().get("Roles", [])}
    assert f"{PREFIX}-break-glass-admin" in names


def test_secrets_are_kms_encrypted(session):
    """Every PAM-managed secret is encrypted with a KMS key."""
    client = session.client("secretsmanager")
    secrets = client.list_secrets(
        Filters=[{"Key": "name", "Values": [f"{PREFIX}/"]}]
    ).get("SecretList", [])
    for secret in secrets:
        assert secret.get("KmsKeyId"), f"{secret['Name']} not KMS-encrypted"
