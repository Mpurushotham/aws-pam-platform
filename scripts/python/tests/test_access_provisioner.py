"""Unit tests for pam_access_provisioner using an in-memory fake table/IAM."""

import pytest

import pam_access_provisioner as prov


class FakeTable:
    """Minimal in-memory stand-in for a DynamoDB Table resource."""

    def __init__(self):
        self.items: dict[str, dict] = {}

    def put_item(self, Item):  # noqa: N803 - boto3 kwarg name
        self.items[Item["request_id"]] = dict(Item)

    def get_item(self, Key):  # noqa: N803
        item = self.items.get(Key["request_id"])
        return {"Item": dict(item)} if item else {}


class FakeIAMExceptions:
    class NoSuchEntityException(Exception):
        pass


class FakeIAM:
    """Records group membership mutations."""

    def __init__(self):
        self.added: list[tuple[str, str]] = []
        self.removed: list[tuple[str, str]] = []
        self.exceptions = FakeIAMExceptions()

    def add_user_to_group(self, GroupName, UserName):  # noqa: N803
        self.added.append((GroupName, UserName))

    def remove_user_from_group(self, GroupName, UserName):  # noqa: N803
        self.removed.append((GroupName, UserName))


def test_create_request_persists_pending():
    table = FakeTable()
    item = prov.create_request(table, "alice", "break-glass-admin", 2, "incident 1")
    assert item["status"] == "pending"
    assert table.items[item["request_id"]]["user"] == "alice"


def test_create_request_rejects_bad_duration():
    with pytest.raises(ValueError):
        prov.create_request(FakeTable(), "alice", "role", 99, "reason")


def test_create_request_requires_reason():
    with pytest.raises(ValueError):
        prov.create_request(FakeTable(), "alice", "role", 1, "   ")


def test_approve_grants_membership_and_activates():
    table, iam = FakeTable(), FakeIAM()
    req = prov.create_request(table, "alice", "break-glass-admin", 1, "incident")
    updated = prov.approve_request(table, iam, req["request_id"], "bob")
    assert updated["status"] == "active"
    assert ("break-glass-admin", "alice") in iam.added
    assert "expires_at" in updated


def test_self_approval_rejected():
    table, iam = FakeTable(), FakeIAM()
    req = prov.create_request(table, "alice", "role", 1, "incident")
    with pytest.raises(ValueError, match="self-approval"):
        prov.approve_request(table, iam, req["request_id"], "alice")


def test_approve_missing_request_raises():
    with pytest.raises(ValueError, match="not found"):
        prov.approve_request(FakeTable(), FakeIAM(), "deadbeef", "bob")


def test_revoke_removes_membership():
    table, iam = FakeTable(), FakeIAM()
    req = prov.create_request(table, "alice", "role", 1, "incident")
    prov.approve_request(table, iam, req["request_id"], "bob")
    prov.revoke_request(table, iam, req["request_id"])
    assert ("role", "alice") in iam.removed
    assert table.items[req["request_id"]]["status"] == "revoked"
