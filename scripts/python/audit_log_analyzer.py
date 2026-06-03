#!/usr/bin/env python3
"""Analyze CloudTrail events for suspicious privileged activity.

Pulls recent events via the CloudTrail LookupEvents API (or reads a local
JSON export) and applies heuristic detections: console logins without MFA,
root account usage, IAM policy changes, mass deletions, and access denials
that may indicate probing. Emits findings and exits non-zero when any
high-severity anomaly is detected.

Examples:
    python audit_log_analyzer.py --region us-east-1 --hours 24
    python audit_log_analyzer.py --input events.json --output findings.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from pam_common import build_session, client_config, configure_logging, utc_now_iso

LOGGER = configure_logging(__name__)

# Sensitive write actions worth flagging when they appear.
_SENSITIVE_ACTIONS = {
    "DeleteTrail",
    "StopLogging",
    "PutUserPolicy",
    "AttachUserPolicy",
    "CreateAccessKey",
    "DeleteBucketPolicy",
    "UpdateAssumeRolePolicy",
}
_MASS_DELETE_THRESHOLD = 10
_ACCESS_DENIED_THRESHOLD = 5


@dataclass
class Finding:
    """A single detected anomaly."""

    rule: str
    severity: str  # low | medium | high
    principal: str
    detail: str
    count: int = 1


def _event_name(event: dict[str, Any]) -> str:
    return event.get("EventName", event.get("eventName", ""))


def _principal(event: dict[str, Any]) -> str:
    return event.get("Username", event.get("userIdentity", {}).get("arn", "unknown"))


def _detail_json(event: dict[str, Any]) -> dict[str, Any]:
    """Return the parsed CloudTrailEvent detail, tolerating both shapes."""
    raw = event.get("CloudTrailEvent")
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return event if "eventName" in event else {}


def detect(events: list[dict[str, Any]]) -> list[Finding]:
    """Apply all heuristics to a batch of events.

    Args:
        events: CloudTrail event dicts (LookupEvents or raw export shape).

    Returns:
        A list of findings, possibly empty.
    """
    findings: list[Finding] = []
    deletes: Counter[str] = Counter()
    denials: Counter[str] = Counter()

    for event in events:
        name = _event_name(event)
        principal = _principal(event)
        detail = _detail_json(event)

        # Root account usage.
        identity_type = detail.get("userIdentity", {}).get("type", "")
        if identity_type == "Root":
            findings.append(
                Finding("root-usage", "high", principal, f"root used for {name}")
            )

        # Console login without MFA.
        if name == "ConsoleLogin":
            mfa = detail.get("additionalEventData", {}).get("MFAUsed", "")
            success = detail.get("responseElements", {}).get("ConsoleLogin", "")
            if mfa == "No" and success == "Success":
                findings.append(
                    Finding(
                        "login-without-mfa",
                        "high",
                        principal,
                        "successful console login without MFA",
                    )
                )

        # Sensitive configuration changes.
        if name in _SENSITIVE_ACTIONS:
            findings.append(
                Finding(
                    "sensitive-action", "medium", principal, f"sensitive action: {name}"
                )
            )

        # Tally deletes and access denials for threshold rules.
        if name.startswith("Delete"):
            deletes[principal] += 1
        if detail.get("errorCode") in {"AccessDenied", "UnauthorizedOperation"}:
            denials[principal] += 1

    for principal, count in deletes.items():
        if count >= _MASS_DELETE_THRESHOLD:
            findings.append(
                Finding(
                    "mass-deletion",
                    "high",
                    principal,
                    f"{count} delete actions in window",
                    count,
                )
            )
    for principal, count in denials.items():
        if count >= _ACCESS_DENIED_THRESHOLD:
            findings.append(
                Finding(
                    "repeated-access-denied",
                    "medium",
                    principal,
                    f"{count} access-denied errors (possible probing)",
                    count,
                )
            )
    return findings


def fetch_events(region: str, hours: int, profile: str | None) -> list[dict[str, Any]]:
    """Fetch CloudTrail events for the trailing ``hours`` window.

    Args:
        region: AWS region.
        hours: Lookback window in hours.
        profile: Optional named AWS profile.

    Returns:
        A list of raw CloudTrail event dicts.
    """
    client = build_session(region=region, profile=profile).client(
        "cloudtrail", config=client_config()
    )
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    events: list[dict[str, Any]] = []
    paginator = client.get_paginator("lookup_events")
    for page in paginator.paginate(StartTime=start):
        events.extend(page.get("Events", []))
    LOGGER.info("Fetched %d events over the last %dh", len(events), hours)
    return events


def load_events(path: str) -> list[dict[str, Any]]:
    """Load events from a local JSON file (list or {"Events": [...]})."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        return data.get("Events", [])
    return data if isinstance(data, list) else []


def build_report(findings: Iterable[Finding]) -> dict[str, Any]:
    """Assemble a findings report with severity counts."""
    findings = list(findings)
    return {
        "generated_at": utc_now_iso(),
        "total_findings": len(findings),
        "by_severity": {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("high", "medium", "low")
        },
        "findings": [asdict(f) for f in findings],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1", help="AWS region.")
    parser.add_argument("--profile", default=None, help="Named AWS profile.")
    parser.add_argument("--hours", type=int, default=24, help="Lookback window hours.")
    parser.add_argument("--input", default=None, help="Read events from a JSON file.")
    parser.add_argument(
        "--output", default="-", help="Findings path or '-' for stdout."
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code (1 if high-severity findings)."""
    args = parse_args(argv)
    try:
        events = (
            load_events(args.input)
            if args.input
            else fetch_events(args.region, args.hours, args.profile)
        )
        findings = detect(events)
    except Exception as exc:  # noqa: BLE001 - top-level guard with logging
        LOGGER.error("Analysis failed: %s", exc)
        return 2

    report = build_report(findings)
    text = json.dumps(report, indent=2)
    if args.output == "-":
        print(text)
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
        LOGGER.info("Wrote findings to %s", args.output)

    high = report["by_severity"]["high"]
    if high:
        LOGGER.error("%d high-severity anomaly(ies) detected", high)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
