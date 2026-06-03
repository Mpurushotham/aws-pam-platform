"""Shared utilities for the AWS PAM operational scripts.

Provides consistent structured logging, a typed boto3 session factory, a
retry decorator for throttled AWS calls, and small helpers used across the
discovery, rotation, compliance, provisioning, and audit-analysis scripts.
"""

from __future__ import annotations

import functools
import logging
import os
import sys
import time
from typing import Any, Callable, TypeVar

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "boto3 is required. Install with: pip install -r requirements.txt"
    ) from exc

T = TypeVar("T")

# Errors that are safe to retry with backoff.
_RETRYABLE_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "RequestThrottled",
}


def configure_logging(name: str, level: str | None = None) -> logging.Logger:
    """Return a logger that emits structured, timestamped records to stderr.

    Args:
        name: Logger name, typically ``__name__`` of the calling module.
        level: Log level override. Falls back to the ``PAM_LOG_LEVEL``
            environment variable, then ``INFO``.

    Returns:
        A configured :class:`logging.Logger` (idempotent across calls).
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    resolved = (level or os.environ.get("PAM_LOG_LEVEL", "INFO")).upper()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, resolved, logging.INFO))
    logger.propagate = False
    return logger


def build_session(
    region: str | None = None, profile: str | None = None
) -> "boto3.session.Session":
    """Create a boto3 session honouring explicit region/profile overrides.

    Args:
        region: AWS region; defaults to the environment's configured region.
        profile: Named AWS profile to use; defaults to the standard chain.

    Returns:
        A configured boto3 :class:`~boto3.session.Session`.
    """
    return boto3.session.Session(region_name=region, profile_name=profile)


def client_config() -> "Config":
    """Return a botocore ``Config`` with adaptive retries and a sane timeout."""
    return Config(
        retries={"max_attempts": 10, "mode": "adaptive"},
        connect_timeout=10,
        read_timeout=30,
        user_agent_extra="aws-pam-infrastructure",
    )


def retry_on_throttle(
    max_attempts: int = 5, base_delay: float = 1.0
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator retrying a function on AWS throttling with exponential backoff.

    Args:
        max_attempts: Maximum number of attempts before giving up.
        base_delay: Base delay in seconds; doubles each retry.

    Returns:
        A decorator wrapping the target callable.
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exc: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code not in _RETRYABLE_CODES or attempt == max_attempts:
                        raise
                    last_exc = exc
                    delay = base_delay * (2 ** (attempt - 1))
                    time.sleep(delay)
            # Unreachable, but satisfies type-checkers.
            raise last_exc  # type: ignore[misc]

        return wrapper

    return decorator


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with ``Z`` suffix."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
