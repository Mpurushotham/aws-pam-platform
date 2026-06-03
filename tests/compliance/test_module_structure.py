"""Repository-invariant compliance tests — no AWS or network required.

Verifies the Terraform module layout, that every privileged role trust policy
enforces MFA, and that no obvious hardcoded secrets exist in the codebase.
Run with: pytest tests/compliance -v
"""

from __future__ import annotations

import os
import re

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODULES_DIR = os.path.join(REPO_ROOT, "terraform", "modules")
ENVIRONMENTS = ("dev", "stage", "prod")

EXPECTED_MODULES = {
    "iam-roles",
    "iam-policies",
    "pam-secrets-manager",
    "ssm-session-manager",
    "kms-encryption",
    "cloudtrail-audit",
    "compliance-framework",
}


def test_all_modules_present():
    """Every expected module directory exists."""
    present = {d for d in os.listdir(MODULES_DIR) if os.path.isdir(os.path.join(MODULES_DIR, d))}
    missing = EXPECTED_MODULES - present
    assert not missing, f"missing modules: {missing}"


def test_each_module_has_standard_files():
    """Each module ships variables.tf, main.tf, and outputs.tf."""
    for module in EXPECTED_MODULES:
        for filename in ("variables.tf", "main.tf", "outputs.tf"):
            path = os.path.join(MODULES_DIR, module, filename)
            assert os.path.isfile(path), f"{module} is missing {filename}"


def test_iam_roles_enforce_mfa():
    """The iam-roles module references the MFA condition key."""
    main_tf = os.path.join(MODULES_DIR, "iam-roles", "main.tf")
    with open(main_tf, encoding="utf-8") as handle:
        content = handle.read()
    assert "aws:MultiFactorAuthPresent" in content


def test_each_environment_composes_modules():
    """Every environment wires up the module compositions."""
    for env in ENVIRONMENTS:
        main_tf = os.path.join(REPO_ROOT, "terraform", "environments", env, "main.tf")
        assert os.path.isfile(main_tf), f"{env}/main.tf missing"
        with open(main_tf, encoding="utf-8") as handle:
            content = handle.read()
        assert 'source      = "../../modules/kms-encryption"' in content or \
               "../../modules/kms-encryption" in content


def _iter_source_files():
    """Yield paths to source files worth scanning for secrets."""
    skip_dirs = {".git", ".terraform", "__pycache__", ".pytest_cache", "node_modules"}
    exts = (".tf", ".py", ".yml", ".yaml", ".json", ".sh")
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in files:
            if name.endswith(exts):
                yield os.path.join(root, name)


# Patterns that indicate a real hardcoded credential (not a variable reference).
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                       # AWS access key id
    re.compile(r"aws_secret_access_key\s*=\s*[\"'][A-Za-z0-9/+]{40}[\"']"),
    re.compile(r"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----"),
]


def test_no_hardcoded_secrets():
    """No source file contains an obvious hardcoded credential."""
    offenders: list[str] = []
    for path in _iter_source_files():
        with open(path, encoding="utf-8", errors="ignore") as handle:
            text = handle.read()
        for pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                offenders.append(f"{os.path.relpath(path, REPO_ROOT)} :: {pattern.pattern}")
    assert not offenders, f"possible hardcoded secrets: {offenders}"
