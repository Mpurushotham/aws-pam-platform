# Security Policy

This repository defines security-critical infrastructure (Privileged Access
Management). We hold it to a high bar and welcome responsible disclosure.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's **[Private vulnerability reporting](https://github.com/Mpurushotham/aws-pam-platform/security/advisories/new)**
(Security tab → "Report a vulnerability"). It is enabled on this repo and keeps
the report private until a fix is ready.

When reporting, please include:

- A description of the issue and its impact.
- Steps to reproduce (or the affected file / line / module).
- Any suggested remediation.

We aim to acknowledge reports within **3 business days** and to provide a
remediation timeline after triage.

## Supported versions

This project follows a rolling release on the `main` branch. Only the latest
commit on `main` is supported; please base reports on current `main`.

## What we consider in scope

- IAM privilege-escalation paths or missing MFA enforcement.
- Secrets exposure (hardcoded credentials, secrets in state/logs).
- Weakened encryption (missing KMS, TLS not enforced).
- CI/CD weaknesses (token scope, OIDC trust, action supply chain).
- Broken audit/logging guarantees.

Out of scope: issues in third-party dependencies already tracked upstream
(report those to the upstream project; Dependabot tracks them here).

## Our security practices

This repo is built defensively. The controls below are enforced in code and in
the GitHub configuration:

| Area | Control |
| ---- | ------- |
| Secrets | Secret scanning **with push protection**; gitleaks + `detect-aws-credentials` pre-commit hooks; a repo test (`tests/compliance/`) fails on hardcoded credentials; no secrets in state. |
| Dependencies | Dependabot alerts + automated security updates for pip, GitHub Actions, and Terraform. |
| Code scanning | CodeQL static analysis on every PR and weekly. |
| IaC scanning | `checkov` + `tflint` gate every PR via `iac-validate.yml`. |
| Branch protection | `main` requires PRs, status checks, signed commits, and linear history; force-pushes and deletions are blocked. |
| Cloud access | No long-lived AWS keys — humans use MFA federation, CI uses GitHub OIDC. |
| Least privilege | Every workflow declares minimal `permissions:`; every IAM role enforces MFA. |

## Hardening backlog (good first contributions)

- Pin third-party GitHub Actions to commit SHAs (supply-chain hardening);
  Dependabot is configured to manage the bumps.
- Add `step-security/harden-runner` to CI jobs for egress control.
