# Architecture

This document describes the design of the AWS PAM platform: its components,
data flows, trust boundaries, and the principles behind each decision.

> 📊 **Rendered diagrams** (system context, module graph, sequence flows, CI/CD)
> live in [DIAGRAMS.md](DIAGRAMS.md) as GitHub-native Mermaid. New to the repo?
> Start with [ONBOARDING.md](ONBOARDING.md).

## Design principles

1. **Least privilege by default** — every role and policy grants the minimum
   set of actions, scoped by resource ARN and guarded by conditions.
2. **No standing privileged access** — privileged grants are time-bound and
   expire automatically; break-glass roles require MFA per assumption.
3. **Everything is recorded** — 100% of API activity (CloudTrail) and every
   interactive session (SSM) is captured and retained.
4. **No long-lived credentials** — humans use federated/MFA access; CI uses
   GitHub OIDC to assume short-lived roles.
5. **Defense in depth** — KMS encryption, TLS enforcement, public-access
   blocks, and continuous compliance evaluation are layered together.

## Component overview

```
                         ┌──────────────────────────────────────┐
                         │            AWS Account (env)           │
   Engineer (MFA) ──────▶│                                        │
        │                │   IAM Roles (MFA, time-bound)          │
        │  StartSession  │      │                                 │
        ▼                │      ▼                                 │
   SSM Session ─────────▶│   Session Manager ──▶ S3 + CloudWatch  │
   Manager (no SSH)      │                         (KMS, recorded)│
                         │                                        │
   Secrets consumers ───▶│   Secrets Manager ──▶ rotation Lambda  │
                         │      (KMS, 30d rotation)               │
                         │                                        │
   All API calls ───────▶│   CloudTrail ──▶ S3 (immutable) +      │
                         │                  CloudWatch Logs (KMS) │
                         │                     │                  │
                         │                     ▼                  │
                         │   Metric filters ──▶ Alarms ──▶ SNS    │
                         │                                        │
                         │   AWS Config ──▶ Managed rules ──▶     │
                         │       (CIS/PCI/SOC2)  EventBridge ─▶SNS │
                         └──────────────────────────────────────┘
                                        │
                  Grafana (CloudWatch datasource) ◀── dashboards
```

## Terraform module map

| Module | Responsibility | Key resources |
| ------ | -------------- | ------------- |
| `kms-encryption` | Customer-managed keys per data domain | `aws_kms_key` (secrets, cloudtrail) |
| `cloudtrail-audit` | Tamper-evident audit trail + session log group | `aws_cloudtrail`, S3, `aws_cloudwatch_log_group` |
| `iam-policies` | Least-privilege managed policies | `aws_iam_policy` (read/admin/session/auditor) |
| `iam-roles` | MFA-enforced privileged roles | `aws_iam_role`, trust policy w/ `MultiFactorAuthPresent` |
| `pam-secrets-manager` | Encrypted secrets + rotation schedule | `aws_secretsmanager_secret`, `_rotation` |
| `ssm-session-manager` | Recorded keyless sessions | `aws_ssm_document`, S3 session bucket |
| `compliance-framework` | Continuous compliance + alerting | `aws_config_*`, `aws_sns_topic`, EventBridge |

Each environment (`terraform/environments/{dev,stage,prod}`) is an identical
composition of these modules; only variable values differ (rotation cadence,
retention, trusted accounts).

## Trust boundaries

- **Human → AWS**: federated identity with mandatory MFA; `MultiFactorAuthAge`
  caps the session freshness window at one hour.
- **CI → AWS**: GitHub OIDC provider trust; each environment has its own
  deploy role with a scoped permission boundary. Prod requires a manual
  approval gate (`production` GitHub Environment).
- **Cross-account**: `trusted_account_ids` extends role trust policies to
  named accounts only, still gated by MFA.

## Data flows & retention

| Data | Store | Encryption | Retention |
| ---- | ----- | ---------- | --------- |
| API audit logs | S3 + CloudWatch | KMS (cloudtrail key) | S3 ~7y (Glacier @ 90d), CW configurable |
| Session recordings | S3 + CloudWatch | KMS (secrets key) | 90d dev / 365d prod |
| Secrets | Secrets Manager | KMS (secrets key) | versioned; rotation 14–30d |
| Config snapshots | S3 | KMS (secrets key) | per S3 lifecycle |

## Scripts as operational glue

The five Python tools in `scripts/python/` operate the platform:
discovery feeds an external PAM (CyberArk/BeyondTrust), rotation drives the
Secrets Manager rotation contract with rollback, the compliance auditor and
audit-log analyzer run on schedule via GitHub Actions, and the access
provisioner manages the request → approval → expiry lifecycle in DynamoDB.

See [DEPLOYMENT.md](DEPLOYMENT.md) to stand the platform up and
[COMPLIANCE.md](COMPLIANCE.md) for the control mapping.
