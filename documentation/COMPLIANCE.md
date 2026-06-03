# Compliance Control Mapping

How this platform's controls map to CIS AWS Foundations Benchmark, PCI-DSS, and
SOC 2. Each row links a technical control to where it is implemented and how it
is continuously verified.

## Summary

| Framework | Coverage focus | Primary evidence |
| --------- | -------------- | ---------------- |
| **CIS AWS Foundations** | IAM, logging, monitoring, encryption | AWS Config managed rules + `compliance_auditor.py` |
| **PCI-DSS v4.0** | Req. 3 (protect stored data), Req. 7–8 (access), Req. 10 (logging) | CloudTrail, KMS, IAM policies |
| **SOC 2** | CC6 (logical access), CC7 (monitoring) | Session recording, audit trail, alerts |

## CIS AWS Foundations Benchmark

| CIS | Control | Implementation | Verification |
| --- | ------- | -------------- | ------------ |
| 1.5 | Root account MFA | Org policy; not provisioned here | `compliance_auditor.check_root_mfa` |
| 1.8 | Strong password policy | Account-level setting | `compliance_auditor.check_password_policy` |
| 1.10 | MFA for all IAM users | Role trust policies enforce MFA | `compliance_auditor.check_users_have_mfa`, Config `iam-user-mfa-enabled` |
| 1.14 | Rotate access keys ≤ 90d | Discovery flags stale keys | Config `access-keys-rotated` |
| 1.16 | No full-admin policies attached to users | `iam-policies` least-privilege docs | discovery risk scoring |
| 3.1 | CloudTrail enabled (all regions) | `cloudtrail-audit` multi-region trail | Config `cloudtrail-enabled`, `check_cloudtrail_enabled` |
| 3.2 | Log file validation enabled | `enable_log_file_validation = true` | trail attribute |
| 3.7 | CloudTrail logs encrypted with KMS | `kms_key_id` on trail | Config `cloud-trail-encryption-enabled` |
| 3.8 | KMS key rotation enabled | `enable_key_rotation = true` | Config `cmk-backing-key-rotation-enabled` |
| 4.x | Metric filters + alarms for key events | `monitoring/cloudwatch` filters/alarms | alarm state → SNS |

## PCI-DSS v4.0

| Req. | Control | Implementation |
| ---- | ------- | -------------- |
| 3.4 | Render stored account data unreadable | KMS encryption on secrets, S3, EBS, RDS; Config `encrypted-volumes`, `rds-storage-encrypted` |
| 7.1 | Restrict access by business need-to-know | least-privilege `iam-policies`, time-bound provisioning |
| 8.3 | Strong authentication / MFA | MFA enforced in every privileged role trust policy |
| 8.6 | Manage shared/service credentials | Secrets Manager + automated rotation |
| 10.1 | Audit trails linking access to users | CloudTrail with user identity; session recording |
| 10.2 | Log all individual access to data | CloudTrail data events on S3; `audit_log_analyzer` |
| 10.5 | Protect audit trails from alteration | S3 versioning, KMS, TLS-only bucket policy, log validation |
| 10.7 | Detect and alert on failures | metric filter alarms (`cloudtrail-tamper`) → SNS |

## SOC 2 (Trust Services Criteria)

| TSC | Criterion | Implementation |
| --- | --------- | -------------- |
| CC6.1 | Logical access controls | MFA-gated roles, least-privilege policies |
| CC6.2 | Registration/authorization of access | access provisioner approval workflow (separation of duties: no self-approval) |
| CC6.3 | Role-based access & removal | time-bound grants with automatic expiry sweep |
| CC6.6 | Boundary protection | public-access blocks, TLS enforcement, KMS |
| CC7.1 | Detect configuration changes | AWS Config + EventBridge → SNS |
| CC7.2 | Monitor for anomalies | `audit_log_analyzer` heuristics + CloudWatch alarms |
| CC7.3 | Evaluate security events | weekly `compliance-audit.yml`, auto-filed GitHub issues |

## Continuous verification

- **AWS Config managed rules** (see `compliance-framework`) evaluate resources
  continuously; any `NON_COMPLIANT` transition fires an EventBridge rule → SNS.
- **Weekly audit** (`.github/workflows/compliance-audit.yml`) runs the auditor
  and the CloudTrail anomaly scanner across all environments and opens a GitHub
  issue on high-severity findings.
- **Pre-deploy gates** (`iac-validate.yml`) run `checkov` and `tflint` so
  misconfigurations are caught before apply.

## Evidence collection

| Evidence | Where |
| -------- | ----- |
| Compliance score over time | Grafana `pam-compliance-status` dashboard |
| Audit reports (JSON) | GitHub Actions artifacts `audit-<env>` |
| Access request history | DynamoDB `pam-access-requests` table |
| Session recordings | S3 session bucket + CloudWatch session log group |
| Config rule status | AWS Config console / `config_rule_names` output |

> This mapping is a starting point for an audit, not a certification. Engage
> your assessor to confirm scope and evidence requirements for your environment.
