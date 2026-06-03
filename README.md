# AWS Privileged Access Management (PAM) Infrastructure

Production-ready, enterprise-grade Privileged Access Management on AWS, delivered
entirely as Infrastructure as Code. The platform manages the full lifecycle of
privileged access — discovery, provisioning, secrets rotation, session recording,
audit logging, and continuous compliance — across `dev`, `stage`, and `prod`.

[![IaC Validate](https://img.shields.io/badge/terraform-validated-7B42BC)](.github/workflows/iac-validate.yml)
[![Compliance](https://img.shields.io/badge/compliance-CIS%20%7C%20PCI--DSS%20%7C%20SOC2-success)](documentation/COMPLIANCE.md)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](scripts/python)

---

## Capabilities

| Domain | What it does |
| ------ | ------------ |
| **IAM least-privilege** | MFA-enforced, time-bound privileged roles with granular policies |
| **Secrets management** | AWS Secrets Manager with automated rotation (default 30 days) |
| **Session recording** | SSM Session Manager streaming to S3 + CloudWatch (no SSH keys) |
| **Audit trail** | CloudTrail → CloudWatch Logs → S3, KMS-encrypted, tamper-evident |
| **Account discovery** | Automated inventory of IAM/EC2/RDS privileged accounts with risk scoring |
| **Access provisioning** | Self-service requests, approval workflow, auto-expiry (DynamoDB-backed) |
| **Compliance** | Continuous CIS / PCI-DSS / SOC2 evaluation with weekly automated audits |

## Repository layout

```
aws-pam-infrastructure/
├── terraform/
│   ├── environments/{dev,stage,prod}/   # per-env composition + backend
│   └── modules/                         # 7 reusable modules
│       ├── iam-roles/  iam-policies/  pam-secrets-manager/
│       ├── ssm-session-manager/  kms-encryption/
│       └── cloudtrail-audit/  compliance-framework/
├── scripts/python/                      # 5 operational scripts + tests
├── .github/workflows/                   # 5 CI/CD pipelines (OIDC, no static keys)
├── ansible/                             # post-provision configuration
├── monitoring/                          # Grafana dashboards + CloudWatch
├── tests/                               # unit / integration / compliance
├── docker/                              # containerized tooling
└── documentation/                       # ARCHITECTURE, DEPLOYMENT, COMPLIANCE
```

## Quick start

```bash
# 0. Prereqs: terraform >= 1.5, python >= 3.9, awscli v2, configured credentials
make setup                      # install python deps + pre-commit hooks

# 1. Bootstrap remote state (one time per account) — see documentation/DEPLOYMENT.md

# 2. Plan & apply the dev environment
make tf-init  ENV=dev
make tf-plan  ENV=dev
make tf-apply ENV=dev

# 3. Run a privileged-account discovery scan
python scripts/python/pam_privileged_account_discovery.py --region us-east-1

# 4. Run a compliance audit
python scripts/python/compliance_auditor.py --frameworks cis,pci-dss,soc2
```

## Security posture

- **Encryption everywhere** — KMS at rest, TLS in transit; no plaintext secrets.
- **No long-lived credentials** — CI authenticates to AWS via GitHub OIDC.
- **MFA required** — every privileged role trust policy enforces `aws:MultiFactorAuthPresent`.
- **Least privilege** — scoped, condition-guarded IAM policies per role.
- **Full audit trail** — 100% of API calls captured and retained.
- **Time-bound access** — provisioned grants auto-expire.

## Development

```bash
make ci          # fmt + validate + tflint + checkov + flake8 + pytest
make tf-fmt      # format terraform
make py-fmt      # black + isort
make test        # pytest with coverage
```

## Documentation

| Doc | Read it when… |
| --- | ------------- |
| [ONBOARDING.md](documentation/ONBOARDING.md) | You just got repo access — start here (repo tour, recipes, guardrails) |
| [DIAGRAMS.md](documentation/DIAGRAMS.md) | You want the picture: system context, module graph, sequence + CI/CD flows (Mermaid) |
| [ARCHITECTURE.md](documentation/ARCHITECTURE.md) | You need the *why* behind a design before changing it |
| [DEPLOYMENT.md](documentation/DEPLOYMENT.md) | You're standing up an environment or troubleshooting an apply |
| [COMPLIANCE.md](documentation/COMPLIANCE.md) | You're mapping controls to CIS / PCI-DSS / SOC 2 for an audit |
| [CONTRIBUTING.md](CONTRIBUTING.md) | You're about to open a PR |

New collaborators: read **ONBOARDING → DIAGRAMS → ARCHITECTURE**, in that order.

## License

Internal / proprietary — adapt the LICENSE file to your organization's policy.
