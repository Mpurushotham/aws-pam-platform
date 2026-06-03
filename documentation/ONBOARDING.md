# Onboarding & Repository Guide

Welcome 👋 — you've been granted access to the **AWS PAM Infrastructure** repo.
This page is the map: what everything is, **when** you'd touch it, **how** to
work with it, and **why** it's built this way. Read it top-to-bottom once; after
that it's a reference.

---

## 1. What this repo is (in one paragraph)

It is the **single source of truth** for our Privileged Access Management
platform on AWS. Everything — the cloud resources, the operational tooling, the
CI/CD that ships it, the dashboards, and the compliance evidence — is defined as
code here. Nothing privileged is clicked together by hand in the console; if it
matters, it lives in this repo and goes out through a pull request.

**Why that matters:** PAM is the system that controls who can touch production.
It has to be auditable, reproducible, and reviewable. Code-defining it gives us
a git history of every change, peer review on every change, and the ability to
rebuild the whole thing in a new account from scratch.

---

## 2. First day checklist

```bash
# 1. Clone and enter
git clone <repo-url> && cd aws-pam-infrastructure

# 2. Install tooling (python deps + pre-commit hooks)
make setup

# 3. Prove your machine is healthy — these need no AWS access
make tf-validate ENV=dev
pytest scripts/python/tests tests/compliance -v

# 4. Read these three, in order
#    documentation/ONBOARDING.md   (this file)
#    documentation/DIAGRAMS.md     (the pictures)
#    documentation/ARCHITECTURE.md (the why)
```

If steps 2–3 pass, you have everything you need to make a change. You do **not**
need AWS credentials to develop and test — only to deploy.

---

## 3. The repository, room by room

> **Rule of thumb:** the thing you change depends on *what* you're changing.
> Cloud resources → `terraform/`. Operational behaviour → `scripts/python/`.
> How it ships → `.github/workflows/`. What it looks like → `monitoring/`.

| Path | What lives here | When you touch it | Why it exists |
| ---- | --------------- | ----------------- | ------------- |
| `terraform/modules/` | The 7 reusable building blocks (KMS, IAM, CloudTrail, Secrets, SSM, Config) | Changing *what* AWS resources exist or their settings | Reusable, reviewed infrastructure — one definition, three environments |
| `terraform/environments/{dev,stage,prod}/` | Per-environment composition + state backend | Onboarding an account, changing env-specific values (retention, trusted accounts) | Same blueprint, different knobs — promotes changes dev → stage → prod |
| `scripts/python/` | 5 operational tools + shared `pam_common` | Changing *behaviour*: discovery, rotation, audit, provisioning | Day-2 operations that don't belong in Terraform |
| `scripts/python/tests/` | Unit tests for the tools | Any time you change a script (write the test first) | Fast feedback, no AWS needed |
| `.github/workflows/` | 5 CI/CD pipelines | Changing *how/when* things validate, deploy, audit, rotate | Automation + guardrails; the only path to prod |
| `monitoring/grafana/` | 3 dashboards + provisioning | Adding/altering a visualization | Operational visibility & audit evidence |
| `monitoring/cloudwatch/` | Metric filters + alarms | Adding a real-time security signal | Detect-and-alert on suspicious activity |
| `ansible/` | Post-provision host hardening | Configuring the OS layer on managed instances | Session/audit logging Terraform can't reach |
| `docker/` | Containerized tooling + local Grafana stack | Running tools in a clean, reproducible env | Portability; CI parity |
| `tests/compliance/` | Repo-invariant tests (layout, MFA, no secrets) | Adding a guardrail about the repo itself | Catches drift in conventions before review |
| `tests/integration/` | Opt-in live smoke tests | Validating a real deployment | Confidence the deployed env matches intent |
| `documentation/` | These guides | Anything worth explaining to the next person | Knowledge that outlives any individual |
| `Makefile` | Task shortcuts (`make help`) | Never directly — just use the targets | One memorable interface over many tools |
| `.pre-commit-config.yaml` | Hooks: fmt, lint, secret-scan | Adding a pre-commit check | Stops bad commits at the door |

Top-level dotfiles: `.gitignore` / `.terraformignore` keep state, secrets, and
caches out of git; `example.tfvars` in each env is the template you copy to
`terraform.tfvars` (which is **never** committed).

---

## 4. The five operational scripts — what & when

| Script | Run it when… | Safe to run read-only? |
| ------ | ------------ | ---------------------- |
| `pam_privileged_account_discovery.py` | You need an inventory of privileged IAM/EC2/RDS accounts with risk scores, or to feed CyberArk/BeyondTrust | ✅ read-only |
| `pam_secret_rotation.py` | Rotating a secret on demand, or rolling one back after a bad rotation | ❌ mutates secrets |
| `compliance_auditor.py` | Checking CIS/PCI/SOC2 posture; runs weekly in CI | ✅ read-only |
| `audit_log_analyzer.py` | Hunting suspicious activity in CloudTrail (root use, no-MFA logins, mass deletes) | ✅ read-only |
| `pam_access_provisioner.py` | Granting/approving/expiring time-bound privileged access | ❌ mutates IAM groups |

Every script supports `--help`, structured logging (`PAM_LOG_LEVEL=DEBUG` for
detail), and exits non-zero on failure so CI can gate on them.

See [DIAGRAMS.md](DIAGRAMS.md) §3–4 for the provisioning and rotation flows.

---

## 5. How to make a change (the golden path)

```bash
# 1. Branch off main (never commit to main directly)
git checkout -b feat/short-description

# 2. Make the change in the right room (see §3)

# 3. Run the local gate — mirrors CI
make ci          # fmt + validate + tflint + checkov + flake8 + pytest

# 4. Commit (pre-commit hooks run automatically)
git add -p && git commit -m "feat: explain what and why"

# 5. Push and open a PR
git push -u origin feat/short-description
```

What happens next:

- **`iac-validate.yml`** runs on your PR (no AWS needed) — must be green.
- A teammate reviews. PAM changes always get a second pair of eyes.
- On merge to `main`, **`deploy-dev.yml`** applies to dev automatically.
- Promotion to prod is a **manual, approval-gated** `deploy-prod.yml` run.

### Common recipes

| I want to… | Do this |
| ---------- | ------- |
| Add a new privileged role | Edit `terraform/modules/iam-roles/main.tf` (the `roles` local) + a matching policy in `iam-policies` |
| Add a managed secret | Add its logical name to `managed_secrets` in the env's `module "secrets"` call |
| Add a compliance rule | Add to `managed_rules` in `compliance-framework/main.tf` and document it in `COMPLIANCE.md` |
| Add a detection | Add a metric filter in `monitoring/cloudwatch/` and/or a heuristic in `audit_log_analyzer.py` (+ test) |
| Tune an environment | Edit that env's `terraform.tfvars` — not the module |

---

## 6. Guardrails you should know about

- **No long-lived AWS keys, ever.** Humans use MFA-federated access; CI uses
  GitHub OIDC. If you find yourself wanting to paste an access key, stop and ask.
- **MFA is enforced** in every privileged role's trust policy. Don't remove the
  `aws:MultiFactorAuthPresent` condition — the compliance test will fail anyway.
- **Secrets never enter git or state.** Terraform manages secret *containers*;
  values are injected out-of-band. `.gitignore` + gitleaks + a repo test all
  guard this.
- **`terraform.tfvars` is local-only.** Account-specific values stay on your
  machine / in CI secrets, never committed.
- **Prod requires approval.** The `production` GitHub Environment has required
  reviewers; an apply pauses until a human approves.

---

## 7. Where things live (quick lookup)

| Looking for… | It's here |
| ------------ | --------- |
| Remote state | S3 `pam-tfstate-<env>` + DynamoDB lock `pam-tfstate-lock-<env>` |
| Secrets | AWS Secrets Manager under `pam-<env>/` |
| Audit logs | CloudTrail → S3 `pam-<env>-cloudtrail-*` + CloudWatch `/aws/pam/pam-<env>/cloudtrail` |
| Session recordings | S3 `pam-<env>-session-logs-*` + CloudWatch `/aws/pam/pam-<env>/sessions` |
| Access request history | DynamoDB `pam-access-requests` |
| Compliance reports | GitHub Actions artifacts `audit-<env>`, Grafana `pam-compliance-status` |
| CI role ARNs | GitHub repo secrets (`AWS_DEPLOY_ROLE_*`, `AWS_AUDIT_ROLE`, `AWS_ROTATION_ROLE`) |

---

## 8. Getting unstuck

1. `make help` lists every task target.
2. [DEPLOYMENT.md](DEPLOYMENT.md) has a troubleshooting table (state locks,
   AccessDenied, rotation not firing).
3. [ARCHITECTURE.md](ARCHITECTURE.md) explains *why* a thing is shaped the way
   it is before you change it.
4. Still stuck? Open a draft PR with what you tried and ask in review — a
   half-finished PR is a great question.

> **The one habit that matters most:** when you learn something the docs didn't
> tell you, add it here. This file is only useful because the last person did.
