# Deployment Guide

Step-by-step instructions to deploy the AWS PAM platform into an account.

## Prerequisites

| Tool | Version | Notes |
| ---- | ------- | ----- |
| Terraform | >= 1.5 | `terraform version` |
| AWS CLI | v2 | configured credentials with bootstrap rights |
| Python | >= 3.9 | for the operational scripts |
| pre-commit | latest | `make setup` installs it |

You also need permission to create IAM, KMS, S3, CloudTrail, Config, Secrets
Manager, SSM, SNS, and EventBridge resources in the target account.

## 1. Bootstrap remote state (once per account)

Terraform state lives in S3 with a DynamoDB lock table. Create them before the
first `init`:

```bash
ENV=dev
REGION=us-east-1

aws s3api create-bucket --bucket "pam-tfstate-$ENV" --region "$REGION"
aws s3api put-bucket-versioning --bucket "pam-tfstate-$ENV" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket "pam-tfstate-$ENV" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
aws s3api put-public-access-block --bucket "pam-tfstate-$ENV" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws dynamodb create-table --table-name "pam-tfstate-lock-$ENV" \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST --region "$REGION"
```

Repeat for `stage` and `prod` (the backend names already follow this pattern).

## 2. Configure variables

```bash
cd terraform/environments/dev
cp example.tfvars terraform.tfvars
$EDITOR terraform.tfvars   # set trusted_account_ids, alarm email, etc.
```

`terraform.tfvars` is gitignored — never commit account-specific values.

## 3. Plan & apply

```bash
# from the repo root
make tf-init  ENV=dev
make tf-plan  ENV=dev
make tf-apply ENV=dev
```

Confirm the SNS subscription email that arrives after apply, so compliance
alerts can be delivered.

## 4. Configure CI (OIDC, no static keys)

1. Add GitHub as an OIDC provider in IAM
   (`token.actions.githubusercontent.com`).
2. Create one deploy role per environment with a trust policy scoped to your
   repo/branch, plus an audit role and a rotation role.
3. Store the role ARNs as GitHub repository secrets:
   - `AWS_DEPLOY_ROLE_DEV`, `AWS_DEPLOY_ROLE_PROD`
   - `AWS_AUDIT_ROLE`, `AWS_ROTATION_ROLE`
4. Create GitHub Environments `dev`, `stage`, `prod`, `production`,
   `production-plan`. Add **required reviewers** to `production` so prod applies
   pause for approval.

After this, merges to `main` deploy dev automatically; prod is launched via the
**Deploy Prod** workflow (`workflow_dispatch`, confirmation phrase + approval).

## 5. Operational scripts

```bash
make setup   # installs scripts/python/requirements.txt + pre-commit

# Discover privileged accounts
python scripts/python/pam_privileged_account_discovery.py --region us-east-1

# Run a compliance audit (non-zero exit on high-severity failures)
python scripts/python/compliance_auditor.py --frameworks cis,pci-dss,soc2

# Provision time-bound access
python scripts/python/pam_access_provisioner.py request \
  --user alice --role pam-dev-break-glass-admin --hours 2 --reason "incident 4821"
```

The access provisioner expects a DynamoDB table (default `pam-access-requests`)
with primary key `request_id` (String).

## 6. Monitoring

Mount `monitoring/grafana/dashboards/*.json` at
`/var/lib/grafana/dashboards` and the `monitoring/grafana/provisioning/`
tree into the Grafana provisioning directory. The CloudWatch datasource
authenticates via the Grafana host's IAM role. Apply
`monitoring/cloudwatch/metric-filters-and-alarms.tf` (passing the audit log
group name and the compliance SNS topic ARN) to light up real-time alarms.

## Teardown

```bash
make tf-destroy ENV=dev
```

Note: S3 buckets with `Versioning` and CloudTrail logs may require manual
emptying before destroy completes. KMS keys enter a deletion window rather than
deleting immediately.

## Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| `Error acquiring the state lock` | stale DynamoDB lock | `terraform force-unlock <id>` |
| `AccessDenied` on apply | deploy role missing perms | widen the deploy role / boundary |
| CloudTrail validate warning on lifecycle | provider version skew | already mitigated via `filter {}` |
| Rotation Lambda not invoked | `rotation_lambda_arn` empty | package + pass the Lambda ARN |
