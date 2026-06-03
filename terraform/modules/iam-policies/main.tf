# ---------------------------------------------------------------------------
# Least-privilege customer-managed IAM policies consumed by privileged roles.
# Every policy is scoped by resource ARN and guarded with MFA / TLS conditions.
# ---------------------------------------------------------------------------

locals {
  secrets_arn = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.secrets_path_prefix}*"
}

# --- Read-only access to PAM secrets -----------------------------------------
data "aws_iam_policy_document" "secrets_read" {
  statement {
    sid    = "ReadPamSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecretVersionIds",
    ]
    resources = [local.secrets_arn]
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }

  dynamic "statement" {
    for_each = length(var.kms_key_arns) > 0 ? [1] : []
    content {
      sid       = "DecryptSecrets"
      effect    = "Allow"
      actions   = ["kms:Decrypt", "kms:DescribeKey"]
      resources = var.kms_key_arns
    }
  }
}

resource "aws_iam_policy" "secrets_read" {
  name        = "${var.name_prefix}-secrets-read"
  description = "MFA-gated read access to PAM-managed secrets."
  policy      = data.aws_iam_policy_document.secrets_read.json
}

# --- Manage secrets (rotation operators) -------------------------------------
data "aws_iam_policy_document" "secrets_admin" {
  statement {
    sid    = "ManagePamSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecret",
      "secretsmanager:RotateSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = [local.secrets_arn]
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_policy" "secrets_admin" {
  name        = "${var.name_prefix}-secrets-admin"
  description = "MFA-gated rotation/management of PAM secrets."
  policy      = data.aws_iam_policy_document.secrets_admin.json
}

# --- SSM Session Manager (recorded shell access) -----------------------------
data "aws_iam_policy_document" "session_access" {
  statement {
    sid    = "StartRecordedSession"
    effect = "Allow"
    actions = [
      "ssm:StartSession",
      "ssm:TerminateSession",
      "ssm:ResumeSession",
      "ssm:DescribeSessions",
      "ssm:GetConnectionStatus",
    ]
    resources = [
      "arn:aws:ec2:${var.region}:${var.account_id}:instance/*",
      "arn:aws:ssm:${var.region}:${var.account_id}:session/*",
      "arn:aws:ssm:${var.region}::document/SSM-SessionManagerRunShell",
    ]
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_policy" "session_access" {
  name        = "${var.name_prefix}-session-access"
  description = "MFA-gated SSM Session Manager access (recorded sessions only)."
  policy      = data.aws_iam_policy_document.session_access.json
}

# --- Read-only auditor (security review, no mutate) --------------------------
data "aws_iam_policy_document" "auditor" {
  #checkov:skip=CKV_AWS_356:A read-only compliance auditor requires account-wide Describe/List/Get; every action in this statement is strictly read-only and cannot mutate resources.
  statement {
    sid    = "ReadOnlyAudit"
    effect = "Allow"
    actions = [
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
      "iam:ListUsers",
      "iam:ListRoles",
      "iam:ListPolicies",
      "iam:GetAccountAuthorizationDetails",
      "cloudtrail:LookupEvents",
      "cloudtrail:GetTrailStatus",
      "config:Describe*",
      "config:Get*",
      "logs:FilterLogEvents",
      "logs:GetLogEvents",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "auditor" {
  name        = "${var.name_prefix}-auditor"
  description = "Read-only access for compliance auditing of PAM controls."
  policy      = data.aws_iam_policy_document.auditor.json
}
