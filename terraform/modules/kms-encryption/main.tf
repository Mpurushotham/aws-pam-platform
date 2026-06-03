# ---------------------------------------------------------------------------
# Customer-managed KMS keys for PAM data-at-rest encryption.
# Separate keys per data domain (secrets vs. audit) to enforce blast-radius
# isolation and distinct key policies.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

locals {
  account_root = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
}

# --- Secrets key: Secrets Manager, SSM session logs, S3 ----------------------
resource "aws_kms_key" "secrets" {
  description             = "${var.name_prefix} PAM secrets encryption key"
  deletion_window_in_days = var.key_deletion_window_days
  enable_key_rotation     = var.enable_key_rotation
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowServiceUse"
        Effect    = "Allow"
        Principal = { Service = ["secretsmanager.amazonaws.com", "s3.amazonaws.com", "logs.amazonaws.com"] }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
    ]
  })

  tags = { Name = "${var.name_prefix}-secrets-key" }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.name_prefix}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# --- CloudTrail key: audit log encryption ------------------------------------
resource "aws_kms_key" "cloudtrail" {
  description             = "${var.name_prefix} PAM CloudTrail audit encryption key"
  deletion_window_in_days = var.key_deletion_window_days
  enable_key_rotation     = var.enable_key_rotation

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.amazonaws.com" }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ]
        Resource = "*"
      },
    ]
  })

  tags = { Name = "${var.name_prefix}-cloudtrail-key" }
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.name_prefix}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}
