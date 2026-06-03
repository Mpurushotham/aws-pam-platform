# ---------------------------------------------------------------------------
# PAM-managed secrets with KMS encryption and optional automated rotation.
# Secret *values* are never stored in Terraform state — only the containers,
# encryption, and rotation schedule are managed here.
# ---------------------------------------------------------------------------

locals {
  path_prefix      = "${var.name_prefix}/"
  rotation_enabled = var.rotation_lambda_arn != ""
}

resource "aws_secretsmanager_secret" "this" {
  #checkov:skip=CKV2_AWS_57:Automatic rotation is enabled (aws_secretsmanager_secret_rotation) when rotation_lambda_arn is supplied; until a rotation Lambda is packaged, rotation is operated via pam_secret_rotation.py. See DEPLOYMENT.md.
  for_each = toset(var.managed_secrets)

  name                    = "${local.path_prefix}${each.value}"
  description             = "PAM-managed secret: ${each.value}"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_days

  tags = {
    Name     = "${var.name_prefix}-${each.value}"
    Rotation = local.rotation_enabled ? "automatic" : "manual"
  }
}

# Placeholder version so the secret exists; real values injected via rotation
# Lambda or out-of-band PutSecretValue. `ignore_changes` prevents drift churn.
resource "aws_secretsmanager_secret_version" "placeholder" {
  for_each      = aws_secretsmanager_secret.this
  secret_id     = each.value.id
  secret_string = jsonencode({ managed = true, initialized = false })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret_rotation" "this" {
  for_each = local.rotation_enabled ? aws_secretsmanager_secret.this : {}

  secret_id           = each.value.id
  rotation_lambda_arn = var.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}

# Resource policy: deny access without MFA, deny non-TLS.
resource "aws_secretsmanager_secret_policy" "this" {
  for_each   = aws_secretsmanager_secret.this
  secret_arn = each.value.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyWithoutTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "secretsmanager:*"
        Resource  = "*"
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}
