# ---------------------------------------------------------------------------
# Privileged IAM roles. Every trust policy enforces MFA and (where relevant)
# cross-account boundaries. Roles map to least-privilege managed policies.
# ---------------------------------------------------------------------------

locals {
  # Role catalogue: logical name -> policies to attach.
  roles = {
    "break-glass-admin"  = ["secrets_admin", "session_access"]
    "secrets-operator"   = ["secrets_admin"]
    "session-operator"   = ["session_access"]
    "secrets-reader"     = ["secrets_read"]
    "compliance-auditor" = ["auditor"]
  }

  trusted_principals = concat(
    ["arn:aws:iam::${var.account_id}:root"],
    [for acct in var.trusted_account_ids : "arn:aws:iam::${acct}:root"],
  )
}

data "aws_iam_policy_document" "assume" {
  statement {
    sid     = "AssumeWithMFA"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = local.trusted_principals
    }

    dynamic "condition" {
      for_each = var.require_mfa ? [1] : []
      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }

    # Reject sessions older than 1 hour even if MFA was presented.
    condition {
      test     = "NumericLessThan"
      variable = "aws:MultiFactorAuthAge"
      values   = ["3600"]
    }
  }
}

resource "aws_iam_role" "this" {
  for_each = local.roles

  name                 = "${var.name_prefix}-${each.key}"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  max_session_duration = var.max_session_duration

  tags = {
    Name     = "${var.name_prefix}-${each.key}"
    RoleType = each.key
  }
}

# Flatten (role, policy) pairs for attachment.
locals {
  attachments = merge([
    for role_name, policy_keys in local.roles : {
      for policy_key in policy_keys :
      "${role_name}:${policy_key}" => {
        role   = role_name
        policy = policy_key
      }
    }
  ]...)
}

resource "aws_iam_role_policy_attachment" "this" {
  for_each   = local.attachments
  role       = aws_iam_role.this[each.value.role].name
  policy_arn = var.policy_arns[each.value.policy]
}
