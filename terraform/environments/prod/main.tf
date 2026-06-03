# ---------------------------------------------------------------------------
# Dev environment composition.
# Wires together the seven reusable PAM modules. Each environment (dev/stage/
# prod) is an identical composition with environment-specific variable values.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = "pam-${var.environment}"
  account_id  = data.aws_caller_identity.current.account_id
}

# --- KMS: encryption keys consumed by every other module ---------------------
module "kms" {
  source      = "../../modules/kms-encryption"
  name_prefix = local.name_prefix
  environment = var.environment
}

# --- CloudTrail + CloudWatch Logs audit trail --------------------------------
module "cloudtrail" {
  source             = "../../modules/cloudtrail-audit"
  name_prefix        = local.name_prefix
  environment        = var.environment
  kms_key_arn        = module.kms.cloudtrail_key_arn
  log_retention_days = var.cloudtrail_retention_days
}

# --- IAM policies (least-privilege documents) --------------------------------
module "iam_policies" {
  source      = "../../modules/iam-policies"
  name_prefix = local.name_prefix
  account_id  = local.account_id
  region      = data.aws_region.current.name
  kms_key_arns = [
    module.kms.secrets_key_arn,
    module.kms.cloudtrail_key_arn,
  ]
}

# --- IAM roles (MFA-enforced, assumable privileged roles) --------------------
module "iam_roles" {
  source              = "../../modules/iam-roles"
  name_prefix         = local.name_prefix
  account_id          = local.account_id
  trusted_account_ids = var.trusted_account_ids
  policy_arns         = module.iam_policies.policy_arns
  require_mfa         = true
}

# --- Secrets Manager + automated rotation ------------------------------------
module "secrets" {
  source              = "../../modules/pam-secrets-manager"
  name_prefix         = local.name_prefix
  kms_key_arn         = module.kms.secrets_key_arn
  rotation_days       = var.secret_rotation_days
  rotation_lambda_arn = "" # supplied after Lambda packaging; empty = manual
}

# --- SSM Session Manager (recorded privileged sessions) ----------------------
module "ssm_sessions" {
  source              = "../../modules/ssm-session-manager"
  name_prefix         = local.name_prefix
  kms_key_arn         = module.kms.secrets_key_arn
  cloudwatch_log_arn  = module.cloudtrail.session_log_group_arn
  cloudwatch_log_name = module.cloudtrail.session_log_group_name
  log_retention_days  = var.session_log_retention_days
}

# --- Compliance framework (CIS/PCI-DSS/SOC2 Config rules) ---------------------
module "compliance" {
  source             = "../../modules/compliance-framework"
  name_prefix        = local.name_prefix
  environment        = var.environment
  notification_email = var.alarm_notification_email
  kms_key_arn        = module.kms.secrets_key_arn
}
