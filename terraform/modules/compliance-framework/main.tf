# ---------------------------------------------------------------------------
# Continuous compliance: AWS Config recorder + managed rules mapped to
# CIS / PCI-DSS / SOC2 controls, with SNS alerting on non-compliance.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

locals {
  config_bucket = "${var.name_prefix}-config-${data.aws_caller_identity.current.account_id}"

  # Managed Config rules with their primary compliance mappings (see COMPLIANCE.md).
  managed_rules = {
    "iam-user-mfa-enabled"               = "IAM_USER_MFA_ENABLED" # CIS 1.10 / SOC2 CC6.1
    "mfa-enabled-for-iam-console-access" = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
    "iam-password-policy"                = "IAM_PASSWORD_POLICY" # CIS 1.5-1.11
    "access-keys-rotated"                = "ACCESS_KEYS_ROTATED" # CIS 1.14
    "cloudtrail-enabled"                 = "CLOUD_TRAIL_ENABLED" # CIS 3.1 / PCI 10.x
    "cloud-trail-encryption-enabled"     = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
    "cmk-backing-key-rotation-enabled"   = "CMK_BACKING_KEY_ROTATION_ENABLED"
    "s3-bucket-public-read-prohibited"   = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    "s3-bucket-ssl-requests-only"        = "S3_BUCKET_SSL_REQUESTS_ONLY"
    "secretsmanager-rotation-enabled"    = "SECRETSMANAGER_ROTATION_ENABLED_CHECK"
    "encrypted-volumes"                  = "ENCRYPTED_VOLUMES" # PCI 3.4
    "rds-storage-encrypted"              = "RDS_STORAGE_ENCRYPTED"
  }
}

# --- SNS topic for compliance & security alerts ------------------------------
resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-compliance-alerts"
  kms_master_key_id = var.kms_key_arn
  tags              = { Name = "${var.name_prefix}-compliance-alerts" }
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# --- Config delivery bucket --------------------------------------------------
resource "aws_s3_bucket" "config" {
  #checkov:skip=CKV_AWS_145:KMS encryption is set via aws_s3_bucket_server_side_encryption_configuration.config; checkov cannot link count-indexed sub-resources.
  #checkov:skip=CKV2_AWS_6:Public access is blocked via aws_s3_bucket_public_access_block.config; checkov cannot link count-indexed sub-resources.
  #checkov:skip=CKV_AWS_18:Access is captured by CloudTrail S3 data events; a central server-access-log bucket is out of scope.
  #checkov:skip=CKV_AWS_144:Cross-region replication is intentionally out of scope (cost/complexity).
  #checkov:skip=CKV2_AWS_62:Config snapshots are consumed by AWS Config, not S3 event notifications.
  count  = var.enable_config_recorder ? 1 : 0
  bucket = local.config_bucket
  tags   = { Name = local.config_bucket }
}

resource "aws_s3_bucket_versioning" "config" {
  count  = var.enable_config_recorder ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  count  = var.enable_config_recorder ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  rule {
    id     = "expire-config-snapshots"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count                   = var.enable_config_recorder ? 1 : 0
  bucket                  = aws_s3_bucket.config[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count  = var.enable_config_recorder ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  count  = var.enable_config_recorder ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.config[0].arn
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
    ]
  })
}

# --- Config recorder + delivery channel --------------------------------------
resource "aws_iam_role" "config" {
  count = var.enable_config_recorder ? 1 : 0
  name  = "${var.name_prefix}-config-recorder"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_config_recorder ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "this" {
  count    = var.enable_config_recorder ? 1 : 0
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  count          = var.enable_config_recorder ? 1 : 0
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.config[0].id
  depends_on     = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  #checkov:skip=CKV2_AWS_45:The recorder records all supported + global resources (see aws_config_configuration_recorder.this); checkov cannot link count-indexed resources.
  count      = var.enable_config_recorder ? 1 : 0
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

# --- Managed Config rules ----------------------------------------------------
resource "aws_config_config_rule" "managed" {
  for_each = var.enable_config_recorder ? local.managed_rules : {}

  name = "${var.name_prefix}-${each.key}"
  source {
    owner             = "AWS"
    source_identifier = each.value
  }
  depends_on = [aws_config_configuration_recorder.this]
  tags       = { Compliance = "CIS,PCI-DSS,SOC2" }
}

# --- Alert on any rule moving to NON_COMPLIANT -------------------------------
resource "aws_cloudwatch_event_rule" "noncompliance" {
  name        = "${var.name_prefix}-config-noncompliance"
  description = "Fires when a Config rule reports NON_COMPLIANT."
  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.noncompliance.name
  target_id = "sns"
  arn       = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}
