# ---------------------------------------------------------------------------
# SSM Session Manager configured for fully recorded, keyless privileged access.
# Every interactive session is streamed to S3 and CloudWatch with KMS
# encryption and TLS enforced end to end.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

locals {
  bucket_name = "${var.name_prefix}-session-logs-${data.aws_caller_identity.current.account_id}"
}

# --- S3 bucket for durable session recordings --------------------------------
resource "aws_s3_bucket" "sessions" {
  bucket = local.bucket_name
  tags   = { Name = local.bucket_name }
}

resource "aws_s3_bucket_versioning" "sessions" {
  bucket = aws_s3_bucket.sessions.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sessions" {
  bucket = aws_s3_bucket.sessions.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "sessions" {
  bucket                  = aws_s3_bucket.sessions.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "sessions" {
  bucket = aws_s3_bucket.sessions.id
  rule {
    id     = "expire-recordings"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_retention_days
    }
  }
}

resource "aws_s3_bucket_policy" "sessions" {
  bucket = aws_s3_bucket.sessions.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.sessions.arn, "${aws_s3_bucket.sessions.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# --- Session Manager preferences document ------------------------------------
# Document type SessionManagerRunShell controls global session behaviour:
# recording targets, encryption, idle timeout, and shell profile.
resource "aws_ssm_document" "session_prefs" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "PAM Session Manager preferences: recorded, encrypted sessions."
    sessionType   = "Standard_Stream"
    inputs = {
      s3BucketName                = aws_s3_bucket.sessions.id
      s3KeyPrefix                 = "sessions/"
      s3EncryptionEnabled         = true
      cloudWatchLogGroupName      = var.cloudwatch_log_name
      cloudWatchEncryptionEnabled = true
      cloudWatchStreamingEnabled  = true
      kmsKeyId                    = var.kms_key_arn
      idleSessionTimeout          = tostring(var.idle_session_timeout)
      runAsEnabled                = false
      shellProfile = {
        linux   = "export PROMPT_COMMAND='history -a'; export HISTTIMEFORMAT='%F %T '"
        windows = ""
      }
    }
  })

  tags = { Name = "${var.name_prefix}-session-prefs" }
}
