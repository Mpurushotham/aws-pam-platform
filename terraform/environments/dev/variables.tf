variable "aws_region" {
  description = "AWS region for PAM resources."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "stage", "prod"], var.environment)
    error_message = "environment must be one of: dev, stage, prod."
  }
}

variable "owner_tag" {
  description = "Owning team for cost allocation and resource tagging."
  type        = string
  default     = "security-pam"
}

variable "trusted_account_ids" {
  description = "AWS account IDs allowed to assume PAM roles (cross-account)."
  type        = list(string)
  default     = []
}

variable "secret_rotation_days" {
  description = "Automatic secret rotation interval in days."
  type        = number
  default     = 30

  validation {
    condition     = var.secret_rotation_days >= 1 && var.secret_rotation_days <= 365
    error_message = "secret_rotation_days must be between 1 and 365."
  }
}

variable "cloudtrail_retention_days" {
  description = "CloudWatch Logs retention for the audit trail."
  type        = number
  default     = 365
}

variable "session_log_retention_days" {
  description = "Retention period for SSM session recordings (S3 lifecycle)."
  type        = number
  default     = 90
}

variable "alarm_notification_email" {
  description = "Email subscribed to the PAM security SNS topic."
  type        = string
  default     = ""
}
