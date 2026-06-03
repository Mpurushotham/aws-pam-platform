variable "name_prefix" {
  description = "Prefix applied to all resource names."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN used to encrypt session logs at rest and in transit."
  type        = string
}

variable "cloudwatch_log_arn" {
  description = "ARN of the CloudWatch Log group receiving session recordings."
  type        = string
}

variable "cloudwatch_log_name" {
  description = "Name of the CloudWatch Log group for session recordings."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "S3 lifecycle expiration for session recordings."
  type        = number
  default     = 90
}

variable "idle_session_timeout" {
  description = "Minutes of inactivity before a session is terminated."
  type        = number
  default     = 15
}
