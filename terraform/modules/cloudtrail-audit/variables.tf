variable "name_prefix" {
  description = "Prefix applied to all resource names."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN used to encrypt CloudTrail and CloudWatch Logs."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period for the audit trail."
  type        = number
  default     = 365
}

variable "is_multi_region" {
  description = "Whether the trail captures events across all regions."
  type        = bool
  default     = true
}

variable "enable_log_file_validation" {
  description = "Enable CloudTrail log file integrity validation (digest files)."
  type        = bool
  default     = true
}
