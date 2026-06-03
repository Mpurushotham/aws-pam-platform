variable "name_prefix" {
  description = "Prefix applied to all resource names."
  type        = string
}

variable "notification_email" {
  description = "Email subscribed to compliance/security alerts. Empty = no subscription."
  type        = string
  default     = ""
}

variable "kms_key_arn" {
  description = "KMS key ARN used to encrypt the SNS topic and Config bucket."
  type        = string
}

variable "enable_config_recorder" {
  description = "Provision an AWS Config recorder. Disable if Config is org-managed."
  type        = bool
  default     = true
}
