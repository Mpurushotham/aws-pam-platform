variable "name_prefix" {
  description = "Prefix applied to secret names and the secrets path."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN used to encrypt secret values."
  type        = string
}

variable "rotation_days" {
  description = "Automatic rotation interval in days."
  type        = number
  default     = 30
}

variable "rotation_lambda_arn" {
  description = "ARN of the rotation Lambda. Empty string disables auto-rotation."
  type        = string
  default     = ""
}

variable "recovery_window_days" {
  description = "Days a deleted secret is recoverable before permanent deletion."
  type        = number
  default     = 7
}

variable "managed_secrets" {
  description = "Logical names of secrets to provision (values set out-of-band)."
  type        = list(string)
  default     = ["rds-master", "app-api-key", "service-account"]
}
