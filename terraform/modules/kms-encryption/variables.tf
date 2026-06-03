variable "name_prefix" {
  description = "Prefix applied to all resource names and aliases."
  type        = string
}

variable "key_deletion_window_days" {
  description = "Waiting period before a scheduled key deletion completes."
  type        = number
  default     = 30

  validation {
    condition     = var.key_deletion_window_days >= 7 && var.key_deletion_window_days <= 30
    error_message = "key_deletion_window_days must be between 7 and 30."
  }
}

variable "enable_key_rotation" {
  description = "Enable annual automatic rotation of the KMS key material."
  type        = bool
  default     = true
}
