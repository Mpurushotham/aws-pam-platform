variable "name_prefix" {
  description = "Prefix applied to all role names."
  type        = string
}

variable "account_id" {
  description = "AWS account ID that principals assume roles from."
  type        = string
}

variable "trusted_account_ids" {
  description = "Additional AWS account IDs trusted to assume cross-account roles."
  type        = list(string)
  default     = []
}

variable "policy_arns" {
  description = "Map of logical policy name -> managed policy ARN (from iam-policies)."
  type        = map(string)
}

variable "require_mfa" {
  description = "Enforce MFA in the trust policy of every privileged role."
  type        = bool
  default     = true
}

variable "max_session_duration" {
  description = "Maximum assumed-role session duration in seconds (1h-12h)."
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration >= 3600 && var.max_session_duration <= 43200
    error_message = "max_session_duration must be between 3600 and 43200 seconds."
  }
}
