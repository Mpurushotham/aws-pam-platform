variable "name_prefix" {
  description = "Prefix applied to all policy names."
  type        = string
}

variable "account_id" {
  description = "AWS account ID hosting the PAM resources."
  type        = string
}

variable "region" {
  description = "AWS region for ARN scoping."
  type        = string
}

variable "kms_key_arns" {
  description = "KMS key ARNs that privileged roles may use for decrypt."
  type        = list(string)
  default     = []
}

variable "secrets_path_prefix" {
  description = "Secrets Manager path prefix that policies are scoped to."
  type        = string
  default     = "pam/"
}
