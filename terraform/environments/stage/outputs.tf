output "kms_secrets_key_arn" {
  description = "KMS key ARN protecting Secrets Manager secrets."
  value       = module.kms.secrets_key_arn
}

output "cloudtrail_name" {
  description = "Name of the PAM CloudTrail."
  value       = module.cloudtrail.trail_name
}

output "audit_log_group" {
  description = "CloudWatch Log group receiving the audit trail."
  value       = module.cloudtrail.log_group_name
}

output "privileged_role_arns" {
  description = "ARNs of the provisioned privileged IAM roles."
  value       = module.iam_roles.role_arns
}

output "secrets_prefix" {
  description = "Secrets Manager path prefix for PAM-managed secrets."
  value       = module.secrets.secret_path_prefix
}

output "session_log_bucket" {
  description = "S3 bucket storing SSM session recordings."
  value       = module.ssm_sessions.session_bucket_name
}

output "compliance_topic_arn" {
  description = "SNS topic ARN for compliance and security alerts."
  value       = module.compliance.alerts_topic_arn
}
