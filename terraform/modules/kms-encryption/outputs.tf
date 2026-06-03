output "secrets_key_arn" {
  description = "ARN of the KMS key protecting secrets, session logs, and S3."
  value       = aws_kms_key.secrets.arn
}

output "secrets_key_id" {
  description = "Key ID of the secrets KMS key."
  value       = aws_kms_key.secrets.key_id
}

output "cloudtrail_key_arn" {
  description = "ARN of the KMS key protecting CloudTrail/CloudWatch audit data."
  value       = aws_kms_key.cloudtrail.arn
}

output "secrets_key_alias" {
  description = "Alias of the secrets KMS key."
  value       = aws_kms_alias.secrets.name
}
