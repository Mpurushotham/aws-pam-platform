output "secret_path_prefix" {
  description = "Secrets Manager path prefix for PAM-managed secrets."
  value       = local.path_prefix
}

output "secret_arns" {
  description = "Map of logical secret name -> secret ARN."
  value       = { for k, s in aws_secretsmanager_secret.this : k => s.arn }
}

output "rotation_enabled" {
  description = "Whether automatic rotation is configured."
  value       = local.rotation_enabled
}
