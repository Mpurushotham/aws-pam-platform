output "role_arns" {
  description = "Map of logical role name -> IAM role ARN."
  value       = { for k, r in aws_iam_role.this : k => r.arn }
}

output "role_names" {
  description = "Map of logical role name -> IAM role name."
  value       = { for k, r in aws_iam_role.this : k => r.name }
}
