output "policy_arns" {
  description = "Map of logical policy name to its managed policy ARN."
  value = {
    secrets_read   = aws_iam_policy.secrets_read.arn
    secrets_admin  = aws_iam_policy.secrets_admin.arn
    session_access = aws_iam_policy.session_access.arn
    auditor        = aws_iam_policy.auditor.arn
  }
}
