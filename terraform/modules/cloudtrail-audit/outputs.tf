output "trail_name" {
  description = "Name of the CloudTrail."
  value       = aws_cloudtrail.main.name
}

output "trail_arn" {
  description = "ARN of the CloudTrail."
  value       = aws_cloudtrail.main.arn
}

output "bucket_name" {
  description = "S3 bucket storing raw trail logs."
  value       = aws_s3_bucket.trail.id
}

output "log_group_name" {
  description = "CloudWatch Log group receiving the audit trail."
  value       = aws_cloudwatch_log_group.trail.name
}

output "log_group_arn" {
  description = "ARN of the audit trail CloudWatch Log group."
  value       = aws_cloudwatch_log_group.trail.arn
}

output "session_log_group_arn" {
  description = "ARN of the SSM session recording log group."
  value       = aws_cloudwatch_log_group.sessions.arn
}

output "session_log_group_name" {
  description = "Name of the SSM session recording log group."
  value       = aws_cloudwatch_log_group.sessions.name
}
