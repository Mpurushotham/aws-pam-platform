output "session_bucket_name" {
  description = "S3 bucket storing SSM session recordings."
  value       = aws_s3_bucket.sessions.id
}

output "session_bucket_arn" {
  description = "ARN of the session recordings bucket."
  value       = aws_s3_bucket.sessions.arn
}

output "session_document_name" {
  description = "Name of the Session Manager preferences document."
  value       = aws_ssm_document.session_prefs.name
}
