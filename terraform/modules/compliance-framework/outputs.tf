output "alerts_topic_arn" {
  description = "SNS topic ARN for compliance and security alerts."
  value       = aws_sns_topic.alerts.arn
}

output "config_rule_names" {
  description = "Names of the managed Config rules provisioned."
  value       = [for r in aws_config_config_rule.managed : r.name]
}

output "config_bucket_name" {
  description = "S3 bucket receiving AWS Config snapshots (empty if recorder disabled)."
  value       = var.enable_config_recorder ? aws_s3_bucket.config[0].id : ""
}
