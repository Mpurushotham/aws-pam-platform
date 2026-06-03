# ---------------------------------------------------------------------------
# CloudWatch metric filters + alarms over the PAM audit log group.
# Apply alongside the cloudtrail-audit module (pass its log group name + the
# compliance SNS topic ARN). Surfaces real-time security signals.
# ---------------------------------------------------------------------------

variable "audit_log_group_name" {
  description = "Name of the CloudTrail audit CloudWatch Log group."
  type        = string
}

variable "alerts_topic_arn" {
  description = "SNS topic ARN to notify on alarm."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for filter/alarm names."
  type        = string
  default     = "pam"
}

locals {
  # filter name => CloudWatch Logs filter pattern
  filters = {
    root-usage           = "{ $.userIdentity.type = \"Root\" && $.eventType != \"AwsServiceEvent\" }"
    console-login-no-mfa = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed = \"No\") && ($.responseElements.ConsoleLogin = \"Success\") }"
    iam-policy-change    = "{ ($.eventName = Put*Policy) || ($.eventName = Attach*Policy) || ($.eventName = Delete*Policy) || ($.eventName = Create*Policy) }"
    cloudtrail-tamper    = "{ ($.eventName = StopLogging) || ($.eventName = DeleteTrail) || ($.eventName = UpdateTrail) }"
    access-denied        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  }
  metric_namespace = "PAM/Audit"
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each       = local.filters
  name           = "${var.name_prefix}-${each.key}"
  log_group_name = var.audit_log_group_name
  pattern        = each.value

  metric_transformation {
    name          = each.key
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each            = local.filters
  alarm_name          = "${var.name_prefix}-${each.key}"
  alarm_description   = "PAM security alarm: ${each.key}"
  namespace           = local.metric_namespace
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.key == "access-denied" ? 5 : 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alerts_topic_arn]
  ok_actions          = [var.alerts_topic_arn]

  tags = { Compliance = "CIS,PCI-DSS,SOC2" }
}
