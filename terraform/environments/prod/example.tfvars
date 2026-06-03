# Copy to terraform.tfvars and adjust per account. terraform.tfvars is gitignored.
aws_region                 = "us-east-1"
environment                = "prod"
owner_tag                  = "security-pam"
trusted_account_ids        = ["111122223333"]
secret_rotation_days       = 14
cloudtrail_retention_days  = 365
session_log_retention_days = 365
alarm_notification_email   = "pam-alerts@example.com"
