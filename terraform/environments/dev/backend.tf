# Remote state backend: S3 for state storage, DynamoDB for state locking.
# Bootstrap the bucket and lock table once before `terraform init` (see
# documentation/DEPLOYMENT.md). State is encrypted at rest with SSE-KMS.
terraform {
  backend "s3" {
    bucket         = "pam-tfstate-dev"
    key            = "pam/dev/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "pam-tfstate-lock-dev"
    encrypt        = true
    # kms_key_id is supplied via `terraform init -backend-config=...` in CI
  }
}
