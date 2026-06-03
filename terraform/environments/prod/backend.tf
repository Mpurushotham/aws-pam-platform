# Remote state backend for the prod environment.
terraform {
  backend "s3" {
    bucket         = "pam-tfstate-prod"
    key            = "pam/prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "pam-tfstate-lock-prod"
    encrypt        = true
  }
}
