# Remote state backend for the stage environment.
terraform {
  backend "s3" {
    bucket         = "pam-tfstate-stage"
    key            = "pam/stage/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "pam-tfstate-lock-stage"
    encrypt        = true
  }
}
