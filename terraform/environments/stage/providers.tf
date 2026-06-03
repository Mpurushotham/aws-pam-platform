terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.47"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "aws-pam-infrastructure"
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = var.owner_tag
      Compliance  = "CIS,PCI-DSS,SOC2"
    }
  }
}
