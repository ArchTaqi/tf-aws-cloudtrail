# Terraform setup
terraform {
  required_version = "~> 1.6"
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "eu-west-1"

  default_tags {
    tags = {
      Environment = terraform.workspace,
      ManagedBy   = "Terraform"
    }
  }
}
