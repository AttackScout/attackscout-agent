terraform {
  required_version = ">= 1.5.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.1"
    }
    legacy = "2.0"
    anything = {
      source = "hashicorp/anything"
    }
  }
}

resource "aws_s3_bucket" "site" {
  bucket = "www.example.com"
}
