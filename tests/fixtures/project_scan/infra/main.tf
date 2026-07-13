terraform {
  required_version = ">= 1.6"
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "logs" {
  bucket = "example-production-logs"
}
