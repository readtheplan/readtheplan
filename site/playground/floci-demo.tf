terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  endpoints {
    s3  = "http://localhost:4566"
    kms = "http://localhost:4566"
    iam = "http://localhost:4566"
    sqs = "http://localhost:4566"
    rds = "http://localhost:4566"
    lambda = "http://localhost:4566"
  }
}

# Safe: create S3 bucket
resource "aws_s3_bucket" "logs" {
  bucket = "floci-demo-logs"
}

# Review: KMS key with rotation
resource "aws_kms_key" "data" {
  description             = "Floci demo encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

# Dangerous: IAM policy with s3:*
resource "aws_iam_policy" "data_access" {
  name        = "floci-demo-data-access"
  description = "Data access policy for Floci demo"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = ["*"]
    }]
  })
}

# Review: SQS queue
resource "aws_sqs_queue" "events" {
  name = "floci-demo-events"
}
