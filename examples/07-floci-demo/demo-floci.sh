#!/usr/bin/env bash
# demo-floci.sh — Floci + Terraform + readtheplan end-to-end demo
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PLAN_JSON="$DIR/plan.json"

export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
ENDPOINT="${FLOCI_ENDPOINT:-http://localhost:4566}"

echo "=== Floci + readtheplan Demo ==="
echo ""

# Step 1: Write Terraform config
cat > "$DIR/main.tf" << 'TFEOF'
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
    s3         = "http://localhost:4566"
    dynamodb   = "http://localhost:4566"
    iam        = "http://localhost:4566"
    kms        = "http://localhost:4566"
    lambda     = "http://localhost:4566"
    sts        = "http://localhost:4566"
  }
}

# Initial resources
resource "aws_s3_bucket" "data" {
  bucket        = "floci-demo-bucket"
  force_destroy = true
}

resource "aws_kms_key" "encryption" {
  description         = "KMS key for S3 encryption"
  enable_key_rotation = false
}

resource "aws_dynamodb_table" "items" {
  name           = "floci-demo-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_iam_role" "lambda_exec" {
  name = "floci-demo-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}
TFEOF

echo "1. Applying initial infrastructure..."
cd "$DIR"
terraform init -input=false > /dev/null 2>&1
terraform apply -auto-approve -input=false > /dev/null 2>&1
echo "   ✓ 4 resources created"

# Step 2: Make destructive changes
echo "2. Making destructive changes..."
sed -i 's/floci-demo-bucket/floci-demo-bucket-v2/' "$DIR/main.tf"
sed -i 's/enable_key_rotation = false/enable_key_rotation = true/' "$DIR/main.tf"
echo "   ✓ S3 bucket renamed (force replace) + KMS key rotation enabled"

# Step 3: Plan the destructive changes
echo "3. Generating Terraform plan..."
terraform plan -out=tfplan -input=false > /dev/null 2>&1
terraform show -json tfplan > "$PLAN_JSON"
echo "   ✓ Plan saved ($(wc -c < "$PLAN_JSON") bytes)"

# Step 4: Analyze with readtheplan
echo ""
echo "4. readtheplan analysis:"
echo "========================================"
readtheplan analyze "$PLAN_JSON" --framework soc2
echo "========================================"

# Cleanup
echo ""
echo "5. Cleaning up..."
terraform destroy -auto-approve -input=false > /dev/null 2>&1
rm -f "$DIR/main.tf" "$DIR/tfplan" "$DIR/terraform.tfstate"* 2>/dev/null
echo "   ✓ Done"

echo ""
echo "Try the plan yourself:"
echo "  readtheplan analyze $PLAN_JSON --framework soc2"
echo "Or drag it into: https://readtheplan.dev/playground/"
