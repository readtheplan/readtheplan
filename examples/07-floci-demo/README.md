# Floci + readtheplan Demo

End-to-end: Floci (local AWS emulator) → Terraform plan → readtheplan analysis.

## Prerequisites

```
docker pull floci/floci:latest
python -m pip install readtheplan
terraform installed
awscli installed
```

## Quick demo (2 minutes)

```bash
# 1. Start Floci
docker run -d --rm -p 4566:4566 -v /var/run/docker.sock:/var/run/docker.sock floci/floci:latest

# 2. Set fake AWS creds
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1

# 3. Run the demo
bash demo-floci.sh
```

## What `demo-floci.sh` does

1. Writes a Terraform config with S3, KMS, DynamoDB, IAM resources
2. `terraform init && terraform apply -auto-approve` against Floci
3. Modifies the config to trigger destructive changes (S3 force_destroy replace, KMS key rotation)
4. `terraform plan -out=tfplan` captures the destructive changes
5. `readtheplan analyze plan.json --framework soc2` → risk report

## Example output

```
Resource changes: 4

Risk:
  review: 1    (KMS key rotation)
  safe: 3      (no-ops, create)

Changes:
  review | update | aws_kms_key.encryption | CC6.1, CC8.1
  safe   | create | aws_s3_bucket.data     | CC8.1
  safe   | no-op  | aws_dynamodb_table     | -
  safe   | no-op  | aws_iam_role           | -
```

## Cleanup

```bash
docker stop floci
terraform destroy -auto-approve
```

## For the in-browser playground

Copy `plan.json` → drag into https://readtheplan.dev/playground/

## Refresh committed playground samples

When `site/playground/floci-demo.tf` changes, regenerate the checked-in sample plans:

```bash
python3 site/scripts/regenerate_floci_samples.py
```

This updates:
- `site/playground/floci-create-plan.json`
- `site/playground/floci-destroy-plan.json`
- `site/playground/floci-samples.meta.json`
