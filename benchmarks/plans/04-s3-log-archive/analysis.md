# readtheplan summary: benchmarks/plans/04-s3-log-archive/plan.json
Terraform version: 1.8.5
Resource changes: 12

## Actions
- create: 6
- update: 6

## Risk
- review: 6
- safe: 6

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| safe | create | aws_s3_bucket.logs | aws_s3_bucket | Terraform will create S3 bucket infrastructure. Confirm public access blocks and data classification before storing sensitive data. |
| review | update | aws_s3_bucket.audit | aws_s3_bucket | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket_policy.audit | aws_s3_bucket_policy | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket_public_access_block.audit | aws_s3_bucket_public_access_block | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_s3_bucket_lifecycle_configuration.audit | aws_s3_bucket_lifecycle_configuration | Terraform will create a new resource without changing existing state. |
| safe | create | aws_s3_bucket_server_side_encryption_configuration.audit | aws_s3_bucket_server_side_encryption_configuration | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudtrail.org | aws_cloudtrail | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_kms_key.logs | aws_kms_key | Terraform will create a new resource without changing existing state. |
| review | update | aws_iam_policy.log_delivery | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| safe | create | aws_cloudwatch_log_group.cloudtrail | aws_cloudwatch_log_group | Terraform will create a new resource without changing existing state. |
| safe | create | aws_sns_topic.alerts | aws_sns_topic | Terraform will create a new resource without changing existing state. |
| review | update | aws_s3_bucket_notification.audit | aws_s3_bucket_notification | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
