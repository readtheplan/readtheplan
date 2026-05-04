# readtheplan summary: benchmarks/plans/09-cloudtrail-org-trail/plan.json
Terraform version: 1.8.5
Resource changes: 10

## Actions
- create: 5
- update: 5

## Risk
- review: 5
- safe: 5

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| safe | create | aws_cloudtrail.org | aws_cloudtrail | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudtrail.member | aws_cloudtrail | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_s3_bucket.cloudtrail | aws_s3_bucket | Terraform will create S3 bucket infrastructure. Confirm public access blocks and data classification before storing sensitive data. |
| review | update | aws_s3_bucket_policy.cloudtrail | aws_s3_bucket_policy | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket_public_access_block.cloudtrail | aws_s3_bucket_public_access_block | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_kms_key.cloudtrail | aws_kms_key | Terraform will create a new resource without changing existing state. |
| review | update | aws_iam_role.cloudtrail | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| safe | create | aws_cloudwatch_log_group.cloudtrail | aws_cloudwatch_log_group | Terraform will create a new resource without changing existing state. |
| safe | create | aws_cloudwatch_metric_alarm.root_login | aws_cloudwatch_metric_alarm | Terraform will create a new resource without changing existing state. |
| review | update | aws_sns_topic.security_alerts | aws_sns_topic | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
