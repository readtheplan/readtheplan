# readtheplan summary: examples/01-small-create/plan.json
Terraform version: 1.8.5
Resource changes: 3

## Actions
- create: 2
- update: 1

## Risk
- review: 1
- safe: 2

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| safe | create | aws_kms_key.app_config | aws_kms_key | Terraform will create a new resource without changing existing state. |
| review | update | aws_iam_role.deploy | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| safe | create | aws_cloudwatch_log_group.api | aws_cloudwatch_log_group | Terraform will create a new resource without changing existing state. |
