# readtheplan summary: examples/02-dangerous-replacement/plan.json
Terraform version: 1.8.5
Resource changes: 5

## Actions
- delete/create: 2
- update: 3

## Risk
- dangerous: 2
- review: 3

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| dangerous | delete/create | aws_kms_key.customer_data | aws_kms_key | Terraform will replace a KMS key. Key identity changes can break decrypt access for data and services that depend on the old key. |
| dangerous | delete/create | aws_db_instance.primary | aws_db_instance | Terraform will replace this RDS instance. Confirm snapshots, restore path, endpoint changes, and maintenance-window impact. |
| review | update | aws_iam_role.app | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_security_group.app | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_cloudtrail.org | aws_cloudtrail | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
