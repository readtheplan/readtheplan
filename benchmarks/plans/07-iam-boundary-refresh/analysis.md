# readtheplan summary: benchmarks/plans/07-iam-boundary-refresh/plan.json
Terraform version: 1.8.5
Resource changes: 11

## Actions
- create: 4
- delete: 1
- update: 6

## Risk
- irreversible: 1
- review: 6
- safe: 4

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| safe | create | aws_iam_role.app | aws_iam_role | Terraform will create a new resource without changing existing state. |
| review | update | aws_iam_role.deploy | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.deploy | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_role_policy.inline | aws_iam_role_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| irreversible | delete | aws_iam_user.legacy_bot | aws_iam_user | Terraform will delete this resource. Verify recovery, backups, and external dependencies before applying. |
| safe | create | aws_iam_policy.permissions_boundary | aws_iam_policy | Terraform will create a new resource without changing existing state. |
| review | update | aws_iam_instance_profile.worker | aws_iam_instance_profile | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_kms_key.identity_exports | aws_kms_key | Terraform will create a new resource without changing existing state. |
| review | update | aws_s3_bucket_policy.identity_exports | aws_s3_bucket_policy | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| safe | create | aws_cloudtrail.identity | aws_cloudtrail | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.admin_vpn | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
