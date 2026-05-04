# readtheplan summary: benchmarks/plans/05-kms-multi-region/plan.json
Terraform version: 1.8.5
Resource changes: 7

## Actions
- create: 3
- delete: 1
- delete/create: 1
- update: 2

## Risk
- dangerous: 1
- irreversible: 1
- review: 2
- safe: 3

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| safe | create | aws_kms_key.primary | aws_kms_key | Terraform will create a new resource without changing existing state. |
| safe | create | aws_kms_alias.primary | aws_kms_alias | Terraform will create a new resource without changing existing state. |
| review | update | aws_kms_key.shared_services | aws_kms_key | Terraform will update a KMS key. Review key policy, rotation, deletion window, and service dependencies. |
| dangerous | delete/create | aws_kms_key.customer_data | aws_kms_key | Terraform will replace a KMS key. Key identity changes can break decrypt access for data and services that depend on the old key. |
| irreversible | delete | aws_kms_key.legacy | aws_kms_key | Terraform will schedule deletion of a KMS key. Once the deletion window completes, data encrypted only by that key cannot be decrypted. |
| safe | create | aws_kms_replica_key.eu | aws_kms_replica_key | Terraform will create a new resource without changing existing state. |
| review | update | aws_iam_policy.kms_access | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
