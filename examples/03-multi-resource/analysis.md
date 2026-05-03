# readtheplan summary: examples/03-multi-resource/plan.json
Terraform version: 1.8.5
Resource changes: 12

## Actions
- create: 2
- delete/create: 1
- update: 9

## Risk
- dangerous: 2
- review: 8
- safe: 2

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| review | update | aws_eks_cluster.platform | aws_eks_cluster | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| dangerous | delete/create | aws_eks_node_group.workers | aws_eks_node_group | Terraform will replace an EKS node group. Expect pod evictions, capacity churn, and possible cluster disruption during rollout. |
| dangerous | update | aws_db_instance.analytics | aws_db_instance | The RDS instance engine_version appears to cross a major version. Major database upgrades can be irreversible or require downtime. |
| review | update | aws_rds_cluster.reporting | aws_rds_cluster | Terraform will update this RDS cluster. Check backup state, maintenance windows, and whether the provider will force replacement. |
| review | update | aws_s3_bucket.audit_logs | aws_s3_bucket | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket_public_access_block.audit_logs | aws_s3_bucket_public_access_block | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_iam_policy.readonly | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| safe | create | aws_iam_role.worker | aws_iam_role | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.cluster | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.api | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudtrail.org | aws_cloudtrail | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_route53_record.app | aws_route53_record | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
