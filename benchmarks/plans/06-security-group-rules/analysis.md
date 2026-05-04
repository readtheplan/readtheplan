# readtheplan summary: benchmarks/plans/06-security-group-rules/plan.json
Terraform version: 1.8.5
Resource changes: 16

## Actions
- create: 6
- delete: 1
- delete/create: 1
- update: 8

## Risk
- dangerous: 1
- irreversible: 1
- review: 8
- safe: 6

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| safe | create | aws_security_group.web | aws_security_group | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.app | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_security_group.database | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.web_https | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| safe | create | aws_vpc_security_group_ingress_rule.app_http | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_vpc_security_group_ingress_rule.db | aws_vpc_security_group_ingress_rule | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| irreversible | delete | aws_security_group_rule.legacy_ssh | aws_security_group_rule | Terraform will delete this resource. Verify recovery, backups, and external dependencies before applying. |
| safe | create | aws_security_group_rule.egress_all | aws_security_group_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_network_acl.private | aws_network_acl | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_network_acl_rule.private_ephemeral | aws_network_acl_rule | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| dangerous | delete/create | aws_security_group.bastion | aws_security_group | Terraform will replace this resource. Review downtime, identity changes, and any state that must be migrated or restored. |
| review | update | aws_route53_record.internal_app | aws_route53_record | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_iam_role.network_admin | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| safe | create | aws_cloudwatch_log_group.vpc_flow | aws_cloudwatch_log_group | Terraform will create a new resource without changing existing state. |
| safe | create | aws_flow_log.vpc | aws_flow_log | Terraform will create a new resource without changing existing state. |
| review | update | aws_s3_bucket.flow_logs | aws_s3_bucket | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
