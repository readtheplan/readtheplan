# readtheplan summary: benchmarks/plans/08-route53-cutover/plan.json
Terraform version: 1.8.5
Resource changes: 8

## Actions
- create: 1
- delete: 1
- delete/create: 1
- update: 5

## Risk
- dangerous: 1
- irreversible: 1
- review: 5
- safe: 1

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| review | update | aws_route53_record.api | aws_route53_record | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_route53_record.app | aws_route53_record | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| dangerous | delete/create | aws_route53_record.blue_green | aws_route53_record | Terraform will replace this resource. Review downtime, identity changes, and any state that must be migrated or restored. |
| irreversible | delete | aws_route53_zone.legacy | aws_route53_zone | Terraform will delete a Route53 hosted zone. DNS for the zone can go dark, and recreating it may produce different name servers. |
| safe | create | aws_route53_record.health_check | aws_route53_record | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudwatch_metric_alarm.dns_health | aws_cloudwatch_metric_alarm | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_security_group.edge | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_iam_role.dns_deploy | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
