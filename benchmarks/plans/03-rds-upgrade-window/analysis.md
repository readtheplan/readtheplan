# readtheplan summary: benchmarks/plans/03-rds-upgrade-window/plan.json
Terraform version: 1.8.5
Resource changes: 9

## Actions
- create: 2
- delete: 1
- delete/create: 1
- update: 5

## Risk
- dangerous: 2
- irreversible: 1
- review: 4
- safe: 2

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| dangerous | update | aws_db_instance.primary | aws_db_instance | The RDS instance engine_version appears to cross a major version. Major database upgrades can be irreversible or require downtime. |
| review | update | aws_db_instance.replica | aws_db_instance | Terraform will update this RDS instance. Check backup state, maintenance windows, and whether the provider will force replacement. |
| dangerous | delete/create | aws_db_parameter_group.primary | aws_db_parameter_group | Terraform will replace this resource. Review downtime, identity changes, and any state that must be migrated or restored. |
| review | update | aws_security_group.database | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_security_group_rule.app_to_db | aws_security_group_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_kms_key.database | aws_kms_key | Terraform will update a KMS key. Review key policy, rotation, deletion window, and service dependencies. |
| safe | create | aws_cloudwatch_metric_alarm.cpu | aws_cloudwatch_metric_alarm | Terraform will create a new resource without changing existing state. |
| review | update | aws_iam_role.enhanced_monitoring | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| irreversible | delete | aws_db_snapshot.old_manual | aws_db_snapshot | Terraform will delete this resource. Verify recovery, backups, and external dependencies before applying. |
