# readtheplan summary: benchmarks/plans/10-large-platform-release/plan.json
Terraform version: 1.8.5
Resource changes: 129

## Actions
- create: 62
- delete: 2
- delete/create: 3
- update: 62

## Risk
- dangerous: 4
- irreversible: 2
- review: 61
- safe: 62

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| safe | create | aws_subnet.private[0] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[1] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[2] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[3] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[4] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[5] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[6] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[7] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[8] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[9] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[10] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[11] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[12] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[13] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[14] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[15] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[16] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[17] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[18] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[19] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[0] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[1] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[2] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[3] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[4] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[5] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[6] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[7] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[8] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[9] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[10] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[11] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[12] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[13] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[14] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.private[15] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[0] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[0] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[1] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[1] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[2] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[2] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[3] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[3] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[4] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[4] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[5] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[5] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[6] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[6] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[7] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[7] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[8] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[8] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[9] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[9] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[10] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[10] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group.service[11] | aws_security_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_vpc_security_group_ingress_rule.service[11] | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_iam_role.service[0] | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.service[0] | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_role.service[1] | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.service[1] | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_role.service[2] | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.service[2] | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_role.service[3] | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.service[3] | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_role.service[4] | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.service[4] | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_role.service[5] | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.service[5] | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_role.service[6] | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.service[6] | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_role.service[7] | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.service[7] | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_role.service[8] | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.service[8] | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_role.service[9] | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.service[9] | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| safe | create | aws_lambda_function.worker[0] | aws_lambda_function | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudwatch_log_group.worker[0] | aws_cloudwatch_log_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_lambda_function.worker[1] | aws_lambda_function | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudwatch_log_group.worker[1] | aws_cloudwatch_log_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_lambda_function.worker[2] | aws_lambda_function | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudwatch_log_group.worker[2] | aws_cloudwatch_log_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_lambda_function.worker[3] | aws_lambda_function | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudwatch_log_group.worker[3] | aws_cloudwatch_log_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_lambda_function.worker[4] | aws_lambda_function | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudwatch_log_group.worker[4] | aws_cloudwatch_log_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_lambda_function.worker[5] | aws_lambda_function | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudwatch_log_group.worker[5] | aws_cloudwatch_log_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_lambda_function.worker[6] | aws_lambda_function | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudwatch_log_group.worker[6] | aws_cloudwatch_log_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_lambda_function.worker[7] | aws_lambda_function | Terraform will create a new resource without changing existing state. |
| review | update | aws_cloudwatch_log_group.worker[7] | aws_cloudwatch_log_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_s3_bucket.app[0] | aws_s3_bucket | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket_policy.app[0] | aws_s3_bucket_policy | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket.app[1] | aws_s3_bucket | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket_policy.app[1] | aws_s3_bucket_policy | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket.app[2] | aws_s3_bucket | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket_policy.app[2] | aws_s3_bucket_policy | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket.app[3] | aws_s3_bucket | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket_policy.app[3] | aws_s3_bucket_policy | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket.app[4] | aws_s3_bucket | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket_policy.app[4] | aws_s3_bucket_policy | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket.app[5] | aws_s3_bucket | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_s3_bucket_policy.app[5] | aws_s3_bucket_policy | Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings. |
| review | update | aws_route53_record.service[0] | aws_route53_record | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_kms_key.service[0] | aws_kms_key | Terraform will create a new resource without changing existing state. |
| review | update | aws_route53_record.service[1] | aws_route53_record | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_kms_key.service[1] | aws_kms_key | Terraform will create a new resource without changing existing state. |
| review | update | aws_route53_record.service[2] | aws_route53_record | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_kms_key.service[2] | aws_kms_key | Terraform will create a new resource without changing existing state. |
| review | update | aws_route53_record.service[3] | aws_route53_record | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_kms_key.service[3] | aws_kms_key | Terraform will create a new resource without changing existing state. |
| review | update | aws_eks_cluster.platform | aws_eks_cluster | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| dangerous | delete/create | aws_eks_node_group.workers | aws_eks_node_group | Terraform will replace an EKS node group. Expect pod evictions, capacity churn, and possible cluster disruption during rollout. |
| dangerous | update | aws_db_instance.primary | aws_db_instance | The RDS instance engine_version appears to cross a major version. Major database upgrades can be irreversible or require downtime. |
| dangerous | delete/create | aws_db_instance.analytics | aws_db_instance | Terraform will replace this RDS instance. Confirm snapshots, restore path, endpoint changes, and maintenance-window impact. |
| review | update | aws_rds_cluster.reporting | aws_rds_cluster | Terraform will update this RDS cluster. Check backup state, maintenance windows, and whether the provider will force replacement. |
| irreversible | delete | aws_s3_bucket.legacy_exports | aws_s3_bucket | Terraform will delete an S3 bucket or bucket control resource. Confirm object retention, replication, and recovery requirements. |
| dangerous | delete/create | aws_kms_key.customer_data | aws_kms_key | Terraform will replace a KMS key. Key identity changes can break decrypt access for data and services that depend on the old key. |
| irreversible | delete | aws_route53_zone.legacy | aws_route53_zone | Terraform will delete a Route53 hosted zone. DNS for the zone can go dark, and recreating it may produce different name servers. |
| review | update | aws_cloudtrail.org | aws_cloudtrail | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_ecr_repository.api | aws_ecr_repository | Terraform will create a new resource without changing existing state. |
| safe | create | aws_sqs_queue.jobs | aws_sqs_queue | Terraform will create a new resource without changing existing state. |
| review | update | aws_lb_listener.https | aws_lb_listener | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_autoscaling_group.api | aws_autoscaling_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
