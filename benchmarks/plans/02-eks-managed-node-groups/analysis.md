# readtheplan summary: benchmarks/plans/02-eks-managed-node-groups/plan.json
Terraform version: 1.8.5
Resource changes: 12

## Actions
- create: 4
- delete/create: 1
- update: 7

## Risk
- dangerous: 1
- review: 7
- safe: 4

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| review | update | aws_eks_cluster.this | aws_eks_cluster | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| dangerous | delete/create | aws_eks_node_group.blue | aws_eks_node_group | Terraform will replace an EKS node group. Expect pod evictions, capacity churn, and possible cluster disruption during rollout. |
| review | update | aws_iam_role.cluster | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| review | update | aws_iam_policy.cluster | aws_iam_policy | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| safe | create | aws_security_group.cluster | aws_security_group | Terraform will create a new resource without changing existing state. |
| safe | create | aws_vpc_security_group_ingress_rule.api | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| safe | create | aws_vpc_security_group_ingress_rule.kubelet | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| review | update | aws_security_group_rule.node_egress | aws_security_group_rule | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_cloudwatch_log_group.cluster | aws_cloudwatch_log_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| safe | create | aws_kms_key.eks | aws_kms_key | Terraform will create a new resource without changing existing state. |
| review | update | aws_kms_alias.eks | aws_kms_alias | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
| review | update | aws_autoscaling_group.workers | aws_autoscaling_group | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying. |
