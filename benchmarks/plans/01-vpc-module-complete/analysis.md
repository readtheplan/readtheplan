# readtheplan summary: benchmarks/plans/01-vpc-module-complete/plan.json
Terraform version: 1.8.5
Resource changes: 43

## Actions
- create: 43

## Risk
- safe: 43

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| safe | create | aws_vpc.this | aws_vpc | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.public[0] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.public[1] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.public[2] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.public[3] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.public[4] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.public[5] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[0] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[1] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[2] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[3] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[4] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.private[5] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.database[0] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.database[1] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.database[2] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.database[3] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.database[4] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_subnet.database[5] | aws_subnet | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table.public[0] | aws_route_table | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.public[0] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table.public[1] | aws_route_table | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.public[1] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table.public[2] | aws_route_table | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.public[2] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table.public[3] | aws_route_table | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.public[3] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table.public[4] | aws_route_table | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.public[4] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table.public[5] | aws_route_table | Terraform will create a new resource without changing existing state. |
| safe | create | aws_route_table_association.public[5] | aws_route_table_association | Terraform will create a new resource without changing existing state. |
| safe | create | aws_eip.nat[0] | aws_eip | Terraform will create a new resource without changing existing state. |
| safe | create | aws_nat_gateway.this[0] | aws_nat_gateway | Terraform will create a new resource without changing existing state. |
| safe | create | aws_eip.nat[1] | aws_eip | Terraform will create a new resource without changing existing state. |
| safe | create | aws_nat_gateway.this[1] | aws_nat_gateway | Terraform will create a new resource without changing existing state. |
| safe | create | aws_eip.nat[2] | aws_eip | Terraform will create a new resource without changing existing state. |
| safe | create | aws_nat_gateway.this[2] | aws_nat_gateway | Terraform will create a new resource without changing existing state. |
| safe | create | aws_internet_gateway.this | aws_internet_gateway | Terraform will create a new resource without changing existing state. |
| safe | create | aws_security_group.default | aws_security_group | Terraform will create a new resource without changing existing state. |
| safe | create | aws_vpc_security_group_ingress_rule.https | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| safe | create | aws_vpc_security_group_ingress_rule.internal | aws_vpc_security_group_ingress_rule | Terraform will create a new resource without changing existing state. |
| safe | create | aws_security_group_rule.egress_all | aws_security_group_rule | Terraform will create a new resource without changing existing state. |
| safe | create | aws_cloudwatch_log_group.flow_logs | aws_cloudwatch_log_group | Terraform will create a new resource without changing existing state. |
