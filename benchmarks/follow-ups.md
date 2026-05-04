# Benchmark follow-ups

These are rule and catalog gaps observed while preparing the benchmark fixtures. They are intentionally not fixed in this PR.

| Area | Follow-up | Priority |
| --- | --- | --- |
| `aws_subnet/aws_route_table/aws_nat_gateway` | Network topology resources are treated by action only; consider low-noise review rules for route/NAT replacements. | Later |
| `aws_lambda_function` | Lambda code/config updates are action-only review with no service-specific explanation. | Later |
| `aws_lb/aws_lb_listener` | Load balancer listener and target group changes can affect availability but are not mapped yet. | Later |
| `aws_cloudwatch_metric_alarm/aws_cloudwatch_event_rule` | Monitoring coverage resources lack SOC 2 CC7.x mappings unless they are CloudTrail. | Later |
| `aws_ecr_repository/aws_sqs_queue` | Application platform support services are action-only today. | Later |
