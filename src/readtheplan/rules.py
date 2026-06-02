from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


RISK_ORDER = {
    "safe": 0,
    "review": 1,
    "dangerous": 2,
    "irreversible": 3,
}


@dataclass(frozen=True)
class RuleResult:
    risk: str
    explanation: str


def action_explanation(actions: tuple[str, ...], *, tool_name: str = "Terraform") -> str:
    if not actions:
        return f"{tool_name} action metadata is missing or unknown; human review is required."
    action_set = set(actions)
    if "delete" in action_set and "create" in action_set:
        return (
            f"{tool_name} will replace this resource. Review downtime, identity "
            "changes, and any state that must be migrated or restored."
        )
    if "delete" in action_set:
        return (
            f"{tool_name} will delete this resource. Verify recovery, backups, and "
            "external dependencies before applying."
        )
    if "update" in action_set:
        return (
            f"{tool_name} will update this resource in place. Review the changed "
            "attributes and rollout timing before applying."
        )
    if action_set <= {"no-op", "read"}:
        return f"{tool_name} is only reading or refreshing this resource."
    if "create" in action_set and action_set <= {"create", "no-op", "read", "update"}:
        return f"{tool_name} will create a new resource without changing existing state."
    return f"{tool_name} action metadata is missing or unknown; human review is required."


def apply_resource_rules(
    *,
    resource_type: str,
    actions: tuple[str, ...],
    change: dict[str, Any],
    baseline: RuleResult,
    tool_name: str = "Terraform",
) -> RuleResult:
    result = baseline
    for candidate in _rule_candidates(resource_type, actions, change):
        result = _max_result(result, candidate)
    # Post-process: replace __TOOL__ sentinel with the actual tool name.
    # This avoids blind string-replace of "Terraform" which could
    # mangle compound names like "Terraform Cloud".
    if result is not baseline:
        result = RuleResult(
            risk=result.risk,
            explanation=result.explanation.replace("__TOOL__", tool_name),
        )
    return result


def _rule_candidates(
    resource_type: str,
    actions: tuple[str, ...],
    change: dict[str, Any],
) -> list[RuleResult]:
    action_set = set(actions)

    if resource_type in {"aws_db_instance", "aws_rds_cluster"}:
        return _rds_candidates(resource_type, action_set, change)
    if resource_type in {"aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_bucket_policy"}:
        return _s3_candidates(resource_type, action_set, change)
    if resource_type == "aws_kms_key":
        return _kms_candidates(action_set)
    if resource_type in {"aws_iam_role", "aws_iam_policy", "aws_iam_role_policy"}:
        return _iam_candidates(resource_type, action_set, change)
    if resource_type == "aws_route53_zone":
        return _route53_candidates(action_set)
    if resource_type == "aws_eks_node_group":
        return _eks_node_group_candidates(action_set)
    if resource_type == "aws_ecs_service":
        return _ecs_service_candidates(action_set, change)
    if resource_type in {
        "aws_lb",
        "aws_lb_listener",
        "aws_lb_listener_rule",
        "aws_lb_target_group",
        "aws_lb_target_group_attachment",
    }:
        return _lb_candidates(resource_type, action_set, change)
    if resource_type in {
        "aws_lambda_function",
        "aws_lambda_alias",
        "aws_lambda_event_source_mapping",
    }:
        return _lambda_candidates(resource_type, action_set, change)
    if resource_type in {
        "aws_ecr_repository",
        "aws_ecr_repository_policy",
        "aws_ecr_lifecycle_policy",
        "aws_sqs_queue",
        "aws_sqs_queue_policy",
        "aws_glue_catalog_database",
        "aws_glue_catalog_table",
        "aws_glue_job",
    }:
        return _platform_service_candidates(resource_type, action_set, change)
    if resource_type in {
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
        "aws_vpc_security_group_egress_rule",
    }:
        return _security_group_candidates(resource_type, action_set, change)
    if resource_type in {
        "aws_subnet",
        "aws_route_table",
        "aws_route",
        "aws_route_table_association",
        "aws_nat_gateway",
        "aws_internet_gateway",
    }:
        return _network_topology_candidates(resource_type, action_set, change)
    if resource_type in {
        "aws_cloudwatch_metric_alarm",
        "aws_cloudwatch_event_rule",
        "aws_cloudwatch_event_target",
        "aws_cloudwatch_log_group",
    }:
        return _observability_candidates(resource_type, action_set, change)
    return []


def _rds_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = "RDS cluster" if resource_type == "aws_rds_cluster" else "RDS instance"
    candidates: list[RuleResult] = []
    if "create" in action_set and "delete" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    f"__TOOL__ will replace this {label}. Confirm snapshots, "
                    "restore path, endpoint changes, and maintenance-window impact."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    f"__TOOL__ will delete this {label}. Without a verified final "
                    "snapshot or restore plan, database data may be lost."
                ),
            )
        )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    f"__TOOL__ will update this {label}. Check backup state, "
                    "maintenance windows, and whether the provider will force replacement."
                ),
            )
        )

    if _major_version_changed(change, "engine_version"):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    f"The {label} engine_version appears to cross a major version. "
                    "Major database upgrades can be irreversible or require downtime."
                ),
            )
        )
    return candidates


def _s3_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []
    force_destroy = bool(_before_value(change, "force_destroy"))

    if "delete" in action_set:
        if force_destroy:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "__TOOL__ will delete an S3 bucket with force_destroy enabled. "
                        "Objects can be removed along with the bucket, making recovery unlikely."
                    ),
                )
            )
        else:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "__TOOL__ will delete an S3 bucket or bucket control resource. "
                        "Confirm object retention, replication, and recovery requirements."
                    ),
                )
            )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "__TOOL__ will update S3 bucket controls. Review public access, "
                    "retention, encryption, and data exposure settings."
                ),
            )
        )
    elif "create" in action_set:
        candidates.append(
            RuleResult(
                "safe",
                (
                    "__TOOL__ will create S3 bucket infrastructure. Confirm public "
                    "access blocks and data classification before storing sensitive data."
                ),
            )
        )

    if _s3_public_exposure(resource_type, change):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "This S3 change appears to allow public access through an ACL or "
                    "bucket policy. Public data exposure requires security review."
                ),
            )
        )
    return candidates


def _kms_candidates(action_set: set[str]) -> list[RuleResult]:
    if "create" in action_set and "delete" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace a KMS key. Key identity changes can break "
                    "decrypt access for data and services that depend on the old key."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will schedule deletion of a KMS key. Once the deletion "
                    "window completes, data encrypted only by that key cannot be decrypted."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will update a KMS key. Review key policy, rotation, "
                    "deletion window, and service dependencies."
                ),
            )
        ]
    return []


def _iam_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []
    if "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete IAM authorization infrastructure. Confirm "
                    "no workloads, humans, or break-glass paths depend on it."
                ),
            )
        )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "__TOOL__ will update IAM authorization. Review trust policies, "
                    "permission boundaries, and deny statements for lockout or escalation risk."
                ),
            )
        )

    if resource_type == "aws_iam_role" and _attribute_changed(
        change, "assume_role_policy"
    ):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "The IAM role trust policy is changing. A bad assume_role_policy "
                    "can lock out workloads or allow unintended principals to assume the role."
                ),
            )
        )

    policy_attr = "assume_role_policy" if resource_type == "aws_iam_role" else "policy"
    before_policy = _policy_document(_before_value(change, policy_attr))
    after_policy = _policy_document(_after_value(change, policy_attr))
    if before_policy is not None and after_policy is not None:
        if _has_deny_statement(before_policy) and not _has_deny_statement(after_policy):
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "This IAM policy change appears to remove deny statements. "
                        "Removing explicit denies can widen access even when allow rules look unchanged."
                    ),
                )
            )

    return candidates


def _route53_candidates(action_set: set[str]) -> list[RuleResult]:
    if "create" in action_set and "delete" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace a Route53 hosted zone. Name server changes "
                    "can take production DNS offline until delegations and records are repaired."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete a Route53 hosted zone. DNS for the zone can "
                    "go dark, and recreating it may produce different name servers."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will update a Route53 hosted zone. Review delegation, "
                    "record ownership, and downstream DNS dependencies."
                ),
            )
        ]
    return []


def _eks_node_group_candidates(action_set: set[str]) -> list[RuleResult]:
    if "create" in action_set and "delete" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace an EKS node group. Expect pod evictions, "
                    "capacity churn, and possible cluster disruption during rollout."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete an EKS node group. Confirm replacement "
                    "capacity and disruption budgets before applying."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will update an EKS node group. Review rollout settings, "
                    "surge capacity, labels, taints, and workload disruption budgets."
                ),
            )
        ]
    return []


def _ecs_service_candidates(
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "create" in action_set and "delete" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace an ECS service. Expect running tasks to be "
                    "drained, possible service disruption, and ALB re-registration delay."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete an ECS service. All tasks, service discovery "
                    "entries, and auto-scaling policies will be removed. Confirm that "
                    "traffic has been routed away."
                ),
            )
        ]
    if "update" in action_set:
        candidates: list[RuleResult] = []
        if _attribute_changed(change, "force_new_deployment"):
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "force_new_deployment is set on an ECS service update. All "
                        "running tasks will be replaced, causing a rolling restart "
                        "with potential service disruption."
                    ),
                )
            )
        if _attribute_changed(change, "launch_type"):
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "ECS launch_type is changing (e.g. EC2 to FARGATE). Review "
                        "capacity providers, networking mode, and task placement "
                        "compatibility."
                    ),
                )
            )
        if not candidates:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update an ECS service. Review deployment "
                        "configuration, desired count, task definition, and health "
                        "check grace period before applying."
                    ),
                )
            )
        return candidates
    return []


def _lb_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if resource_type == "aws_lb":
        if "delete" in action_set and "create" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will replace this load balancer. Expect DNS rebinding, "
                        "connection draining, and possible downtime for all fronted services."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "__TOOL__ will delete this load balancer. All listeners, target "
                        "groups, and DNS aliases are affected immediately."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update this load balancer. Review attribute changes "
                        "for availability impact."
                    ),
                )
            )
        if _attribute_changed(change, "internal"):
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "The load balancer scheme is changing between internal and "
                        "internet-facing. DNS and address rebinding is required; "
                        "this is effectively irreversible without downtime."
                    ),
                )
            )

    elif resource_type == "aws_lb_listener":
        if "delete" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will delete a load balancer listener. "
                        "Production traffic on this port will be dropped."
                    ),
                )
            )
        if _attribute_changed(change, "port") or _attribute_changed(change, "protocol"):
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "Load balancer listener port or protocol is changing. "
                        "Clients may not reconnect to the new endpoint."
                    ),
                )
            )
        if _attribute_changed(change, "default_action"):
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "Load balancer listener default_action is changing. "
                        "This fronts production traffic; a misroute is immediately visible."
                    ),
                )
            )

    elif resource_type == "aws_lb_listener_rule":
        if _attribute_changed(change, "priority"):
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "Listener rule priority is changing. Routing precedence is "
                        "sensitive and concurrent priority changes can race."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update a listener rule. Review condition and "
                        "action changes for routing impact."
                    ),
                )
            )

    elif resource_type == "aws_lb_target_group":
        if "create" in action_set and "delete" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will replace this target group. Target registrations "
                        "are lost and must re-register, causing a traffic gap."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "__TOOL__ will delete this target group. Confirm no listeners "
                        "still reference it and no traffic depends on it."
                    ),
                )
            )
        if _attribute_changed(change, "target_type"):
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "Target group target_type is changing. This forces replacement "
                        "and disrupts all registered targets."
                    ),
                )
            )
        if _health_check_changed(change):
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "Target group health check settings are changing. Aggressive "
                        "thresholds can mass-fail healthy targets."
                    ),
                )
            )

    elif resource_type == "aws_lb_target_group_attachment":
        if "delete" in action_set and "create" not in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will detach a target from a target group. "
                        "Traffic will no longer route to this target."
                    ),
                )
            )

    return candidates


def _lambda_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if resource_type != "aws_lambda_function":
        return candidates

    if "update" not in action_set:
        return candidates

    if _attribute_changed(change, "package_type"):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "Lambda package_type is changing (e.g. zip to image). "
                    "This switch is not always cleanly reversible and may "
                    "require infrastructure changes."
                ),
            )
        )
    if _attribute_changed(change, "code_signing_config_arn"):
        candidates.append(
            RuleResult(
                "review",
                (
                    "Lambda code_signing_config_arn is changing. Review that the "
                    "new signing profile is trusted and deployment pipeline aligned."
                ),
            )
        )
    if _attribute_changed(change, "vpc_config"):
        candidates.append(
            RuleResult(
                "review",
                (
                    "Lambda vpc_config is changing. Network attachment changes "
                    "affect downstream connectivity and cold-start latency."
                ),
            )
        )
    if _runtime_major_changed(change):
        candidates.append(
            RuleResult(
                "review",
                (
                    "Lambda runtime major version is changing. Review compatibility "
                    "of dependencies and runtime behavior."
                ),
            )
        )
    if _attribute_changed(change, "role"):
        candidates.append(
            RuleResult(
                "review",
                (
                    "Lambda execution role is changing. The permission boundary "
                    "may shift, affecting what the function can access."
                ),
            )
        )
    if _runtime_deprecated(change):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "Lambda runtime is deprecated or approaching end-of-life. AWS "
                    "may block function updates or invocations for deprecated runtimes. "
                    "Upgrade to a supported runtime before applying."
                ),
            )
        )

    return candidates


def _platform_service_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if resource_type == "aws_ecr_repository":
        if "delete" in action_set and "create" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will replace an ECR repository. Image URLs, "
                        "repository policy, scanning, and pull paths may change."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "__TOOL__ will delete an ECR repository. Container images "
                        "and tags may be removed with the repository."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update an ECR repository. Review image "
                        "scanning, mutability, encryption, and lifecycle posture."
                    ),
                )
            )

    elif resource_type == "aws_ecr_repository_policy":
        candidates.extend(
            _policy_resource_candidates(
                action_set,
                change,
                "ECR repository policy",
                "container images",
            )
        )

    elif resource_type == "aws_ecr_lifecycle_policy":
        if "delete" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will delete an ECR lifecycle policy. Old images "
                        "may accumulate or retention assumptions may change."
                    ),
                )
            )
        elif "update" in action_set or "create" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will change an ECR lifecycle policy. Confirm tag "
                        "retention rules will not expire rollback images too early."
                    ),
                )
            )

    elif resource_type == "aws_sqs_queue":
        if "delete" in action_set and "create" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will replace an SQS queue. Queue URL/ARN changes "
                        "can break producers, consumers, and dead-letter routing."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "__TOOL__ will delete an SQS queue. Undelivered messages "
                        "and dead-letter history can be lost."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update an SQS queue. Review retention, "
                        "visibility timeout, encryption, and redrive policy changes."
                    ),
                )
            )
        if any(
            _attribute_changed(change, key)
            for key in (
                "redrive_policy",
                "visibility_timeout_seconds",
                "message_retention_seconds",
            )
        ):
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "SQS delivery semantics are changing. Redrive, visibility, "
                        "or retention changes can cause retries, loss, or backlog growth."
                    ),
                )
            )

    elif resource_type == "aws_sqs_queue_policy":
        candidates.extend(
            _policy_resource_candidates(
                action_set,
                change,
                "SQS queue policy",
                "queue producers and consumers",
            )
        )

    elif resource_type in {"aws_glue_catalog_database", "aws_glue_catalog_table"}:
        label = (
            "Glue catalog database"
            if resource_type == "aws_glue_catalog_database"
            else "Glue catalog table"
        )
        if "delete" in action_set and "create" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        f"__TOOL__ will replace a {label}. Data catalog identity "
                        "changes can break analytics jobs and lineage references."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        f"__TOOL__ will delete a {label}. Queries and ETL jobs "
                        "depending on the catalog entry may fail."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        f"__TOOL__ will update a {label}. Review schema, location, "
                        "classification, and consumer compatibility."
                    ),
                )
            )

    elif resource_type == "aws_glue_job":
        if "delete" in action_set and "create" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will replace a Glue job. Schedule bindings, "
                        "bookmarks, permissions, and ETL behavior may change."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "__TOOL__ will delete a Glue job. Dependent data pipelines "
                        "will stop running unless an equivalent job exists."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update a Glue job. Review script, role, "
                        "worker, bookmark, and connection changes before rollout."
                    ),
                )
            )
        if _attribute_changed(change, "role_arn"):
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "Glue job role_arn is changing. The ETL job's data access "
                        "boundary may shift."
                    ),
                )
            )

    return candidates


def _security_group_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if "delete" in action_set and "create" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace security group network boundaries. "
                    "Attached workloads may lose expected traffic paths during rollout."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will delete security group configuration. "
                    "Ingress/egress permissions for attached workloads may break."
                ),
            )
        )
    elif "update" in action_set or "create" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "__TOOL__ will change security group rules. Review ports, "
                    "protocols, and source/destination boundaries before applying."
                ),
            )
        )

    if _security_group_opens_to_internet(resource_type, change):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "This security group change appears to allow internet-wide access "
                    "(0.0.0.0/0 or ::/0). Confirm this exposure is intentional."
                ),
            )
        )

    return candidates


def _network_topology_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if resource_type == "aws_subnet":
        if "delete" in action_set and "create" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will replace a subnet. ENIs, load balancers, "
                        "NAT placement, and workload attachment may be disrupted."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will delete a subnet. Workloads and network "
                        "interfaces in that subnet must move first."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update subnet configuration. Review CIDR, "
                        "availability zone, public IP, and routing assumptions."
                    ),
                )
            )
        if _attribute_changed(change, "map_public_ip_on_launch"):
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "Subnet map_public_ip_on_launch is changing. New instances "
                        "may gain or lose public internet reachability."
                    ),
                )
            )

    elif resource_type in {"aws_route_table", "aws_route_table_association"}:
        if "delete" in action_set and "create" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will replace route table topology. Subnet "
                        "egress, ingress, and private/public boundaries may shift."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will delete route table topology. Attached "
                        "subnets may lose expected routing."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update route table topology. Review subnet "
                        "associations and default route behavior."
                    ),
                )
            )

    elif resource_type == "aws_route":
        if "delete" in action_set and "create" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will replace a route. Traffic may briefly blackhole "
                        "or move to a different network boundary."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will delete a route. Dependent traffic may lose "
                        "connectivity immediately."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update a route. Review destination CIDRs "
                        "and next-hop targets for reachability impact."
                    ),
                )
            )
        if _route_opens_internet_path(change):
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "This route appears to add a default route to an internet "
                        "gateway. Confirm the attached subnet is intended to be public."
                    ),
                )
            )

    elif resource_type == "aws_nat_gateway":
        if "delete" in action_set and "create" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will replace a NAT gateway. Private subnet egress "
                        "may be interrupted until routes point at the new gateway."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will delete a NAT gateway. Private subnet egress "
                        "for patching, pulls, and outbound calls may stop."
                    ),
                )
            )
        elif "create" in action_set or "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will change a NAT gateway. Review egress routing, "
                        "AZ placement, and elastic IP dependencies."
                    ),
                )
            )

    elif resource_type == "aws_internet_gateway":
        if "delete" in action_set and "create" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will replace an internet gateway. Public subnet "
                        "ingress and egress may be interrupted."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will delete an internet gateway. Public subnet "
                        "connectivity through that VPC will stop."
                    ),
                )
            )
        elif "create" in action_set or "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will change an internet gateway. Review which "
                        "subnets and routes should become internet reachable."
                    ),
                )
            )

    return candidates


def _observability_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if resource_type == "aws_cloudwatch_metric_alarm":
        if "delete" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "__TOOL__ will delete a CloudWatch alarm. Detection and "
                        "incident response coverage may be reduced."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update a CloudWatch alarm. Review threshold, "
                        "period, evaluation, and action changes for detection impact."
                    ),
                )
            )
        if any(
            _attribute_changed(change, key)
            for key in (
                "alarm_actions",
                "ok_actions",
                "insufficient_data_actions",
                "threshold",
                "evaluation_periods",
                "datapoints_to_alarm",
            )
        ):
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "CloudWatch alarm sensitivity or notification actions are "
                        "changing. Confirm alerts still reach the right responders."
                    ),
                )
            )

    elif resource_type in {"aws_cloudwatch_event_rule", "aws_cloudwatch_event_target"}:
        label = (
            "EventBridge rule"
            if resource_type == "aws_cloudwatch_event_rule"
            else "EventBridge target"
        )
        if "delete" in action_set:
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        f"__TOOL__ will delete an {label}. Automated detection, "
                        "routing, or remediation may stop."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        f"__TOOL__ will update an {label}. Review event pattern, "
                        "schedule, target, and retry behavior."
                    ),
                )
            )
        if any(
            _attribute_changed(change, key)
            for key in ("event_pattern", "schedule_expression", "arn", "role_arn")
        ):
            candidates.append(
                RuleResult(
                    "review",
                    (
                        f"{label} routing criteria or destination is changing. "
                        "Security events may stop reaching the expected workflow."
                    ),
                )
            )

    elif resource_type == "aws_cloudwatch_log_group":
        if "delete" in action_set:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "__TOOL__ will delete a CloudWatch log group. Log history "
                        "used for investigations and audit evidence may be removed."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update a CloudWatch log group. Review "
                        "retention, encryption, and subscription changes."
                    ),
                )
            )
        if _retention_decreased(change, "retention_in_days"):
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "CloudWatch log retention is decreasing. Investigation and "
                        "audit lookback windows may shrink."
                    ),
                )
            )

    return candidates


def _policy_resource_candidates(
    action_set: set[str],
    change: dict[str, Any],
    label: str,
    protected_subject: str,
) -> list[RuleResult]:
    candidates: list[RuleResult] = []
    if "delete" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    f"__TOOL__ will delete a {label}. Access for {protected_subject} "
                    "may become too broad or too restrictive depending on defaults."
                ),
            )
        )
    elif "update" in action_set or "create" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    f"__TOOL__ will change a {label}. Review principals, actions, "
                    "and cross-account access before applying."
                ),
            )
        )

    policy = _policy_document(_after_value(change, "policy"))
    if policy is not None and _policy_allows_public(policy):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    f"This {label} appears to allow public access. Public or "
                    "anonymous access requires security review."
                ),
            )
        )
    return candidates


def _health_check_changed(change: dict[str, Any]) -> bool:
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    before_hc = before.get("health_check")
    after_hc = after.get("health_check")
    return before_hc != after_hc and before_hc is not None and after_hc is not None


def _runtime_major_changed(change: dict[str, Any]) -> bool:
    if not _attribute_changed(change, "runtime"):
        return False
    before_rt = _before_value(change, "runtime")
    after_rt = _after_value(change, "runtime")
    if not isinstance(before_rt, str) or not isinstance(after_rt, str):
        return False
    before_major = _extract_runtime_major(before_rt)
    after_major = _extract_runtime_major(after_rt)
    return (
        before_major is not None
        and after_major is not None
        and before_major != after_major
    )


def _extract_runtime_major(runtime: str) -> str | None:
    match = re.match(r"^([a-zA-Z]+)(\d+)", runtime)
    if match is None:
        return None
    return f"{match.group(1)}{match.group(2)}"


# AWS Lambda runtimes deprecated as of 2026-05.
# See https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
_DEPRECATED_RUNTIMES: set[str] = {
    "nodejs12.x",
    "nodejs14.x",
    "nodejs16.x",
    "python3.6",
    "python3.7",
    "python3.8",
    "dotnetcore3.1",
    "dotnet5.0",
    "dotnet6",
    "ruby2.5",
    "ruby2.7",
    "java8",
    "java8.al2",
    "go1.x",
    "provided",
}


def _runtime_deprecated(change: dict[str, Any]) -> bool:
    """Check if the runtime is deprecated (in after value) or changing to deprecated."""
    after = _after_value(change, "runtime")
    if isinstance(after, str) and after in _DEPRECATED_RUNTIMES:
        return True
    before = _before_value(change, "runtime")
    if isinstance(before, str) and before in _DEPRECATED_RUNTIMES:
        return True
    return False


def _max_result(current: RuleResult, candidate: RuleResult) -> RuleResult:
    current_rank = RISK_ORDER.get(current.risk, RISK_ORDER["review"])
    candidate_rank = RISK_ORDER.get(candidate.risk, RISK_ORDER["review"])
    if candidate_rank >= current_rank:
        return candidate
    return current


def _before_value(change: dict[str, Any], key: str) -> Any:
    before = change.get("before")
    if isinstance(before, dict):
        return before.get(key)
    return None


def _after_value(change: dict[str, Any], key: str) -> Any:
    after = change.get("after")
    if isinstance(after, dict):
        return after.get(key)
    return None


def _attribute_changed(change: dict[str, Any], key: str) -> bool:
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    return before.get(key) != after.get(key)


def _major_version_changed(change: dict[str, Any], key: str) -> bool:
    if not _attribute_changed(change, key):
        return False
    before_major = _major_version(_before_value(change, key))
    after_major = _major_version(_after_value(change, key))
    return before_major is not None and after_major is not None and after_major != before_major


def _major_version(value: Any) -> int | None:
    if value is None:
        return None
    match = re.match(r"^\s*(\d+)", str(value))
    if match is None:
        return None
    return int(match.group(1))


def _route_opens_internet_path(change: dict[str, Any]) -> bool:
    destination = _after_value(change, "destination_cidr_block")
    ipv6_destination = _after_value(change, "destination_ipv6_cidr_block")
    gateway_id = _after_value(change, "gateway_id")
    return (
        (destination == "0.0.0.0/0" or ipv6_destination == "::/0")
        and isinstance(gateway_id, str)
        and (gateway_id.startswith("igw-") or "internet_gateway" in gateway_id)
    )


def _retention_decreased(change: dict[str, Any], key: str) -> bool:
    if not _attribute_changed(change, key):
        return False
    before = _before_value(change, key)
    after = _after_value(change, key)
    if not isinstance(before, int) or not isinstance(after, int):
        return False
    return after < before


def _s3_public_exposure(resource_type: str, change: dict[str, Any]) -> bool:
    acl = _after_value(change, "acl")
    if isinstance(acl, str) and acl.lower() in {"public-read", "public-read-write"}:
        return True

    if resource_type == "aws_s3_bucket_policy" or _after_value(change, "policy"):
        policy = _policy_document(_after_value(change, "policy"))
        return policy is not None and _policy_allows_public(policy)
    return False


def _security_group_opens_to_internet(resource_type: str, change: dict[str, Any]) -> bool:
    if resource_type == "aws_security_group":
        ingress = _after_value(change, "ingress")
        if isinstance(ingress, list):
            return any(_rule_block_opens_to_internet(rule) for rule in ingress)
        return _rule_block_opens_to_internet(ingress)

    return _rule_block_opens_to_internet(change.get("after"))


def _rule_block_opens_to_internet(value: Any) -> bool:
    if isinstance(value, dict):
        cidrs = value.get("cidr_blocks")
        if isinstance(cidrs, list) and any(cidr == "0.0.0.0/0" for cidr in cidrs):
            return True
        ipv6_cidrs = value.get("ipv6_cidr_blocks")
        if isinstance(ipv6_cidrs, list) and any(cidr == "::/0" for cidr in ipv6_cidrs):
            return True

        if value.get("cidr_ipv4") == "0.0.0.0/0" or value.get("cidr_ipv6") == "::/0":
            return True

        nested_ingress = value.get("ingress")
        if isinstance(nested_ingress, list) and any(
            _rule_block_opens_to_internet(rule) for rule in nested_ingress
        ):
            return True

    return False


def _policy_document(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return None
        if isinstance(decoded, dict):
            return decoded
    return None


def _policy_allows_public(policy: dict[str, Any]) -> bool:
    return any(
        _statement_effect(statement) == "allow" and _principal_is_public(statement)
        for statement in _statements(policy)
    )


def _has_deny_statement(policy: dict[str, Any]) -> bool:
    return any(_statement_effect(statement) == "deny" for statement in _statements(policy))


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    return [statement for statement in statements if isinstance(statement, dict)]


def _statement_effect(statement: dict[str, Any]) -> str:
    return str(statement.get("Effect", "")).lower()


def _principal_is_public(statement: dict[str, Any]) -> bool:
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(_contains_public_principal(value) for value in principal.values())
    return False


def _contains_public_principal(value: Any) -> bool:
    if value == "*":
        return True
    if isinstance(value, list):
        return any(item == "*" for item in value)
    return False
