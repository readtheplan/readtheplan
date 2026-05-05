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


def action_explanation(actions: tuple[str, ...]) -> str:
    if not actions:
        return "Terraform action metadata is missing or unknown; human review is required."
    action_set = set(actions)
    if "delete" in action_set and "create" in action_set:
        return (
            "Terraform will replace this resource. Review downtime, identity "
            "changes, and any state that must be migrated or restored."
        )
    if "delete" in action_set:
        return (
            "Terraform will delete this resource. Verify recovery, backups, and "
            "external dependencies before applying."
        )
    if "update" in action_set:
        return (
            "Terraform will update this resource in place. Review the changed "
            "attributes and rollout timing before applying."
        )
    if action_set <= {"no-op", "read"}:
        return "Terraform is only reading or refreshing this resource."
    if "create" in action_set:
        return "Terraform will create a new resource without changing existing state."
    return "Terraform action metadata is missing or unknown; human review is required."


def apply_resource_rules(
    *,
    resource_type: str,
    actions: tuple[str, ...],
    change: dict[str, Any],
    baseline: RuleResult,
) -> RuleResult:
    result = baseline
    for candidate in _rule_candidates(resource_type, actions, change):
        result = _max_result(result, candidate)
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
                    f"Terraform will replace this {label}. Confirm snapshots, "
                    "restore path, endpoint changes, and maintenance-window impact."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    f"Terraform will delete this {label}. Without a verified final "
                    "snapshot or restore plan, database data may be lost."
                ),
            )
        )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    f"Terraform will update this {label}. Check backup state, "
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
                        "Terraform will delete an S3 bucket with force_destroy enabled. "
                        "Objects can be removed along with the bucket, making recovery unlikely."
                    ),
                )
            )
        else:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "Terraform will delete an S3 bucket or bucket control resource. "
                        "Confirm object retention, replication, and recovery requirements."
                    ),
                )
            )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "Terraform will update S3 bucket controls. Review public access, "
                    "retention, encryption, and data exposure settings."
                ),
            )
        )
    elif "create" in action_set:
        candidates.append(
            RuleResult(
                "safe",
                (
                    "Terraform will create S3 bucket infrastructure. Confirm public "
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
                    "Terraform will replace a KMS key. Key identity changes can break "
                    "decrypt access for data and services that depend on the old key."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "Terraform will schedule deletion of a KMS key. Once the deletion "
                    "window completes, data encrypted only by that key cannot be decrypted."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "Terraform will update a KMS key. Review key policy, rotation, "
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
                    "Terraform will delete IAM authorization infrastructure. Confirm "
                    "no workloads, humans, or break-glass paths depend on it."
                ),
            )
        )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "Terraform will update IAM authorization. Review trust policies, "
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
                    "Terraform will replace a Route53 hosted zone. Name server changes "
                    "can take production DNS offline until delegations and records are repaired."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "Terraform will delete a Route53 hosted zone. DNS for the zone can "
                    "go dark, and recreating it may produce different name servers."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "Terraform will update a Route53 hosted zone. Review delegation, "
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
                    "Terraform will replace an EKS node group. Expect pod evictions, "
                    "capacity churn, and possible cluster disruption during rollout."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "Terraform will delete an EKS node group. Confirm replacement "
                    "capacity and disruption budgets before applying."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "Terraform will update an EKS node group. Review rollout settings, "
                    "surge capacity, labels, taints, and workload disruption budgets."
                ),
            )
        ]
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
                        "Terraform will replace this load balancer. Expect DNS rebinding, "
                        "connection draining, and possible downtime for all fronted services."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "Terraform will delete this load balancer. All listeners, target "
                        "groups, and DNS aliases are affected immediately."
                    ),
                )
            )
        elif "update" in action_set:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "Terraform will update this load balancer. Review attribute changes "
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
                        "Terraform will delete a load balancer listener. "
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
                        "Terraform will update a listener rule. Review condition and "
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
                        "Terraform will replace this target group. Target registrations "
                        "are lost and must re-register, causing a traffic gap."
                    ),
                )
            )
        elif "delete" in action_set:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "Terraform will delete this target group. Confirm no listeners "
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
                        "Terraform will detach a target from a target group. "
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


def _s3_public_exposure(resource_type: str, change: dict[str, Any]) -> bool:
    acl = _after_value(change, "acl")
    if isinstance(acl, str) and acl.lower() in {"public-read", "public-read-write"}:
        return True

    if resource_type == "aws_s3_bucket_policy" or _after_value(change, "policy"):
        policy = _policy_document(_after_value(change, "policy"))
        return policy is not None and _policy_allows_public(policy)
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
