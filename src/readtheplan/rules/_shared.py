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
    # Lazy imports to avoid circular dependency.
    from readtheplan.rules import aws as _aws
    from readtheplan.rules import gcp as _gcp
    from readtheplan.rules import azure as _azure
    from readtheplan.rules import k8s as _k8s

    action_set = set(actions)

    # ── AWS: specific resource types ─────────────────────────────────
    if resource_type in {"aws_db_instance", "aws_rds_cluster"}:
        return _aws._rds_candidates(resource_type, action_set, change)
    if resource_type in {"aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_bucket_policy"}:
        return _aws._s3_candidates(resource_type, action_set, change)
    if resource_type == "aws_kms_key":
        return _aws._kms_candidates(action_set)
    if resource_type in {"aws_iam_role", "aws_iam_policy", "aws_iam_role_policy"}:
        return _aws._iam_candidates(resource_type, action_set, change)
    if resource_type == "aws_route53_zone":
        return _aws._route53_candidates(action_set)
    if resource_type in {"aws_eks_node_group", "aws_eks_nodegroup"}:
        return _aws._eks_node_group_candidates(action_set)
    if resource_type == "aws_ecs_service":
        return _aws._ecs_service_candidates(action_set, change)
    if resource_type in {"aws_lb", "aws_elb", "aws_alb", "aws_nlb"}:
        return _aws._lb_candidates(resource_type, action_set, change)
    if resource_type in {"aws_lb_listener", "aws_lb_listener_rule"}:
        return _aws._lb_candidates(resource_type, action_set, change)
    if resource_type in {"aws_lb_target_group", "aws_lb_target_group_attachment"}:
        return _aws._lb_candidates(resource_type, action_set, change)
    if resource_type in {"aws_lambda_function", "aws_lambda_alias"}:
        return _aws._lambda_candidates(resource_type, action_set, change)
    if resource_type == "aws_lambda_event_source_mapping":
        return _aws._lambda_candidates(resource_type, action_set, change)
    if resource_type in {
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
        "aws_vpc_security_group_egress_rule",
    }:
        return _aws._security_group_candidates(resource_type, action_set, change)

    # ── AWS: cross-cutting (broad type-prefix matching) ──────────────
    candidates: list[RuleResult] = []
    candidates.extend(_aws._platform_service_candidates(resource_type, action_set, change))
    candidates.extend(_aws._network_topology_candidates(resource_type, action_set, change))
    candidates.extend(_aws._observability_candidates(resource_type, action_set, change))

    # ── GCP: google_* resources ──────────────────────────────────────
    if resource_type == "google_compute_instance":
        candidates.extend(_gcp._gcp_compute_instance_candidates(action_set, change))
    elif resource_type == "google_container_cluster":
        candidates.extend(_gcp._gcp_container_cluster_candidates(action_set, change))
    elif resource_type == "google_sql_database_instance":
        candidates.extend(_gcp._gcp_sql_database_instance_candidates(action_set, change))
    elif resource_type == "google_storage_bucket":
        candidates.extend(_gcp._gcp_storage_bucket_candidates(action_set, change))
    elif resource_type == "google_compute_firewall":
        candidates.extend(_gcp._gcp_compute_firewall_candidates(action_set, change))

    # ── Azure: azurerm_* resources ───────────────────────────────────
    if resource_type == "azurerm_virtual_machine":
        candidates.extend(_azure._azurerm_virtual_machine_candidates(action_set, change))
    elif resource_type == "azurerm_kubernetes_cluster":
        candidates.extend(_azure._azurerm_kubernetes_cluster_candidates(action_set, change))
    elif resource_type == "azurerm_storage_account":
        candidates.extend(_azure._azurerm_storage_account_candidates(action_set, change))
    elif resource_type == "azurerm_role_assignment":
        candidates.extend(_azure._azurerm_role_assignment_candidates(action_set))
    elif resource_type in {"azurerm_network_security_group", "azurerm_network_security_rule"}:
        candidates.extend(_azure._azurerm_network_security_candidates(resource_type, action_set, change))

    # ── Kubernetes: kubernetes_* resources ───────────────────────────
    if resource_type == "kubernetes_deployment":
        candidates.extend(_k8s._k8s_deployment_candidates(action_set))
    elif resource_type in {"kubernetes_service", "kubernetes_ingress"}:
        candidates.extend(_k8s._k8s_service_candidates(resource_type, action_set))
    elif resource_type == "kubernetes_secret":
        candidates.extend(_k8s._k8s_secret_candidates(action_set))
    elif resource_type == "kubernetes_namespace":
        candidates.extend(_k8s._k8s_namespace_candidates(action_set))
    elif resource_type in {
        "kubernetes_cluster_role",
        "kubernetes_cluster_role_binding",
        "kubernetes_role_binding",
    }:
        candidates.extend(_k8s._k8s_rbac_candidates(resource_type, action_set))
    elif resource_type == "kubernetes_network_policy":
        candidates.extend(_k8s._k8s_network_policy_candidates(action_set))

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
    "nodejs18.x",
    "python3.6",
    "python3.7",
    "python3.8",
    "python3.9",
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
