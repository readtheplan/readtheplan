from __future__ import annotations

from typing import Any

from readtheplan.rules._shared import (
    RuleResult,
    register_rule,
)


@register_rule("kubernetes_deployment")
def _k8s_deployment_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set and "create" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace this Deployment. A "
                    "rolling replacement will drain old pods and "
                    "create new ones; review the new spec for "
                    "configuration drift."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this Deployment. All "
                    "pods managed by this Deployment will be "
                    "terminated and their endpoints removed."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will update this Deployment. Review "
                    "image tag, replicas, container resources, "
                    "probes, and selector changes."
                ),
            )
        ]
    return []




@register_rule("kubernetes_service", "kubernetes_ingress")
def _k8s_service_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = "Ingress" if resource_type == "kubernetes_ingress" else "Service"

    if "delete" in action_set and "create" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    f"__TOOL__ will replace this {label}. Endpoints "
                    "and DNS records may change, causing transient "
                    "connectivity loss."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    f"__TOOL__ will delete this {label}. Traffic "
                    "routing to this service will stop immediately."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    f"__TOOL__ will update this {label}. Review "
                    "port mapping, selector, type (ClusterIP / "
                    "NodePort / LoadBalancer), and annotations."
                ),
            )
        ]
    return []




@register_rule("kubernetes_secret")
def _k8s_secret_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this Secret. Credentials, "
                    "tokens, or certs stored in this Secret will "
                    "be lost; pods mounting it must be recreated."
                ),
            )
        ]
    if "update" in action_set or "create" in action_set:
        is_create = "delete" not in action_set and "create" in action_set and "update" not in action_set  # noqa: E501
        verb = "create this" if is_create else "change this"
        return [
            RuleResult(
                "dangerous",
                (
                    f"__TOOL__ will {verb} Secret. Secrets contain "
                    "sensitive data; verify the new values and ensure "
                    "pods are configured to pick up the change."
                ),
            )
        ]
    return []




@register_rule("kubernetes_namespace")
def _k8s_namespace_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set and "create" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace this Namespace. All "
                    "resources in the old namespace will be "
                    "destroyed and recreated."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this Namespace. All "
                    "pods, services, and RBAC resources inside "
                    "it will be removed."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will update this Namespace. Review "
                    "labels, annotations, and resource quotas."
                ),
            )
        ]
    return []




_RBAC_ROLE_TYPES = frozenset({"kubernetes_cluster_role", "kubernetes_role"})


def _wildcard_rbac_fields(change: dict[str, Any]) -> tuple[str, ...]:
    """Return RBAC rule fields whose desired value contains a wildcard grant."""
    after = change.get("after", {})
    if not isinstance(after, dict):
        return ()

    rules = after.get("rules", [])
    if not isinstance(rules, list):
        return ()

    wildcard_fields: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        for field in ("apiGroups", "resources", "verbs"):
            values = rule.get(field, [])
            if values == "*" or (
                isinstance(values, (list, tuple, set, frozenset)) and "*" in values
            ):
                wildcard_fields.add(field)

    return tuple(sorted(wildcard_fields))


@register_rule(
    "kubernetes_cluster_role",
    "kubernetes_cluster_role_binding",
    "kubernetes_role_binding",
    "kubernetes_role",
)
def _k8s_rbac_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if resource_type == "kubernetes_cluster_role":
        label = "ClusterRole"
    elif resource_type == "kubernetes_role":
        label = "Role"
    elif resource_type == "kubernetes_cluster_role_binding":
        label = "ClusterRoleBinding"
    else:
        label = "RoleBinding"

    if resource_type in _RBAC_ROLE_TYPES and (
        "create" in action_set or "update" in action_set
    ):
        wildcard_fields = _wildcard_rbac_fields(change)
        if wildcard_fields:
            fields = ", ".join(wildcard_fields)
            return [
                RuleResult(
                    "dangerous",
                    (
                        f"__TOOL__ will grant wildcard {fields} permissions "
                        f"through a {label}. Verify that this broad RBAC access "
                        "is intentional and cannot enable privilege escalation."
                    ),
                )
            ]

    if "delete" in action_set and "create" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    f"__TOOL__ will replace a {label}. RBAC "
                    "permissions will be removed and re-granted; "
                    "subjects may temporarily lose access."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    f"__TOOL__ will delete a {label}. Subjects "
                    "bound by this RBAC resource will lose "
                    "permissions immediately."
                ),
            )
        ]
    if "update" in action_set or "create" in action_set:
        return [
            RuleResult(
                "review",
                (
                    f"__TOOL__ will change a {label}. Review "
                    "rules, subjects, and roleRef for privilege "
                    "escalation or lockout risk."
                ),
            )
        ]
    return []




@register_rule("kubernetes_network_policy")
def _k8s_network_policy_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set and "create" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace a NetworkPolicy. "
                    "Pod-to-pod traffic isolation will briefly "
                    "reset during the transition."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete a NetworkPolicy. Pod "
                    "isolation rules will be removed; traffic "
                    "that was blocked may become allowed."
                ),
            )
        ]
    if "update" in action_set or "create" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will change a NetworkPolicy. Review "
                    "podSelector, ingress/egress rules, and "
                    "namespace isolation before applying."
                ),
            )
        ]
    return []

