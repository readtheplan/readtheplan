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
        is_create = (
            "delete" not in action_set and "create" in action_set and "update" not in action_set
        )  # noqa: E501
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

    if resource_type in _RBAC_ROLE_TYPES and ("create" in action_set or "update" in action_set):
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


def _desired_spec(change: dict[str, Any]) -> dict[str, Any]:
    after = change.get("after", {})
    if not isinstance(after, dict):
        return {}
    spec = after.get("spec", {})
    return spec if isinstance(spec, dict) else {}


def _automated_prune_enabled(spec: dict[str, Any]) -> bool:
    sync_policy = spec.get("syncPolicy", {})
    if not isinstance(sync_policy, dict):
        return False
    automated = sync_policy.get("automated")
    if not isinstance(automated, dict) or automated.get("enabled") is False:
        return False
    return automated.get("prune") is True


@register_rule("kubernetes_argocd_application")
def _argocd_application_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this Argo CD Application. Depending on "
                    "finalizers and cascade settings, managed workloads may also be pruned."
                ),
            )
        ]

    spec = _desired_spec(change)
    if _automated_prune_enabled(spec):
        return [
            RuleResult(
                "dangerous",
                (
                    "This Argo CD Application enables automated pruning. Resources "
                    "removed from Git can be deleted from the destination cluster "
                    "without a separate manual sync approval."
                ),
            )
        ]
    if "create" in action_set or "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will change an Argo CD Application. Review source "
                    "repository and revision, destination cluster/namespace, project, "
                    "sync policy, and ignore-difference rules."
                ),
            )
        ]
    return []


def _argocd_project_wildcards(spec: dict[str, Any]) -> tuple[str, ...]:
    findings: set[str] = set()
    source_repos = spec.get("sourceRepos", [])
    if source_repos == "*" or (isinstance(source_repos, list) and "*" in source_repos):
        findings.add("source repositories")

    destinations = spec.get("destinations", [])
    if isinstance(destinations, list):
        for destination in destinations:
            if not isinstance(destination, dict):
                continue
            if any(destination.get(field) == "*" for field in ("name", "namespace", "server")):
                findings.add("destinations")

    for field, label in (
        ("clusterResourceWhitelist", "cluster resources"),
        ("namespaceResourceWhitelist", "namespace resources"),
    ):
        resources = spec.get(field, [])
        if isinstance(resources, list) and any(
            isinstance(resource, dict)
            and (resource.get("group") == "*" or resource.get("kind") == "*")
            for resource in resources
        ):
            findings.add(label)

    roles = spec.get("roles", [])
    if isinstance(roles, list) and any(
        isinstance(role, dict) and any("*" in str(policy) for policy in role.get("policies", []))
        for role in roles
    ):
        findings.add("project role policies")
    return tuple(sorted(findings))


@register_rule("kubernetes_argocd_project")
def _argocd_project_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this Argo CD AppProject. Applications tied "
                    "to the project may lose their authorization boundary."
                ),
            )
        ]
    wildcards = _argocd_project_wildcards(_desired_spec(change))
    if wildcards:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Argo CD AppProject grants wildcard scope for "
                    f"{', '.join(wildcards)}. Review tenant isolation and deployment "
                    "boundaries before applying."
                ),
            )
        ]
    if "create" in action_set or "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will change an Argo CD AppProject. Review allowed "
                    "sources, destinations, resource allow/deny lists, and project roles."
                ),
            )
        ]
    return []


@register_rule("kubernetes_argocd_application_set")
def _argocd_application_set_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this Argo CD ApplicationSet. Generated "
                    "Applications and their managed resources may be cascaded."
                ),
            )
        ]

    spec = _desired_spec(change)
    template = spec.get("template", {})
    template_spec = template.get("spec", {}) if isinstance(template, dict) else {}
    if isinstance(template_spec, dict) and _automated_prune_enabled(template_spec):
        return [
            RuleResult(
                "dangerous",
                (
                    "This Argo CD ApplicationSet template enables automated pruning. "
                    "A generator change can remove workloads across multiple generated "
                    "Applications without separate manual sync approvals."
                ),
            )
        ]
    if "create" in action_set or "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will change an Argo CD ApplicationSet. Review generators, "
                    "template source/destination, project, and deletion preservation."
                ),
            )
        ]
    return []


def _flux_source_candidates(
    source_name: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    f"__TOOL__ will delete this Flux {source_name}. Dependent "
                    "reconciliations will lose their artifact source and may stop updating."
                ),
            )
        ]
    spec = _desired_spec(change)
    url = str(spec.get("url") or "").lower()
    if url.startswith("http://"):
        return [
            RuleResult(
                "dangerous",
                f"This Flux {source_name} fetches artifacts over unencrypted HTTP.",
            )
        ]
    if any(spec.get(field) for field in ("secretRef", "proxySecretRef")):
        return [
            RuleResult(
                "dangerous",
                (
                    f"This Flux {source_name} uses authentication or proxy secret "
                    "material. Verify repository trust, credential scope, and rotation."
                ),
            )
        ]
    if spec.get("suspend") is True:
        return [
            RuleResult(
                "dangerous",
                (
                    f"This Flux {source_name} suspends reconciliation. Artifact and "
                    "security updates will stop until it is resumed."
                ),
            )
        ]
    if "create" in action_set or "update" in action_set:
        ref = spec.get("ref", {})
        immutable = isinstance(ref, dict) and bool(ref.get("commit") or ref.get("digest"))
        verification = spec.get("verify")
        guidance = (
            "The source uses an immutable revision; still verify repository ownership, "
            "signature policy, included artifacts, and consumer scope."
            if immutable
            else "The source follows a mutable branch, tag, or version selector; review "
            "repository ownership, signature verification, and update scope."
        )
        if verification:
            guidance += " Source verification is configured."
        return [RuleResult("review", f"__TOOL__ will change a Flux {source_name}. {guidance}")]
    return []


@register_rule("kubernetes_flux_git_repository")
def _flux_git_repository_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    return _flux_source_candidates("GitRepository", action_set, change)


@register_rule("kubernetes_flux_oci_repository")
def _flux_oci_repository_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    return _flux_source_candidates("OCIRepository", action_set, change)


@register_rule("kubernetes_flux_kustomization")
def _flux_kustomization_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this Flux Kustomization. Depending on its "
                    "deletion policy and finalizers, managed cluster resources may be pruned."
                ),
            )
        ]
    spec = _desired_spec(change)
    destructive: list[str] = []
    if spec.get("prune") is True:
        destructive.append("prune resources removed from the source")
    if spec.get("force") is True:
        destructive.append("recreate resources when immutable fields change")
    if spec.get("kubeConfig"):
        destructive.append("apply to a remote cluster through kubeConfig")
    if spec.get("decryption"):
        destructive.append("decrypt secret-bearing manifests")
    if destructive:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Flux Kustomization can "
                    f"{'; '.join(destructive)}. Verify source, identity, target cluster, "
                    "deletion policy, and recovery path."
                ),
            )
        ]
    if spec.get("suspend") is True:
        return [
            RuleResult(
                "dangerous",
                "This Flux Kustomization suspends reconciliation and drift correction.",
            )
        ]
    if "create" in action_set or "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will change a Flux Kustomization. Review sourceRef, path, "
                    "dependencies, service account, target namespace, health checks, and "
                    "server-side apply policies."
                ),
            )
        ]
    return []


def _helm_release_uses_secrets(spec: dict[str, Any]) -> bool:
    values_from = spec.get("valuesFrom", [])
    if isinstance(values_from, list) and any(
        isinstance(value, dict) and str(value.get("kind", "Secret")).lower() == "secret"
        for value in values_from
    ):
        return True
    kube_config = spec.get("kubeConfig")
    return isinstance(kube_config, dict) and bool(kube_config.get("secretRef"))


def _helm_release_destructive_remediation(spec: dict[str, Any]) -> bool:
    install = spec.get("install", {})
    upgrade = spec.get("upgrade", {})
    for phase in (install, upgrade):
        if not isinstance(phase, dict):
            continue
        if phase.get("force") is True:
            return True
        remediation = phase.get("remediation", {})
        if isinstance(remediation, dict) and (
            remediation.get("remediateLastFailure") is True
            or remediation.get("retries") not in (None, 0, "0")
        ):
            return True
    return False


@register_rule("kubernetes_flux_helm_release")
def _flux_helm_release_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this Flux HelmRelease. The controller may "
                    "uninstall the release and delete its managed resources."
                ),
            )
        ]
    spec = _desired_spec(change)
    findings: list[str] = []
    if spec.get("kubeConfig"):
        findings.append("target a remote cluster")
    if _helm_release_uses_secrets(spec):
        findings.append("consume secret-backed values or credentials")
    if _helm_release_destructive_remediation(spec):
        findings.append("automatically remediate failed installs or upgrades")
    if findings:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Flux HelmRelease can "
                    f"{'; '.join(findings)}. Review chart provenance, target identity, "
                    "values, remediation, rollback, and uninstall behavior."
                ),
            )
        ]
    if spec.get("suspend") is True:
        return [
            RuleResult(
                "dangerous",
                "This Flux HelmRelease suspends release reconciliation and drift correction.",
            )
        ]
    if "create" in action_set or "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will change a Flux HelmRelease. Review chart source and "
                    "version, values, target namespace, service account, tests, and "
                    "install/upgrade/rollback strategies."
                ),
            )
        ]
    return []


@register_rule("kubernetes_flux_image_update_automation")
def _flux_image_update_automation_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "dangerous",
                "__TOOL__ will delete Flux image update automation and stop managed updates.",
            )
        ]
    if "create" in action_set or "update" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Flux ImageUpdateAutomation can commit and push image changes "
                    "to Git automatically. Review checkout/push branches, commit identity, "
                    "update path, image policies, and repository credentials."
                ),
            )
        ]
    return []


@register_rule("kubernetes_flux_receiver")
def _flux_receiver_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "dangerous",
                "__TOOL__ will delete a Flux webhook receiver and stop event reconciliation.",
            )
        ]
    if "create" in action_set or "update" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Flux Receiver exposes an event-driven reconciliation endpoint. "
                    "Verify receiver type, webhook secret, resource filters, ingress, and "
                    "denial-of-service controls."
                ),
            )
        ]
    return []
