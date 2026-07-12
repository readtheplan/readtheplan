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


_TEKTON_SECRET_TOKENS = (
    "api_key",
    "apikey",
    "credential",
    "passwd",
    "password",
    "private_key",
    "secret",
    "token",
)


def _tekton_walk(value: Any):
    yield value
    if isinstance(value, dict):
        for item in value.values():
            yield from _tekton_walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _tekton_walk(item)


def _tekton_has_secret_reference(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key).lower()
            if key_text in {
                "secret",
                "secretref",
                "secretkeyref",
                "imagepullsecrets",
            }:
                return True
            if any(token in key_text for token in _TEKTON_SECRET_TOKENS):
                return True
            if _tekton_has_secret_reference(item):
                return True
        return False
    if isinstance(value, list):
        return any(_tekton_has_secret_reference(item) for item in value)
    return False


def _tekton_has_privileged_pod_settings(value: Any) -> bool:
    for item in _tekton_walk(value):
        if not isinstance(item, dict):
            continue
        if any(item.get(key) is True for key in ("hostIPC", "hostNetwork", "hostPID")):
            return True
        if item.get("hostPath") is not None:
            return True
        security = item.get("securityContext")
        if isinstance(security, dict) and (
            security.get("privileged") is True
            or security.get("allowPrivilegeEscalation") is True
            or security.get("runAsUser") in (0, "0")
        ):
            return True
        text = str(item).lower()
        if "docker.sock" in text or "containerd.sock" in text or "podman.sock" in text:
            return True
    return False


def _tekton_images(value: Any) -> list[str]:
    images: list[str] = []
    for item in _tekton_walk(value):
        if isinstance(item, dict) and item.get("image") is not None:
            images.append(str(item["image"]))
    return images


def _tekton_mutable_images(value: Any) -> list[str]:
    return [image for image in _tekton_images(value) if "@sha256:" not in image.lower()]


def _tekton_param_map(reference: dict[str, Any]) -> dict[str, Any]:
    params = reference.get("params", [])
    if not isinstance(params, list):
        return {}
    return {
        str(param.get("name")): param.get("value")
        for param in params
        if isinstance(param, dict) and param.get("name") is not None
    }


def _tekton_reference_findings(value: Any) -> list[str]:
    findings: list[str] = []
    for item in _tekton_walk(value):
        if not isinstance(item, dict) or not item.get("resolver"):
            continue
        resolver = str(item["resolver"]).lower()
        params = _tekton_param_map(item)
        if resolver == "git":
            revision = str(params.get("revision") or "")
            invalid_sha = len(revision) != 40 or any(
                char not in "0123456789abcdefABCDEF" for char in revision
            )
            if invalid_sha:
                findings.append("resolve a Task or Pipeline from a mutable Git revision")
        elif resolver == "bundles":
            bundle = str(params.get("bundle") or "")
            if "@sha256:" not in bundle.lower():
                findings.append("resolve a Task or Pipeline from a mutable OCI bundle")
            if params.get("secret"):
                findings.append("use registry credentials for remote bundle resolution")
        elif resolver == "http":
            url = str(params.get("url") or "")
            if url.lower().startswith("http://"):
                findings.append("fetch a remote definition over unencrypted HTTP")
            if not (params.get("digest") or params.get("sha256") or params.get("sha512")):
                findings.append("fetch a remote HTTP definition without an integrity digest")
        elif resolver == "cluster":
            findings.append("resolve a mutable Task or Pipeline from the cluster")
        elif resolver == "hub":
            findings.append("resolve executable pipeline content from a configured Hub")
        else:
            findings.append(f"use the '{resolver}' remote resolver")
    return findings


def _tekton_workspace_findings(spec: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    workspaces = spec.get("workspaces", [])
    if not isinstance(workspaces, list):
        return findings
    for workspace in workspaces:
        if not isinstance(workspace, dict):
            continue
        if workspace.get("secret") is not None:
            findings.append("mount a Secret-backed workspace")
        if workspace.get("persistentVolumeClaim") is not None:
            findings.append("read or write a persistent volume workspace")
        if workspace.get("volumeClaimTemplate") is not None:
            findings.append("provision persistent storage for pipeline execution")
    return findings


@register_rule(
    "kubernetes_tekton_task",
    "kubernetes_tekton_cluster_task",
    "kubernetes_tekton_step_action",
)
def _tekton_task_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if resource_type.endswith("cluster_task"):
        label = "ClusterTask"
    elif resource_type.endswith("step_action"):
        label = "StepAction"
    else:
        label = "Task"
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                f"__TOOL__ will delete this Tekton {label}; future Runs may fail to resolve it.",
            )
        ]
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    steps = spec.get("steps", [])
    sidecars = spec.get("sidecars", [])
    executable = bool(steps) or (
        resource_type.endswith("step_action")
        and any(spec.get(key) is not None for key in ("image", "script", "command", "args"))
    )
    findings = ["execute container steps and commands"] if executable else []
    if sidecars:
        findings.append("run sidecar containers alongside build steps")
    if _tekton_mutable_images(spec):
        findings.append("use one or more container images not pinned by digest")
    if _tekton_has_secret_reference(spec):
        findings.append("consume Secret-backed credentials or values")
    if _tekton_has_privileged_pod_settings(spec):
        findings.append("request privileged, root, host, or container-runtime access")
    findings.extend(_tekton_workspace_findings(spec))
    if findings:
        return [
            RuleResult(
                "dangerous",
                (
                    f"This Tekton {label} can {'; '.join(dict.fromkeys(findings))}. "
                    "Review scripts, commands, image provenance, workspaces, network access, "
                    "results, and least-privilege execution before use."
                ),
            )
        ]
    return [
        RuleResult(
            "review",
            f"__TOOL__ will change a Tekton {label}; review its resolved execution spec.",
        )
    ]


@register_rule("kubernetes_tekton_pipeline")
def _tekton_pipeline_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                "__TOOL__ will delete this Tekton Pipeline; future PipelineRuns may fail.",
            )
        ]
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = _tekton_reference_findings(spec)
    embedded = any(
        isinstance(item, dict) and item.get("taskSpec") is not None
        for item in _tekton_walk(spec)
    )
    if embedded:
        findings.append("embed executable Task specifications directly")
    if _tekton_has_secret_reference(spec):
        findings.append("reference Secret-backed pipeline inputs")
    if findings:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Tekton Pipeline can "
                    f"{'; '.join(dict.fromkeys(findings))}. Review task provenance, "
                    "parameter flow, workspace access, finally tasks, and failure behavior."
                ),
            )
        ]
    return [
        RuleResult(
            "review",
            (
                "__TOOL__ will change a Tekton Pipeline. Review task references, ordering, "
                "when expressions, params, workspaces, results, finally tasks, and timeouts."
            ),
        )
    ]


_TEKTON_RUN_TYPES = (
    "kubernetes_tekton_task_run",
    "kubernetes_tekton_pipeline_run",
    "kubernetes_tekton_run",
    "kubernetes_tekton_custom_run",
)


@register_rule(*_TEKTON_RUN_TYPES)
def _tekton_run_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("kubernetes_tekton_").replace("_", " ").title()
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                f"__TOOL__ will delete this Tekton {label}, cancelling or removing run state.",
            )
        ]
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["start or alter executable workload on the cluster"]
    if spec.get("serviceAccountName") or spec.get("taskRunTemplate"):
        findings.append("execute with a selected Kubernetes ServiceAccount")
    findings.extend(_tekton_reference_findings(spec))
    findings.extend(_tekton_workspace_findings(spec))
    if _tekton_has_secret_reference(spec):
        findings.append("consume Secret-backed credentials or parameters")
    if _tekton_has_privileged_pod_settings(spec):
        findings.append("request privileged, root, host, or container-runtime access")
    if _tekton_mutable_images(spec):
        findings.append("execute one or more images not pinned by digest")
    return [
        RuleResult(
            "dangerous",
            (
                f"This Tekton {label} can {'; '.join(dict.fromkeys(findings))}. Review "
                "resolved definitions, identity, inputs, workspaces, pod templates, "
                "timeouts, cancellation, and emitted results before execution."
            ),
        )
    ]


@register_rule("kubernetes_tekton_event_listener")
def _tekton_event_listener_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                "__TOOL__ will delete this Tekton EventListener and stop event ingestion.",
            )
        ]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Tekton EventListener exposes event-driven pipeline ingress. "
                    "Review service account, trigger bindings/templates, interceptors, "
                    "webhook authentication, payload validation, network exposure, and "
                    "denial-of-service controls."
                ),
            )
        ]
    return []


@register_rule("kubernetes_tekton_trigger_template")
def _tekton_trigger_template_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                "__TOOL__ will delete this TriggerTemplate and break dependent triggers.",
            )
        ]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Tekton TriggerTemplate creates Kubernetes resources from event "
                    "parameters. Review every resourceTemplate, namespace, ServiceAccount, "
                    "untrusted substitution, Run identity, and admission boundary."
                ),
            )
        ]
    return []


@register_rule("kubernetes_tekton_trigger")
def _tekton_trigger_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [RuleResult("irreversible", "__TOOL__ will delete this Tekton Trigger.")]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Tekton Trigger connects event payloads, interceptors, bindings, "
                    "templates, and a ServiceAccount. Review authentication, filtering, "
                    "credential scope, and generated resources."
                ),
            )
        ]
    return []


@register_rule(
    "kubernetes_tekton_trigger_binding",
    "kubernetes_tekton_cluster_trigger_binding",
)
def _tekton_trigger_binding_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                "__TOOL__ will delete this Tekton TriggerBinding and break dependent triggers.",
            )
        ]
    if {"create", "update"} & action_set:
        scope = "cluster-wide " if "cluster" in resource_type else ""
        return [
            RuleResult(
                "review",
                (
                    f"__TOOL__ will change a {scope}Tekton TriggerBinding. Review event "
                    "payload/header extraction, defaults, namespace scope, and downstream "
                    "parameter validation."
                ),
            )
        ]
    return []


@register_rule("kubernetes_tekton_pipeline_resource")
def _tekton_pipeline_resource_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                "__TOOL__ will delete this deprecated Tekton PipelineResource.",
            )
        ]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This deprecated Tekton PipelineResource can identify external Git, "
                    "image, storage, or cluster inputs and outputs. Migrate to Tasks and "
                    "Workspaces; review source trust, revisions, credentials, and consumers."
                ),
            )
        ]
    return []


@register_rule("kubernetes_tekton_cluster_interceptor")
def _tekton_cluster_interceptor_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                "__TOOL__ will delete this cluster-scoped Tekton interceptor.",
            )
        ]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Tekton ClusterInterceptor lets EventListeners invoke a "
                    "cluster-scoped webhook extension. Review endpoint identity, TLS, "
                    "payload handling, namespace consumers, availability, and RBAC."
                ),
            )
        ]
    return []


@register_rule("kubernetes_tekton_resolution_request")
def _tekton_resolution_request_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                "__TOOL__ will delete this Tekton ResolutionRequest and its resolver state.",
            )
        ]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Tekton ResolutionRequest asks an installed resolver to fetch "
                    "executable pipeline content. Review resolver policy, source, immutable "
                    "revision or digest, credentials, integrity, caching, and result consumers."
                ),
            )
        ]
    return []
