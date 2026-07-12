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
        isinstance(item, dict) and item.get("taskSpec") is not None for item in _tekton_walk(spec)
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


def _controller_walk(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _controller_walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _controller_walk(child)


def _controller_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _controller_items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _controller_dicts(value: Any):
    return (item for item in _controller_walk(value) if isinstance(item, dict))


def _controller_has_key(value: Any, *keys: str) -> bool:
    lowered = {key.lower() for key in keys}
    return any(
        any(str(key).lower() in lowered for key in item) for item in _controller_dicts(value)
    )


def _controller_secret_refs(value: Any) -> bool:
    return _controller_has_key(
        value,
        "secretKeyRef",
        "secretRef",
        "secretName",
        "privateKeySecretRef",
        "certificateRefs",
        "authSecretRef",
    )


def _controller_mutable_images(value: Any) -> bool:
    for item in _controller_dicts(value):
        image = item.get("image")
        if isinstance(image, str) and "@sha256:" not in image.lower():
            return True
    return False


def _controller_privileged(value: Any) -> bool:
    for item in _controller_dicts(value):
        if item.get("privileged") is True or item.get("hostNetwork") is True:
            return True
        if item.get("hostPID") is True or item.get("hostIPC") is True:
            return True
        if item.get("allowPrivilegeEscalation") is True:
            return True
        if item.get("runAsNonRoot") is False:
            return True
        capabilities = item.get("capabilities")
        if isinstance(capabilities, dict) and capabilities.get("add"):
            return True
    return False


def _controller_delete(label: str, action_set: set[str]) -> list[RuleResult] | None:
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                f"__TOOL__ will delete this {label} and remove its controller-managed state.",
            )
        ]
    return None


@register_rule(
    "kubernetes_argo_workflow",
    "kubernetes_argo_workflow_template",
    "kubernetes_argo_cluster_workflow_template",
    "kubernetes_argo_cron_workflow",
    "kubernetes_argo_workflow_task_set",
)
def _argo_workflow_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("kubernetes_argo_").replace("_", " ").title()
    deleted = _controller_delete(f"Argo {label}", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["define or start executable workflow tasks"]
    if spec.get("serviceAccountName") or _controller_has_key(spec, "serviceAccountName"):
        findings.append("run with a selected Kubernetes ServiceAccount")
    if spec.get("automountServiceAccountToken") is not False:
        findings.append("may mount a Kubernetes API token into workflow pods")
    if _controller_mutable_images(spec):
        findings.append("execute container images not pinned by digest")
    if _controller_privileged(spec) or spec.get("podSpecPatch"):
        findings.append("alter pod security, host, or runtime settings")
    if _controller_secret_refs(spec):
        findings.append("consume Secret-backed credentials or artifacts")
    if _controller_has_key(spec, "script", "resource", "http", "plugin", "containerSet"):
        findings.append("run scripts, mutate Kubernetes resources, or call external services")
    if spec.get("workflowTemplateRef") or _controller_has_key(spec, "templateRef"):
        findings.append("execute reusable templates resolved from cluster state")
    return [
        RuleResult(
            "dangerous",
            (
                f"This Argo {label} can {'; '.join(dict.fromkeys(findings))}. Review "
                "resolved templates, identity, parameters, artifacts, synchronization, "
                "pod GC, exit handlers, retries, and controller restrictions."
            ),
        )
    ]


@register_rule("kubernetes_argo_workflow_event_binding")
def _argo_workflow_event_binding_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Argo WorkflowEventBinding", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This Argo WorkflowEventBinding turns accepted event payloads into "
                    "Workflow submissions. Review selector scope, payload-to-parameter "
                    "mapping, referenced template, submit identity, and API authentication."
                ),
            )
        ]
    return []


@register_rule("kubernetes_argo_event_source")
def _argo_event_source_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Argo EventSource", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["ingest events from webhooks, brokers, cloud APIs, or Kubernetes resources"]
    if _controller_secret_refs(spec):
        findings.append("use Secret-backed broker or cloud credentials")
    if _controller_has_key(spec, "serviceAccountName"):
        findings.append("watch resources with a selected ServiceAccount")
    if any(item.get("insecureSkipVerify") is True for item in _controller_dicts(spec)):
        findings.append("disable TLS peer verification")
    return [
        RuleResult(
            "dangerous",
            (
                f"This Argo EventSource can {'; '.join(findings)}. Review endpoint exposure, "
                "authentication, TLS, filters, payload limits, credential scope, and EventBus."
            ),
        )
    ]


@register_rule("kubernetes_argo_sensor")
def _argo_sensor_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Argo Sensor", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        spec = _desired_spec(change)
        findings = ["turn untrusted event data into external or Kubernetes actions"]
        if _controller_has_key(spec, "serviceAccountName"):
            findings.append("execute resource/workflow triggers with a selected ServiceAccount")
        if _controller_secret_refs(spec):
            findings.append("use Secret-backed trigger credentials")
        if _controller_has_key(spec, "parameters", "payload"):
            findings.append("substitute event payload fields into trigger destinations")
        return [
            RuleResult(
                "dangerous",
                (
                    f"This Argo Sensor can {'; '.join(findings)}. Review dependency filters, "
                    "conditions, trigger templates, retries, rate limits, delivery semantics, "
                    "dead-letter behavior, and least-privilege identity."
                ),
            )
        ]
    return []


@register_rule("kubernetes_argo_event_bus")
def _argo_event_bus_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Argo EventBus", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        spec = _desired_spec(change)
        findings = ["change the shared event transport used by EventSources and Sensors"]
        if _controller_secret_refs(spec):
            findings.append("use Secret-backed transport authentication or TLS")
        if _controller_has_key(spec, "persistence", "volumeClaimTemplate"):
            findings.append("persist event and delivery state")
        return [
            RuleResult(
                "dangerous",
                f"This Argo EventBus can {'; '.join(findings)}. Review NATS/Kafka "
                "security, durability, topic scope, availability, and migration impact.",
            )
        ]
    return []


@register_rule("kubernetes_gateway_class")
def _gateway_class_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("GatewayClass", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This GatewayClass selects a cluster gateway controller and optional "
                    "implementation-specific parameters. Review controller trust, scope, "
                    "supported features, infrastructure ownership, and class acceptance."
                ),
            )
        ]
    return []


@register_rule("kubernetes_gateway", "kubernetes_gateway_listener_set")
def _gateway_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = "ListenerSet" if resource_type.endswith("listener_set") else "Gateway"
    deleted = _controller_delete(label, action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["change externally or internally reachable network listeners"]
    listeners = [
        item for item in _controller_items(spec.get("listeners")) if isinstance(item, dict)
    ]
    if any(
        str(item.get("protocol", "HTTP")).upper() in {"HTTP", "TCP", "UDP"} for item in listeners
    ):
        findings.append("expose plaintext or unauthenticated transport listeners")
    if any(not item.get("hostname") or item.get("hostname") == "*" for item in listeners):
        findings.append("accept listener traffic without a specific hostname")
    if any(
        _controller_mapping(_controller_mapping(item.get("allowedRoutes")).get("namespaces")).get(
            "from"
        )
        == "All"
        for item in listeners
    ):
        findings.append("allow Routes from every namespace")
    if _controller_secret_refs(spec):
        findings.append("terminate TLS with referenced certificate Secrets")
    return [
        RuleResult(
            "dangerous",
            f"This {label} can {'; '.join(findings)}. Review addresses, TLS mode, "
            "route attachment, namespace trust, implementation parameters, and status "
            "before rollout.",
        )
    ]


@register_rule(
    "kubernetes_gateway_http_route",
    "kubernetes_gateway_grpc_route",
    "kubernetes_gateway_tls_route",
    "kubernetes_gateway_tcp_route",
    "kubernetes_gateway_udp_route",
)
def _gateway_route_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("kubernetes_gateway_").replace("_", " ").upper()
    deleted = _controller_delete(label, action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["change traffic matching and backend forwarding"]
    if not spec.get("hostnames") or "*" in _controller_items(spec.get("hostnames")):
        findings.append("match traffic without a specific hostname")
    refs = [
        item
        for item in _controller_dicts(spec)
        if any(key in item for key in ("backendRefs", "backendRef", "parentRefs"))
    ]
    if any(_controller_has_key(item, "namespace") for item in refs):
        findings.append("reference gateways or backends across namespace boundaries")
    filter_types = {
        str(item.get("type"))
        for item in _controller_dicts(spec)
        if item.get("type")
        in {
            "ExternalAuth",
            "RequestHeaderModifier",
            "RequestMirror",
            "RequestRedirect",
            "ResponseHeaderModifier",
            "URLRewrite",
        }
    }
    if filter_types:
        findings.append(f"apply traffic filters: {', '.join(sorted(filter_types))}")
    return [
        RuleResult(
            "dangerous",
            f"This Gateway API {label} can {'; '.join(findings)}. Review parent "
            "attachment, ReferenceGrants, filters, backend kinds/ports/weights, timeouts, "
            "retries, and controller conformance.",
        )
    ]


@register_rule("kubernetes_gateway_reference_grant")
def _gateway_reference_grant_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Gateway API ReferenceGrant", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This ReferenceGrant authorizes cross-namespace object references. "
                    "Review every source group/kind/namespace and destination group/kind/name "
                    "for confused-deputy, Secret, and backend access risks."
                ),
            )
        ]
    return []


@register_rule("kubernetes_gateway_backend_tls_policy")
def _gateway_backend_tls_policy_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Gateway API BackendTLSPolicy", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This BackendTLSPolicy changes how a Gateway authenticates backend TLS. "
                    "Review targetRef, hostname validation, CA sources, system trust, "
                    "cross-namespace references, and implementation support."
                ),
            )
        ]
    return []


@register_rule("kubernetes_cert_manager_certificate")
def _cert_manager_certificate_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("cert-manager Certificate", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["issue and store a private key and signed certificate in a Secret"]
    dns_names = [str(name) for name in _controller_items(spec.get("dnsNames"))]
    if any(name.startswith("*.") for name in dns_names):
        findings.append("request a wildcard DNS certificate")
    if spec.get("isCA") is True or any(
        usage in {"cert sign", "crl sign"} for usage in _controller_items(spec.get("usages"))
    ):
        findings.append("create a certificate capable of signing other certificates")
    if _controller_mapping(spec.get("privateKey")).get("rotationPolicy") == "Never":
        findings.append("reuse the private key across certificate renewals")
    if _controller_mapping(spec.get("issuerRef")).get("kind") == "ClusterIssuer":
        findings.append("use a cluster-scoped signing authority")
    return [
        RuleResult(
            "dangerous",
            f"This cert-manager Certificate can {'; '.join(findings)}. Review names, "
            "usages, issuer, key algorithm/size/rotation, duration, renewal, secret "
            "ownership, and approval policy.",
        )
    ]


@register_rule(
    "kubernetes_cert_manager_issuer",
    "kubernetes_cert_manager_cluster_issuer",
)
def _cert_manager_issuer_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    cluster = resource_type.endswith("cluster_issuer")
    label = "ClusterIssuer" if cluster else "Issuer"
    deleted = _controller_delete(f"cert-manager {label}", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["configure a certificate signing authority"]
    if cluster:
        findings.append("make the authority usable across namespaces")
    if spec.get("selfSigned") is not None or spec.get("ca") is not None:
        findings.append("trust a self-signed or Secret-backed CA key")
    acme = _controller_mapping(spec.get("acme"))
    if acme:
        findings.append("register an ACME account and solve domain-control challenges")
        if any(
            "dns01" in solver
            for solver in _controller_items(acme.get("solvers"))
            if isinstance(solver, dict)
        ):
            findings.append("grant DNS provider access for DNS01 records")
        if any(
            _cert_manager_unscoped_http01(solver)
            for solver in _controller_items(acme.get("solvers"))
            if isinstance(solver, dict)
        ):
            findings.append("let all installed ingress controllers serve an HTTP01 challenge")
    if _controller_secret_refs(spec):
        findings.append("use Secret-backed issuer credentials or account keys")
    return [
        RuleResult(
            "dangerous",
            f"This cert-manager {label} can {'; '.join(findings)}. Review scope, "
            "credential access, server/CA trust, solver selectors, name constraints, and "
            "request approval policy.",
        )
    ]


def _cert_manager_unscoped_http01(solver: dict[str, Any]) -> bool:
    http01 = _controller_mapping(solver.get("http01"))
    if "ingress" not in http01:
        return False
    ingress = _controller_mapping(http01.get("ingress"))
    return not any(key in ingress for key in ("class", "ingressClassName", "name"))


@register_rule("kubernetes_cert_manager_certificate_request")
def _cert_manager_request_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("cert-manager CertificateRequest", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This CertificateRequest asks an issuer to sign a CSR. Review requester "
                    "identity, approval/denial conditions, issuer scope, requested names and "
                    "usages, CSR integrity, and approver-policy enforcement."
                ),
            )
        ]
    return []


@register_rule(
    "kubernetes_cert_manager_acme_order",
    "kubernetes_cert_manager_acme_challenge",
)
def _cert_manager_acme_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = "ACME Challenge" if resource_type.endswith("challenge") else "ACME Order"
    deleted = _controller_delete(f"cert-manager {label}", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                f"This cert-manager {label} changes active certificate issuance state. "
                "Review requested identifiers, authorization URL, solver configuration, "
                "DNS/ingress mutations, and controller ownership.",
            )
        ]
    return []


@register_rule("kubernetes_cert_manager_trust_bundle")
def _cert_manager_bundle_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("trust-manager Bundle", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This trust-manager Bundle distributes trusted CA certificates across "
                    "workloads or namespaces. Review every source, default-CA package pin, "
                    "target kind/key/selector, namespace scope, and CA rotation overlap."
                ),
            )
        ]
    return []


@register_rule(
    "kubernetes_external_secrets_secret_store",
    "kubernetes_external_secrets_cluster_secret_store",
)
def _external_secrets_store_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    cluster = resource_type.endswith("cluster_secret_store")
    label = "ClusterSecretStore" if cluster else "SecretStore"
    deleted = _controller_delete(f"External Secrets {label}", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["authorize access to an external secret backend"]
    if cluster:
        findings.append("make the backend selectable across namespaces")
        if not spec.get("conditions"):
            findings.append("set no namespace conditions on cluster-wide use")
    if _controller_secret_refs(spec):
        findings.append("use Kubernetes Secrets for backend authentication")
    if _controller_has_key(spec, "serviceAccountRef"):
        findings.append("mint or use a Kubernetes ServiceAccount identity")
    return [
        RuleResult(
            "dangerous",
            f"This External Secrets {label} can {'; '.join(findings)}. Review provider "
            "endpoint, auth scope, controller class, namespace conditions, retry/refresh "
            "behavior, and backend maintenance status.",
        )
    ]


@register_rule(
    "kubernetes_external_secrets_external_secret",
    "kubernetes_external_secrets_cluster_external_secret",
)
def _external_secret_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    cluster = resource_type.endswith("cluster_external_secret")
    label = "ClusterExternalSecret" if cluster else "ExternalSecret"
    deleted = _controller_delete(f"External Secrets {label}", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["read external values and write Kubernetes Secrets"]
    if cluster:
        findings.append("replicate secrets into selected namespaces")
    if spec.get("dataFrom") or _controller_has_key(spec, "find", "extract"):
        findings.append("bulk import or discover remote secret values")
    target = _controller_mapping(spec.get("target"))
    if target.get("template") or target.get("templateFrom"):
        findings.append("render secret data through templates or ConfigMaps")
    if _controller_mapping(spec.get("secretStoreRef")).get("kind") == "ClusterSecretStore":
        findings.append("use a cluster-scoped secret backend identity")
    if str(spec.get("refreshPolicy", "Periodic")) == "Periodic":
        findings.append("periodically overwrite the target from remote state")
    return [
        RuleResult(
            "dangerous",
            f"This External Secrets {label} can {'; '.join(findings)}. Review remote "
            "keys/properties, store scope, target ownership/type, refresh and "
            "deletion/creation policies, templates, namespace selectors, and consumers.",
        )
    ]


@register_rule(
    "kubernetes_external_secrets_push_secret",
    "kubernetes_external_secrets_cluster_push_secret",
)
def _external_secrets_push_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    cluster = resource_type.endswith("cluster_push_secret")
    label = "ClusterPushSecret" if cluster else "PushSecret"
    deleted = _controller_delete(f"External Secrets {label}", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    f"This External Secrets {label} exports Kubernetes Secret data to one "
                    "or more remote stores. Review source selector, namespace scope, store "
                    "selection, key rewrites, template output, update/deletion policy, bulk "
                    "dataTo matching, and exfiltration boundaries."
                ),
            )
        ]
    return []


@register_rule("kubernetes_external_secrets_generator")
def _external_secrets_generator_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("External Secrets generator", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "This External Secrets generator creates dynamic credentials, tokens, "
                    "keys, passwords, or webhook-derived values. Review generator scope, "
                    "provider identity, endpoint/TLS, output lifetime, entropy, consumers, "
                    "and cluster-wide reuse."
                ),
            )
        ]
    return []


def _desired_metadata(change: dict[str, Any]) -> dict[str, Any]:
    after = change.get("after", {})
    if not isinstance(after, dict):
        return {}
    metadata = after.get("metadata", {})
    return metadata if isinstance(metadata, dict) else {}


def _contains_value(value: Any, *expected: str) -> bool:
    wanted = {item.lower() for item in expected}
    return any(isinstance(item, str) and item.lower() in wanted for item in _controller_walk(value))


def _integer_or_default(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@register_rule(
    "kubernetes_istio_virtual_service",
    "kubernetes_istio_destination_rule",
    "kubernetes_istio_gateway",
    "kubernetes_istio_service_entry",
    "kubernetes_istio_sidecar",
    "kubernetes_istio_workload_entry",
    "kubernetes_istio_workload_group",
    "kubernetes_istio_proxy_config",
)
def _istio_networking_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("kubernetes_istio_").replace("_", " ").title()
    deleted = _controller_delete(f"Istio {label}", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["change service-mesh traffic reachability or identity"]
    if resource_type.endswith("virtual_service"):
        if _controller_has_key(spec, "mirror", "fault", "rewrite", "redirect", "delegate"):
            findings.append("mirror, fault, rewrite, redirect, or delegate live traffic")
        if not spec.get("hosts") or "*" in _controller_items(spec.get("hosts")):
            findings.append("match traffic without a specific host")
    elif resource_type.endswith("destination_rule"):
        if _contains_value(spec.get("trafficPolicy"), "DISABLE", "SIMPLE"):
            findings.append("disable mutual TLS or use server-only TLS")
        if _controller_has_key(spec, "loadBalancer", "outlierDetection", "connectionPool"):
            findings.append("change load balancing, ejection, or connection limits")
    elif resource_type.endswith("gateway"):
        if _contains_value(spec, "HTTP", "PASSTHROUGH", "AUTO_PASSTHROUGH"):
            findings.append("expose plaintext or pass-through listeners")
        if any(
            "*" in _controller_items(item.get("hosts"))
            for item in _controller_dicts(spec)
            if "hosts" in item
        ):
            findings.append("accept wildcard hosts")
    elif resource_type.endswith("service_entry"):
        if spec.get("location") == "MESH_EXTERNAL":
            findings.append("add external endpoints to the mesh service registry")
        if spec.get("resolution") == "NONE":
            findings.append("allow traffic by port without DNS or endpoint resolution")
        if not spec.get("exportTo") or "*" in _controller_items(spec.get("exportTo")):
            findings.append("export the service entry to all namespaces")
        if any(str(host).startswith("*.") for host in _controller_items(spec.get("hosts"))):
            findings.append("register wildcard external hosts")
    elif resource_type.endswith("sidecar"):
        if _contains_value(spec.get("egress"), "*/*"):
            findings.append("allow sidecar egress to every namespace and host")
        if _contains_value(spec.get("outboundTrafficPolicy"), "ALLOW_ANY"):
            findings.append("allow traffic to destinations absent from the mesh registry")
    elif resource_type.endswith(("workload_entry", "workload_group")):
        findings.append("attach VM or non-Kubernetes workload endpoints and service accounts")
    if _controller_secret_refs(spec):
        findings.append("use certificate or credential Secrets")
    return [
        RuleResult(
            "dangerous",
            f"This Istio {label} can {'; '.join(findings)}. Review selectors, "
            "namespace export, hosts, ports, TLS/SAN validation, routes, retries, "
            "failover, and proxy/controller compatibility.",
        )
    ]


@register_rule("kubernetes_istio_envoy_filter", "kubernetes_istio_wasm_plugin")
def _istio_extension_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = "WasmPlugin" if resource_type.endswith("wasm_plugin") else "EnvoyFilter"
    deleted = _controller_delete(f"Istio {label}", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        spec = _desired_spec(change)
        findings = ["inject custom code or low-level proxy configuration into mesh data paths"]
        if _controller_mutable_images(spec) or (
            isinstance(spec.get("url"), str) and "@sha256:" not in spec["url"]
        ):
            findings.append("load an extension artifact not pinned by digest")
        if _controller_secret_refs(spec):
            findings.append("provide Secret-backed pull or plugin configuration")
        return [
            RuleResult(
                "dangerous",
                f"This Istio {label} can {'; '.join(findings)}. Review patch context/order, "
                "workload scope, ABI/runtime, artifact integrity, capabilities, failure "
                "mode, and proxy-version compatibility.",
            )
        ]
    return []


@register_rule("kubernetes_istio_authorization_policy")
def _istio_authorization_policy_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Istio AuthorizationPolicy", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        spec = _desired_spec(change)
        action = str(spec.get("action", "ALLOW"))
        findings = [f"change mesh request authorization with action {action}"]
        if action == "CUSTOM":
            findings.append("delegate decisions to an extension provider")
        if not spec.get("selector") and not spec.get("targetRefs"):
            findings.append("apply broadly within the policy namespace or mesh root")
        if _contains_value(spec.get("rules"), "*"):
            findings.append("use wildcard principals, namespaces, methods, paths, or hosts")
        return [
            RuleResult(
                "dangerous",
                f"This Istio AuthorizationPolicy can {'; '.join(findings)}. Review target "
                "scope, rule normalization, source identity/IP, operations, conditions, "
                "dry-run/audit use, and deny-by-default interactions.",
            )
        ]
    return []


@register_rule(
    "kubernetes_istio_peer_authentication",
    "kubernetes_istio_request_authentication",
)
def _istio_authentication_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    request = resource_type.endswith("request_authentication")
    label = "RequestAuthentication" if request else "PeerAuthentication"
    deleted = _controller_delete(f"Istio {label}", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["change workload authentication requirements"]
    if request:
        if _controller_has_key(spec, "jwksUri"):
            findings.append("fetch JWT verification keys from external endpoints")
        if any(item.get("forwardOriginalToken") is True for item in _controller_dicts(spec)):
            findings.append("forward original bearer tokens to workloads")
        if _controller_has_key(spec, "outputClaimToHeaders"):
            findings.append("copy JWT claims into request headers")
    elif _contains_value(spec, "DISABLE", "PERMISSIVE"):
        findings.append("permit plaintext or non-mutually-authenticated workload traffic")
    return [
        RuleResult(
            "dangerous",
            f"This Istio {label} can {'; '.join(findings)}. Review selector/target scope, "
            "trust domains, issuer/audience, key sources, token forwarding, mTLS mode, "
            "port overrides, and AuthorizationPolicy coupling.",
        )
    ]


@register_rule("kubernetes_istio_telemetry")
def _istio_telemetry_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Istio Telemetry", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        spec = _desired_spec(change)
        disabled = any(item.get("disabled") is True for item in _controller_dicts(spec))
        return [
            RuleResult(
                "dangerous" if disabled else "review",
                (
                    "This Istio Telemetry policy disables selected mesh telemetry providers."
                    if disabled
                    else "__TOOL__ will change mesh metrics, access logs, or tracing providers."
                )
                + " Review workload scope, provider selection, filters, sampling, tag "
                "overrides, sensitive-data capture, and observability gaps.",
            )
        ]
    return []


@register_rule("kubernetes_kyverno_cluster_policy", "kubernetes_kyverno_policy")
def _kyverno_legacy_policy_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    cluster = resource_type.endswith("cluster_policy")
    label = "ClusterPolicy" if cluster else "Policy"
    deleted = _controller_delete(f"Kyverno {label}", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["evaluate Kubernetes admission requests"]
    if cluster:
        findings.append("apply policy across cluster namespaces")
    if _controller_has_key(spec, "mutate", "patchStrategicMerge", "patchesJson6902"):
        findings.append("mutate matching resources before validation")
    if _controller_has_key(spec, "generate", "clone", "cloneList"):
        findings.append("create, clone, synchronize, or mutate existing resources")
    if _controller_has_key(spec, "verifyImages"):
        findings.append("verify or mutate container image references and attestations")
    if str(spec.get("validationFailureAction", "Audit")) != "Enforce":
        findings.append("audit validation failures instead of blocking them")
    return [
        RuleResult(
            "dangerous",
            f"This Kyverno {label} can {'; '.join(findings)}. Review match/exclude scope, "
            "failure policy, background behavior, context/API calls, preconditions, "
            "foreach, mutation order, generated ownership, and policy exceptions.",
        )
    ]


@register_rule(
    "kubernetes_kyverno_validating_policy",
    "kubernetes_kyverno_namespaced_validating_policy",
    "kubernetes_kyverno_mutating_policy",
    "kubernetes_kyverno_namespaced_mutating_policy",
    "kubernetes_kyverno_generating_policy",
    "kubernetes_kyverno_namespaced_generating_policy",
    "kubernetes_kyverno_deleting_policy",
    "kubernetes_kyverno_namespaced_deleting_policy",
    "kubernetes_kyverno_image_validating_policy",
    "kubernetes_kyverno_namespaced_image_validating_policy",
)
def _kyverno_cel_policy_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("kubernetes_kyverno_").replace("_", " ").title()
    deleted = _controller_delete(f"Kyverno {label}", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        mutating = any(word in resource_type for word in ("mutating", "generating", "deleting"))
        image = "image_validating" in resource_type
        effect = (
            "mutate, generate, or delete matching resources"
            if mutating
            else "verify image signatures/attestations and optionally rewrite image references"
            if image
            else "allow, deny, warn, or audit matching admission requests"
        )
        return [
            RuleResult(
                "dangerous",
                f"This Kyverno {label} can {effect}. Review cluster/namespaced scope, match "
                "constraints, CEL expressions, variables/context, failure policy, webhook "
                "timeout, background actions, credentials, and exceptions.",
            )
        ]
    return []


@register_rule(
    "kubernetes_kyverno_cleanup_policy",
    "kubernetes_kyverno_cluster_cleanup_policy",
)
def _kyverno_cleanup_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Kyverno cleanup policy", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                "This Kyverno cleanup policy deletes matching resources on a schedule. "
                "Review match/exclude scope, conditions, schedule, propagation, cluster "
                "scope, and recovery evidence.",
            )
        ]
    return []


@register_rule("kubernetes_kyverno_policy_exception")
def _kyverno_exception_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Kyverno PolicyException", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                "This PolicyException bypasses selected Kyverno policy rules for matching "
                "resources. Review namespace, subjects, policy/rule names, match scope, "
                "duration, approvals, and exception governance.",
            )
        ]
    return []


@register_rule("kubernetes_gatekeeper_constraint_template")
def _gatekeeper_template_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Gatekeeper ConstraintTemplate", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                "This ConstraintTemplate installs Rego or CEL admission policy code and a "
                "new Constraint API. Review code, targets, schema, external data, library "
                "dependencies, failure behavior, and every instantiated Constraint.",
            )
        ]
    return []


@register_rule("kubernetes_gatekeeper_constraint")
def _gatekeeper_constraint_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Gatekeeper Constraint", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        spec = _desired_spec(change)
        enforcement = str(spec.get("enforcementAction", "deny")).lower()
        risk = "review" if enforcement in {"dryrun", "warn"} else "dangerous"
        return [
            RuleResult(
                risk,
                "This Gatekeeper Constraint applies a template with "
                f"enforcementAction={enforcement}. Review match scope, excluded namespaces, "
                "parameters, scoped enforcement points, audit behavior, and template "
                "provenance.",
            )
        ]
    return []


@register_rule(
    "kubernetes_gatekeeper_assign",
    "kubernetes_gatekeeper_assign_metadata",
    "kubernetes_gatekeeper_modify_set",
    "kubernetes_gatekeeper_assign_image",
)
def _gatekeeper_mutation_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("kubernetes_gatekeeper_").replace("_", " ").title()
    deleted = _controller_delete(f"Gatekeeper {label}", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        spec = _desired_spec(change)
        external = _controller_has_key(spec, "externalData")
        return [
            RuleResult(
                "dangerous",
                f"This Gatekeeper {label} mutates matching admission objects"
                + (" using an external data provider" if external else "")
                + ". Review applyTo/match scope, location, value source, path tests, "
                "mutation conflicts/order, provider failure policy, and validation "
                "interactions.",
            )
        ]
    return []


@register_rule(
    "kubernetes_gatekeeper_config",
    "kubernetes_gatekeeper_expansion_template",
    "kubernetes_gatekeeper_sync_set",
    "kubernetes_gatekeeper_external_data_provider",
)
def _gatekeeper_control_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("kubernetes_gatekeeper_").replace("_", " ").title()
    deleted = _controller_delete(f"Gatekeeper {label}", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                f"This Gatekeeper {label} changes policy-engine inventory, expansion, "
                "exclusion, or external-data behavior. Review cluster scope, synced data "
                "sensitivity, process exclusions, generated resources, provider "
                "endpoint/TLS, timeout/failure mode, and policy consumers.",
            )
        ]
    return []


@register_rule("kubernetes_keda_scaled_object")
def _keda_scaled_object_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("KEDA ScaledObject", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["let external metrics change workload replica count, including scale to zero"]
    if _integer_or_default(spec.get("maxReplicaCount", 100) or 100, 100) > 100:
        findings.append("allow more than 100 replicas")
    if spec.get("fallback"):
        findings.append("force a fallback replica count when scaler metrics fail")
    if _controller_has_key(spec, "authenticationRef"):
        findings.append("use referenced scaler credentials or pod identity")
    if _contains_value(spec, "external", "metrics-api"):
        findings.append("trust an external scaler or arbitrary metrics API")
    if any(
        str(item.get("unsafeSsl", "false")).lower() == "true" for item in _controller_dicts(spec)
    ):
        findings.append("disable TLS validation for a metric endpoint")
    return [
        RuleResult(
            "dangerous",
            f"This KEDA ScaledObject can {'; '.join(findings)}. Review target ownership, "
            "min/idle/max replicas, polling/cooldown, trigger endpoints/queries, HPA "
            "behavior, fallback, pause/transfer annotations, and deletion restoration.",
        )
    ]


@register_rule("kubernetes_keda_scaled_job")
def _keda_scaled_job_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("KEDA ScaledJob", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        spec = _desired_spec(change)
        findings = ["create executable Jobs in response to external metrics"]
        if _controller_mutable_images(spec):
            findings.append("run images not pinned by digest")
        if _controller_privileged(spec):
            findings.append("launch privileged or host-accessing job pods")
        if _controller_has_key(spec, "authenticationRef"):
            findings.append("use referenced scaler credentials")
        if (
            _contains_value(spec.get("rollout"), "default")
            or spec.get("rolloutStrategy") == "default"
        ):
            findings.append("terminate existing Jobs when the ScaledJob changes")
        return [
            RuleResult(
                "dangerous",
                f"This KEDA ScaledJob can {'; '.join(findings)}. Review job identity/code, "
                "secrets, triggers, replica/job-history limits, rollout propagation, "
                "scaling strategy, pending-job calculation, and duplicate processing.",
            )
        ]
    return []


@register_rule(
    "kubernetes_keda_trigger_authentication",
    "kubernetes_keda_cluster_trigger_authentication",
)
def _keda_authentication_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    cluster = resource_type.endswith("cluster_trigger_authentication")
    label = "ClusterTriggerAuthentication" if cluster else "TriggerAuthentication"
    deleted = _controller_delete(f"KEDA {label}", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        spec = _desired_spec(change)
        findings = ["provide credentials or workload identity to metric scalers"]
        if cluster:
            findings.append("make the identity reusable across namespaces")
        if _controller_secret_refs(spec) or _controller_has_key(spec, "secretTargetRef"):
            findings.append("read Kubernetes Secret values")
        if _controller_has_key(spec, "podIdentity", "serviceAccount"):
            findings.append("use cloud or Kubernetes workload identity")
        if _controller_has_key(spec, "hashiCorpVault", "azureKeyVault", "awsSecretManager"):
            findings.append("retrieve credentials from an external secret backend")
        return [
            RuleResult(
                "dangerous",
                f"This KEDA {label} can {'; '.join(findings)}. Review namespace scope, "
                "secret names/keys, environment sources, identity provider/role, Vault/Key "
                "Vault settings, token lifetime, and every referencing trigger.",
            )
        ]
    return []


@register_rule("kubernetes_keda_cloud_event_source")
def _keda_cloud_event_source_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("KEDA CloudEventSource", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "review",
                "__TOOL__ will change where KEDA emits autoscaling CloudEvents. Review "
                "destination URI, authentication/network policy, event metadata "
                "sensitivity, failure handling, and receiver trust.",
            )
        ]
    return []


@register_rule(
    "kubernetes_knative_service",
    "kubernetes_knative_configuration",
    "kubernetes_knative_revision",
)
def _knative_serving_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("kubernetes_knative_").replace("_", " ").title()
    deleted = _controller_delete(f"Knative {label}", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    metadata = _desired_metadata(change)
    annotations = _controller_mapping(metadata.get("annotations"))
    findings = ["deploy executable containers and create immutable revisions"]
    if _controller_mutable_images(spec):
        findings.append("run container images not pinned by digest")
    if _controller_privileged(spec):
        findings.append("request privileged or host-level pod settings")
    if _controller_secret_refs(spec):
        findings.append("consume Secret-backed environment, volumes, or image pulls")
    if _controller_has_key(spec, "serviceAccountName"):
        findings.append("run with a selected Kubernetes ServiceAccount")
    if (
        resource_type.endswith("service")
        and annotations.get("networking.knative.dev/visibility") != "cluster-local"
    ):
        findings.append("create a network Route that may be externally visible")
    if annotations.get("autoscaling.knative.dev/min-scale") == "0":
        findings.append("permit scale-to-zero cold starts")
    return [
        RuleResult(
            "dangerous",
            f"This Knative {label} can {'; '.join(findings)}. Review traffic visibility, "
            "revision rollout, image provenance, identity, pod security, concurrency, "
            "timeout, scale bounds/metrics, probes, volumes, and retained revisions.",
        )
    ]


@register_rule("kubernetes_knative_route")
def _knative_route_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Knative Route", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                "This Knative Route changes network exposure and weighted/tagged traffic "
                "across Revisions. Review visibility/domain, certificate/TLS, "
                "latestRevision usage, percentage splits, tag URLs, target readiness, and "
                "rollback.",
            )
        ]
    return []


@register_rule(
    "kubernetes_knative_broker",
    "kubernetes_knative_trigger",
    "kubernetes_knative_channel",
    "kubernetes_knative_in_memory_channel",
    "kubernetes_knative_subscription",
    "kubernetes_knative_sequence",
    "kubernetes_knative_parallel",
    "kubernetes_knative_event_source",
    "kubernetes_knative_event_transform",
    "kubernetes_knative_request_reply",
)
def _knative_eventing_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("kubernetes_knative_").replace("_", " ").title()
    deleted = _controller_delete(f"Knative {label}", action_set)
    if deleted is not None:
        return deleted
    if not ({"create", "update"} & action_set):
        return []
    spec = _desired_spec(change)
    findings = ["route CloudEvents between producers, brokers/channels, and sinks"]
    if _controller_has_key(spec, "uri"):
        findings.append("send events to an explicit network URI")
    if _controller_has_key(spec, "namespace"):
        findings.append("reference event components across namespaces")
    if _controller_has_key(spec, "deadLetterSink", "retry", "backoffPolicy"):
        findings.append("change retry and dead-letter delivery semantics")
    if resource_type.endswith("event_source"):
        findings.append("read external or Kubernetes event sources with controller identity")
    if resource_type.endswith("in_memory_channel"):
        findings.append("use a development-only in-memory delivery implementation")
    return [
        RuleResult(
            "dangerous",
            f"This Knative {label} can {'; '.join(findings)}. Review ingress authentication, "
            "broker/channel class, filters/transforms, sink identity, payload sensitivity, "
            "delivery guarantees, retries/DLQ, reply paths, and availability.",
        )
    ]


@register_rule("kubernetes_knative_event_policy")
def _knative_event_policy_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _controller_delete("Knative EventPolicy", action_set)
    if deleted is not None:
        return deleted
    if {"create", "update"} & action_set:
        spec = _desired_spec(change)
        broad = not spec.get("to")
        return [
            RuleResult(
                "dangerous",
                "This Knative EventPolicy changes which OIDC identities or sources may send events"
                + (" to every addressable resource in the namespace" if broad else "")
                + ". Review targets, subjects, OIDC issuer/audience, cross-namespace "
                "references, defaults, and enforcement status.",
            )
        ]
    return []
