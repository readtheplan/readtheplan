from __future__ import annotations

from typing import Any

from readtheplan.rules._shared import RuleResult, register_rule

# Exact resource catalog published by hashicorp/kubernetes v3.2.1. Keep this
# explicit so a provider release cannot silently introduce safe fallbacks.
KUBERNETES_PROVIDER_RESOURCES = frozenset(
    {
        "kubernetes_annotations",
        "kubernetes_api_service",
        "kubernetes_api_service_v1",
        "kubernetes_certificate_signing_request",
        "kubernetes_certificate_signing_request_v1",
        "kubernetes_cluster_role",
        "kubernetes_cluster_role_binding",
        "kubernetes_cluster_role_binding_v1",
        "kubernetes_cluster_role_v1",
        "kubernetes_config_map",
        "kubernetes_config_map_v1",
        "kubernetes_config_map_v1_data",
        "kubernetes_cron_job",
        "kubernetes_cron_job_v1",
        "kubernetes_csi_driver",
        "kubernetes_csi_driver_v1",
        "kubernetes_daemon_set_v1",
        "kubernetes_daemonset",
        "kubernetes_default_service_account",
        "kubernetes_default_service_account_v1",
        "kubernetes_deployment",
        "kubernetes_deployment_v1",
        "kubernetes_endpoint_slice_v1",
        "kubernetes_endpoints",
        "kubernetes_endpoints_v1",
        "kubernetes_env",
        "kubernetes_horizontal_pod_autoscaler",
        "kubernetes_horizontal_pod_autoscaler_v1",
        "kubernetes_horizontal_pod_autoscaler_v2",
        "kubernetes_horizontal_pod_autoscaler_v2beta2",
        "kubernetes_ingress",
        "kubernetes_ingress_class",
        "kubernetes_ingress_class_v1",
        "kubernetes_ingress_v1",
        "kubernetes_job",
        "kubernetes_job_v1",
        "kubernetes_labels",
        "kubernetes_limit_range",
        "kubernetes_limit_range_v1",
        "kubernetes_manifest",
        "kubernetes_mutating_webhook_configuration",
        "kubernetes_mutating_webhook_configuration_v1",
        "kubernetes_namespace",
        "kubernetes_namespace_v1",
        "kubernetes_network_policy",
        "kubernetes_network_policy_v1",
        "kubernetes_node_taint",
        "kubernetes_persistent_volume",
        "kubernetes_persistent_volume_claim",
        "kubernetes_persistent_volume_claim_v1",
        "kubernetes_persistent_volume_v1",
        "kubernetes_pod",
        "kubernetes_pod_disruption_budget",
        "kubernetes_pod_disruption_budget_v1",
        "kubernetes_pod_security_policy",
        "kubernetes_pod_security_policy_v1beta1",
        "kubernetes_pod_v1",
        "kubernetes_priority_class",
        "kubernetes_priority_class_v1",
        "kubernetes_replication_controller",
        "kubernetes_replication_controller_v1",
        "kubernetes_resource_quota",
        "kubernetes_resource_quota_v1",
        "kubernetes_role",
        "kubernetes_role_binding",
        "kubernetes_role_binding_v1",
        "kubernetes_role_v1",
        "kubernetes_runtime_class_v1",
        "kubernetes_secret",
        "kubernetes_secret_v1",
        "kubernetes_secret_v1_data",
        "kubernetes_service",
        "kubernetes_service_account",
        "kubernetes_service_account_v1",
        "kubernetes_service_v1",
        "kubernetes_stateful_set",
        "kubernetes_stateful_set_v1",
        "kubernetes_storage_class",
        "kubernetes_storage_class_v1",
        "kubernetes_token_request_v1",
        "kubernetes_validating_admission_policy",
        "kubernetes_validating_webhook_configuration",
        "kubernetes_validating_webhook_configuration_v1",
    }
)


_SPECIALIZED_RESOURCES = frozenset(
    {
        "kubernetes_cluster_role",
        "kubernetes_cluster_role_binding",
        "kubernetes_cluster_role_binding_v1",
        "kubernetes_cluster_role_v1",
        "kubernetes_deployment",
        "kubernetes_deployment_v1",
        "kubernetes_ingress",
        "kubernetes_ingress_v1",
        "kubernetes_namespace",
        "kubernetes_namespace_v1",
        "kubernetes_network_policy",
        "kubernetes_network_policy_v1",
        "kubernetes_role",
        "kubernetes_role_binding",
        "kubernetes_role_binding_v1",
        "kubernetes_role_v1",
        "kubernetes_secret",
        "kubernetes_secret_v1",
        "kubernetes_secret_v1_data",
        "kubernetes_service",
        "kubernetes_service_v1",
    }
)

_GENERIC_RESOURCES = tuple(sorted(KUBERNETES_PROVIDER_RESOURCES - _SPECIALIZED_RESOURCES))

_WORKLOAD_RESOURCES = {
    "kubernetes_cron_job",
    "kubernetes_cron_job_v1",
    "kubernetes_daemon_set_v1",
    "kubernetes_daemonset",
    "kubernetes_job",
    "kubernetes_job_v1",
    "kubernetes_pod",
    "kubernetes_pod_v1",
    "kubernetes_replication_controller",
    "kubernetes_replication_controller_v1",
    "kubernetes_stateful_set",
    "kubernetes_stateful_set_v1",
}

_SCALING_RESOURCES = {
    "kubernetes_horizontal_pod_autoscaler",
    "kubernetes_horizontal_pod_autoscaler_v1",
    "kubernetes_horizontal_pod_autoscaler_v2",
    "kubernetes_horizontal_pod_autoscaler_v2beta2",
}

_ADMISSION_RESOURCES = {
    "kubernetes_mutating_webhook_configuration",
    "kubernetes_mutating_webhook_configuration_v1",
    "kubernetes_pod_security_policy",
    "kubernetes_pod_security_policy_v1beta1",
    "kubernetes_validating_admission_policy",
    "kubernetes_validating_webhook_configuration",
    "kubernetes_validating_webhook_configuration_v1",
}

_STORAGE_RESOURCES = {
    "kubernetes_csi_driver",
    "kubernetes_csi_driver_v1",
    "kubernetes_persistent_volume",
    "kubernetes_persistent_volume_claim",
    "kubernetes_persistent_volume_claim_v1",
    "kubernetes_persistent_volume_v1",
    "kubernetes_storage_class",
    "kubernetes_storage_class_v1",
}

_NETWORK_RESOURCES = {
    "kubernetes_api_service",
    "kubernetes_api_service_v1",
    "kubernetes_endpoint_slice_v1",
    "kubernetes_endpoints",
    "kubernetes_endpoints_v1",
    "kubernetes_ingress_class",
    "kubernetes_ingress_class_v1",
}

_IDENTITY_RESOURCES = {
    "kubernetes_default_service_account",
    "kubernetes_default_service_account_v1",
    "kubernetes_service_account",
    "kubernetes_service_account_v1",
    "kubernetes_token_request_v1",
}

_CONFIG_RESOURCES = {
    "kubernetes_config_map",
    "kubernetes_config_map_v1",
    "kubernetes_config_map_v1_data",
}

_POLICY_RESOURCES = {
    "kubernetes_limit_range",
    "kubernetes_limit_range_v1",
    "kubernetes_pod_disruption_budget",
    "kubernetes_pod_disruption_budget_v1",
    "kubernetes_priority_class",
    "kubernetes_priority_class_v1",
    "kubernetes_resource_quota",
    "kubernetes_resource_quota_v1",
    "kubernetes_runtime_class_v1",
}


def _desired(change: dict[str, Any]) -> dict[str, Any]:
    after = change.get("after")
    return after if isinstance(after, dict) else {}


def _walk(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk(item)


def _values(value: Any, *keys: str) -> list[Any]:
    expected = set(keys)
    return [item for key, item in _walk(value) if key in expected]


def _any_true(value: Any, *keys: str) -> bool:
    return any(item is True for item in _values(value, *keys))


def _contains_text(value: Any, *needles: str) -> bool:
    lowered = tuple(needle.lower() for needle in needles)
    return any(
        (isinstance(key, str) and any(needle in key.lower() for needle in lowered))
        or (isinstance(item, str) and any(needle in item.lower() for needle in lowered))
        for key, item in _walk(value)
    )


def _label(resource_type: str) -> str:
    label = resource_type.removeprefix("kubernetes_")
    for suffix in ("_v2beta2", "_v1beta1", "_v2", "_v1"):
        label = label.removesuffix(suffix)
    return label.replace("_", " ")


def _delete(
    resource_type: str,
    action_set: set[str],
    *,
    data_bearing: bool = False,
) -> RuleResult | None:
    if "delete" not in action_set:
        return None
    label = _label(resource_type)
    if "create" in action_set:
        return RuleResult(
            "dangerous",
            f"__TOOL__ will replace this Kubernetes {label}. Review stable identity, "
            "controller ownership, dependent objects, rollout ordering, downtime, and rollback.",
        )
    if data_bearing:
        return RuleResult(
            "irreversible",
            f"__TOOL__ will delete this data-bearing Kubernetes {label}. Cluster data, "
            "configuration, credentials, or external storage bindings may not be recoverable. "
            "Verify backup contents, reclaim policy, and restore procedure before applying.",
        )
    return RuleResult(
        "dangerous",
        f"__TOOL__ will delete this Kubernetes {label}. Review workload disruption, "
        "controller recreation, dependents, policy gaps, and rollback before applying.",
    )


def _workload_result(resource_type: str, desired: dict[str, Any]) -> RuleResult:
    findings = ["run executable containers and change workload availability"]
    if _any_true(desired, "privileged", "host_network", "hostNetwork", "host_pid", "hostPID"):
        findings.append("request privileged or host-level access")
    if _values(desired, "host_path", "hostPath"):
        findings.append("mount host filesystem paths")
    if _values(desired, "secret", "secret_ref", "secretRef", "secret_key_ref"):
        findings.append("consume Secret-backed values")
    if _contains_text(desired, ":latest"):
        findings.append("use a mutable latest image tag")
    if _values(desired, "service_account_name", "serviceAccountName"):
        findings.append("run under a selected ServiceAccount identity")
    return RuleResult(
        "dangerous",
        f"This Kubernetes {_label(resource_type)} can {'; '.join(findings)}. Review image "
        "provenance, command/args, identity, pod security, secrets, network/storage access, "
        "probes, resource limits, scheduling, rollout strategy, and disruption budget.",
    )


@register_rule(*_GENERIC_RESOURCES)
def _kubernetes_provider_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    desired = _desired(change)
    data_bearing = resource_type in _CONFIG_RESOURCES or resource_type in {
        "kubernetes_persistent_volume",
        "kubernetes_persistent_volume_claim",
        "kubernetes_persistent_volume_claim_v1",
        "kubernetes_persistent_volume_v1",
    }
    deleted = _delete(resource_type, action_set, data_bearing=data_bearing)
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []

    if resource_type in _WORKLOAD_RESOURCES:
        return [_workload_result(resource_type, desired)]

    if resource_type in _SCALING_RESOURCES:
        return [
            RuleResult(
                "dangerous",
                "This Kubernetes autoscaler changes workload replica counts from resource or "
                "external metrics. Review target ownership, min/max replicas, scale-to-zero, "
                "metric trust, stabilization, rate limits, capacity, and cost blast radius.",
            )
        ]

    if resource_type in _ADMISSION_RESOURCES:
        mutating = "mutating" in resource_type
        legacy_psp = "pod_security_policy" in resource_type
        effect = (
            "mutate every matching API request before persistence"
            if mutating
            else "grant legacy pod-security capabilities cluster-wide"
            if legacy_psp
            else "allow, deny, warn, or audit matching API requests"
        )
        insecure = _any_true(desired, "insecure_skip_tls_verify", "insecureSkipTLSVerify")
        return [
            RuleResult(
                "dangerous",
                f"This Kubernetes admission control can {effect}"
                + (" while skipping webhook TLS verification" if insecure else "")
                + ". Review match scope, selectors, failure policy, side effects, timeout, "
                "TLS trust, CEL/webhook code, reinvocation, and emergency rollback.",
            )
        ]

    if resource_type == "kubernetes_manifest":
        manifest = desired.get("manifest", desired)
        kind = str(manifest.get("kind", "unknown")) if isinstance(manifest, dict) else "unknown"
        return [
            RuleResult(
                "dangerous",
                f"This kubernetes_manifest can apply an arbitrary {kind} object with "
                "server-side field ownership. Review the complete manifest, CRD/controller "
                "semantics, sensitive values, identity, admission effects, wait conditions, "
                "field manager conflicts, and deletion behavior.",
            )
        ]

    if resource_type in _STORAGE_RESOURCES:
        return [
            RuleResult(
                "dangerous",
                "This Kubernetes storage resource changes provisioning, attachment, mount, "
                "reclaim, expansion, or topology behavior. Review driver trust, parameters and "
                "credentials, encryption, access modes, reclaim policy, snapshots/backups, "
                "retention, migration, and data-loss recovery.",
            )
        ]

    if resource_type in _NETWORK_RESOURCES:
        aggregated_api = "api_service" in resource_type
        return [
            RuleResult(
                "dangerous",
                "This Kubernetes network resource "
                + (
                    "delegates an API group to an extension server"
                    if aggregated_api
                    else "changes service discovery, traffic endpoints, or ingress handling"
                )
                + ". Review endpoint ownership, selectors, ports/protocols, TLS trust, "
                "authentication, external exposure, health, topology, and failover.",
            )
        ]

    if resource_type in _IDENTITY_RESOURCES:
        token = resource_type == "kubernetes_token_request_v1"
        return [
            RuleResult(
                "dangerous",
                "This Kubernetes identity resource "
                + (
                    "mints a bearer token for a ServiceAccount"
                    if token
                    else "creates or changes a workload ServiceAccount identity"
                )
                + ". Review audiences, expiration, automounted credentials, image-pull "
                "secrets, RBAC bindings, namespace scope, token storage, and rotation.",
            )
        ]

    if resource_type in _CONFIG_RESOURCES:
        sensitive = _contains_text(desired, "password", "secret", "token", "private_key")
        return [
            RuleResult(
                "dangerous" if sensitive else "review",
                "This Kubernetes ConfigMap writes configuration into Terraform plan/state and "
                "can change live workload behavior."
                + (" It appears to contain secret-like material." if sensitive else "")
                + " Review data sensitivity, consumers, immutable behavior, rollout triggers, "
                "size limits, ownership, and rollback.",
            )
        ]

    if resource_type in _POLICY_RESOURCES:
        return [
            RuleResult(
                "dangerous",
                "This Kubernetes policy changes scheduling priority, runtime implementation, "
                "availability guarantees, or namespace resource limits. Review selectors, "
                "eviction/preemption, disruption math, quota ceilings, default requests/limits, "
                "runtime trust, affected workloads, and rollback.",
            )
        ]

    if "certificate_signing_request" in resource_type:
        return [
            RuleResult(
                "dangerous",
                "This Kubernetes CertificateSigningRequest asks a cluster signer to issue an "
                "identity certificate. Review requester, signerName, usages, subject/SANs, "
                "approval flow, private-key custody, lifetime, trust scope, and revocation.",
            )
        ]

    if resource_type == "kubernetes_env":
        return [
            RuleResult(
                "dangerous",
                "This kubernetes_env resource patches environment variables on a live workload. "
                "Review target containers, overwrite behavior, Secret/ConfigMap references, "
                "sensitive values in Terraform state, rollout impact, and field ownership.",
            )
        ]

    if resource_type == "kubernetes_node_taint":
        return [
            RuleResult(
                "dangerous",
                "This Kubernetes node taint changes workload scheduling and may evict running "
                "pods. Review node selection, taint effect, tolerations, capacity, disruption, "
                "system workloads, overwrite behavior, and recovery.",
            )
        ]

    # annotations and labels manage live-object fields using server-side apply.
    return [
        RuleResult(
            "review",
            f"This Kubernetes {_label(resource_type)} resource changes metadata on an existing "
            "object. Review target identity, field-manager ownership, overwrite behavior, "
            "controller selectors, policy/ingress annotations, reconciliation side effects, "
            "and rollback.",
        )
    ]


@register_rule("helm_release")
def _helm_provider_release_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    desired = _desired(change)
    if "delete" in action_set:
        if "create" in action_set:
            return [
                RuleResult(
                    "dangerous",
                    "__TOOL__ will replace this Helm release, uninstalling and reinstalling its "
                    "chart-managed objects. Review persistent data, hooks, CRDs, stable identity, "
                    "downtime, dependency ordering, and rollback.",
                )
            ]
        return [
            RuleResult(
                "irreversible",
                "__TOOL__ will uninstall this Helm release. Hook jobs, namespaced objects, "
                "release history, and persistent data selected by the chart may be deleted. "
                "Verify backups, keep policies, CRDs, and a tested recovery procedure.",
            )
        ]
    if not ({"create", "update"} & action_set):
        return []

    findings = ["render and apply chart-controlled Kubernetes objects"]
    if desired.get("atomic") is True or desired.get("cleanup_on_fail") is True:
        findings.append("delete newly created resources after a failed operation")
    if desired.get("force_update") is True or desired.get("recreate_pods") is True:
        findings.append("force replacement or restart of managed workloads")
    if desired.get("skip_crds") is not True:
        findings.append("install or retain cluster-scoped CRDs")
    if desired.get("disable_webhooks") is not True:
        findings.append("run chart lifecycle hooks")
    if desired.get("verify") is not True:
        findings.append("install a chart without cryptographic provenance verification")
    if _values(desired, "set_sensitive") or _contains_text(desired, "password", "token"):
        findings.append("pass sensitive values that require Terraform-state review")
    return [
        RuleResult(
            "dangerous",
            f"This Helm release can {'; '.join(findings)}. Review chart source/version/digest, "
            "repository credentials and TLS, values and secret exposure, namespace/RBAC, "
            "rendered manifests, CRDs/hooks, waits/timeouts, dependency updates, and rollback.",
        )
    ]
