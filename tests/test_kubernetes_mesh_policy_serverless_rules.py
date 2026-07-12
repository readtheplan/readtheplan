from __future__ import annotations

from pathlib import Path

import pytest

from readtheplan.adapters.kubernetes import KubernetesAdapter, parse_kubernetes_input

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(source: str):
    return KubernetesAdapter().analyze(parse_kubernetes_input(source), tool_name="Kubernetes")


def test_mesh_policy_autoscaling_and_serverless_fixture_receives_first_party_rules() -> None:
    changes = _analyze((FIXTURES / "kubernetes_mesh_policy_serverless_risky.yml").read_text())
    by_type = {change.resource_type: change for change in changes}

    expected = {
        "kubernetes_istio_virtual_service",
        "kubernetes_istio_destination_rule",
        "kubernetes_istio_gateway",
        "kubernetes_istio_service_entry",
        "kubernetes_istio_sidecar",
        "kubernetes_istio_envoy_filter",
        "kubernetes_istio_wasm_plugin",
        "kubernetes_istio_authorization_policy",
        "kubernetes_istio_peer_authentication",
        "kubernetes_istio_request_authentication",
        "kubernetes_istio_telemetry",
        "kubernetes_kyverno_cluster_policy",
        "kubernetes_kyverno_mutating_policy",
        "kubernetes_kyverno_deleting_policy",
        "kubernetes_kyverno_image_validating_policy",
        "kubernetes_kyverno_policy_exception",
        "kubernetes_gatekeeper_constraint_template",
        "kubernetes_gatekeeper_constraint",
        "kubernetes_gatekeeper_assign",
        "kubernetes_gatekeeper_config",
        "kubernetes_keda_scaled_object",
        "kubernetes_keda_scaled_job",
        "kubernetes_keda_cluster_trigger_authentication",
        "kubernetes_keda_cloud_event_source",
        "kubernetes_knative_service",
        "kubernetes_knative_route",
        "kubernetes_knative_broker",
        "kubernetes_knative_trigger",
        "kubernetes_knative_in_memory_channel",
        "kubernetes_knative_subscription",
        "kubernetes_knative_sequence",
        "kubernetes_knative_event_source",
        "kubernetes_knative_event_policy",
        "kubernetes_knative_event_transform",
        "kubernetes_knative_request_reply",
    }
    assert expected == set(by_type)
    assert by_type["kubernetes_keda_cloud_event_source"].risk == "review"
    assert {
        by_type[resource_type].risk
        for resource_type in expected - {"kubernetes_keda_cloud_event_source"}
    } == {"dangerous"}

    assert "mirror, fault" in by_type["kubernetes_istio_virtual_service"].explanation
    assert "disable mutual TLS" in by_type["kubernetes_istio_destination_rule"].explanation
    assert "wildcard external hosts" in by_type["kubernetes_istio_service_entry"].explanation
    assert (
        "forward original bearer" in by_type["kubernetes_istio_request_authentication"].explanation
    )
    assert "audit validation failures" in by_type["kubernetes_kyverno_cluster_policy"].explanation
    assert "bypasses selected" in by_type["kubernetes_kyverno_policy_exception"].explanation
    assert "external data provider" in by_type["kubernetes_gatekeeper_assign"].explanation
    assert "more than 100 replicas" in by_type["kubernetes_keda_scaled_object"].explanation
    assert "privileged" in by_type["kubernetes_keda_scaled_job"].explanation
    assert "externally visible" in by_type["kubernetes_knative_service"].explanation
    assert "development-only" in by_type["kubernetes_knative_in_memory_channel"].explanation
    assert "every addressable resource" in by_type["kubernetes_knative_event_policy"].explanation


@pytest.mark.parametrize(
    ("api_version", "kind", "expected_type"),
    [
        ("networking.istio.io/v1", "WorkloadEntry", "kubernetes_istio_workload_entry"),
        ("networking.istio.io/v1", "WorkloadGroup", "kubernetes_istio_workload_group"),
        ("networking.istio.io/v1", "ProxyConfig", "kubernetes_istio_proxy_config"),
        (
            "policies.kyverno.io/v1alpha1",
            "ValidatingPolicy",
            "kubernetes_kyverno_validating_policy",
        ),
        (
            "policies.kyverno.io/v1alpha1",
            "NamespacedValidatingPolicy",
            "kubernetes_kyverno_namespaced_validating_policy",
        ),
        (
            "policies.kyverno.io/v1alpha1",
            "NamespacedMutatingPolicy",
            "kubernetes_kyverno_namespaced_mutating_policy",
        ),
        (
            "policies.kyverno.io/v1alpha1",
            "GeneratingPolicy",
            "kubernetes_kyverno_generating_policy",
        ),
        (
            "policies.kyverno.io/v1alpha1",
            "NamespacedGeneratingPolicy",
            "kubernetes_kyverno_namespaced_generating_policy",
        ),
        (
            "policies.kyverno.io/v1alpha1",
            "NamespacedDeletingPolicy",
            "kubernetes_kyverno_namespaced_deleting_policy",
        ),
        (
            "policies.kyverno.io/v1alpha1",
            "NamespacedImageValidatingPolicy",
            "kubernetes_kyverno_namespaced_image_validating_policy",
        ),
        ("kyverno.io/v2", "CleanupPolicy", "kubernetes_kyverno_cleanup_policy"),
        ("kyverno.io/v2", "ClusterCleanupPolicy", "kubernetes_kyverno_cluster_cleanup_policy"),
        ("mutations.gatekeeper.sh/v1", "AssignMetadata", "kubernetes_gatekeeper_assign_metadata"),
        ("mutations.gatekeeper.sh/v1", "ModifySet", "kubernetes_gatekeeper_modify_set"),
        ("mutations.gatekeeper.sh/v1", "AssignImage", "kubernetes_gatekeeper_assign_image"),
        (
            "expansion.gatekeeper.sh/v1alpha1",
            "ExpansionTemplate",
            "kubernetes_gatekeeper_expansion_template",
        ),
        ("syncset.gatekeeper.sh/v1alpha1", "SyncSet", "kubernetes_gatekeeper_sync_set"),
        (
            "externaldata.gatekeeper.sh/v1beta1",
            "Provider",
            "kubernetes_gatekeeper_external_data_provider",
        ),
        ("keda.sh/v1alpha1", "TriggerAuthentication", "kubernetes_keda_trigger_authentication"),
        ("serving.knative.dev/v1", "Configuration", "kubernetes_knative_configuration"),
        ("serving.knative.dev/v1", "Revision", "kubernetes_knative_revision"),
        ("messaging.knative.dev/v1", "Channel", "kubernetes_knative_channel"),
        ("flows.knative.dev/v1", "Parallel", "kubernetes_knative_parallel"),
        ("sources.knative.dev/v1", "KafkaSource", "kubernetes_knative_event_source"),
    ],
)
def test_known_mesh_policy_autoscaling_and_serverless_types_normalize_and_escalate(
    api_version: str, kind: str, expected_type: str
) -> None:
    change = _analyze(
        f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: example\nspec: {{}}\n"
    )[0]
    assert change.resource_type == expected_type
    assert change.risk == "dangerous"


@pytest.mark.parametrize(
    ("api_version", "kind"),
    [
        ("networking.istio.io/v1", "VirtualService"),
        ("kyverno.io/v1", "ClusterPolicy"),
        ("templates.gatekeeper.sh/v1", "ConstraintTemplate"),
        ("keda.sh/v1alpha1", "ScaledObject"),
        ("serving.knative.dev/v1", "Service"),
    ],
)
def test_mesh_policy_autoscaling_and_serverless_deletion_is_irreversible(
    api_version: str, kind: str
) -> None:
    old = f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: example\nspec: {{}}\n"
    data = {"old_manifests": parse_kubernetes_input(old)["resources"], "new_manifests": []}
    change = KubernetesAdapter().analyze(data, tool_name="Kubernetes")[0]
    assert change.risk == "irreversible"


def test_gatekeeper_non_enforcing_constraint_is_review() -> None:
    change = _analyze(
        "apiVersion: constraints.gatekeeper.sh/v1beta1\n"
        "kind: K8sRequiredLabels\nmetadata:\n  name: example\n"
        "spec:\n  enforcementAction: dryrun\n"
    )[0]
    assert change.resource_type == "kubernetes_gatekeeper_constraint"
    assert change.risk == "review"


def test_istio_telemetry_change_without_disabled_provider_is_review() -> None:
    change = _analyze(
        "apiVersion: telemetry.istio.io/v1\nkind: Telemetry\n"
        "metadata:\n  name: example\nspec:\n  metrics: [{}]\n"
    )[0]
    assert change.risk == "review"


def test_templated_keda_max_replica_count_does_not_crash() -> None:
    change = _analyze(
        "apiVersion: keda.sh/v1alpha1\nkind: ScaledObject\n"
        "metadata:\n  name: example\nspec:\n  maxReplicaCount: '{{ .Values.max }}'\n"
    )[0]
    assert change.resource_type == "kubernetes_keda_scaled_object"
    assert change.risk == "dangerous"


@pytest.mark.parametrize(
    ("api_version", "kind"),
    [
        ("example.io/v1", "VirtualService"),
        ("example.io/v1", "Policy"),
        ("example.io/v1", "Config"),
        ("example.io/v1", "Provider"),
    ],
)
def test_same_kind_from_unrelated_api_group_stays_generic(api_version: str, kind: str) -> None:
    change = _analyze(
        f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: example\nspec: {{}}\n"
    )[0]
    assert change.resource_type == f"kubernetes_{kind.lower()}"
    assert change.risk == "review"
