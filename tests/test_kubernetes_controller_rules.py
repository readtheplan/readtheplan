from __future__ import annotations

from pathlib import Path

import pytest

from readtheplan.adapters.kubernetes import KubernetesAdapter, parse_kubernetes_input

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(source: str):
    return KubernetesAdapter().analyze(parse_kubernetes_input(source), tool_name="Kubernetes")


def test_popular_controller_fixture_receives_first_party_rules() -> None:
    changes = _analyze((FIXTURES / "kubernetes_controllers_risky.yml").read_text())
    by_type = {change.resource_type: change for change in changes}

    expected = {
        "kubernetes_argo_workflow",
        "kubernetes_argo_workflow_event_binding",
        "kubernetes_argo_event_source",
        "kubernetes_argo_sensor",
        "kubernetes_argo_event_bus",
        "kubernetes_gateway_class",
        "kubernetes_gateway",
        "kubernetes_gateway_http_route",
        "kubernetes_gateway_reference_grant",
        "kubernetes_gateway_backend_tls_policy",
        "kubernetes_cert_manager_certificate",
        "kubernetes_cert_manager_cluster_issuer",
        "kubernetes_cert_manager_certificate_request",
        "kubernetes_cert_manager_trust_bundle",
        "kubernetes_external_secrets_cluster_secret_store",
        "kubernetes_external_secrets_external_secret",
        "kubernetes_external_secrets_cluster_external_secret",
        "kubernetes_external_secrets_push_secret",
        "kubernetes_external_secrets_generator",
    }
    assert expected <= set(by_type)
    assert {by_type[resource_type].risk for resource_type in expected} == {"dangerous"}

    assert "images not pinned" in by_type["kubernetes_argo_workflow"].explanation
    assert "event payloads" in by_type["kubernetes_argo_workflow_event_binding"].explanation
    assert "disable TLS" in by_type["kubernetes_argo_event_source"].explanation
    assert "selected ServiceAccount" in by_type["kubernetes_argo_sensor"].explanation
    assert "persist event" in by_type["kubernetes_argo_event_bus"].explanation
    assert "every namespace" in by_type["kubernetes_gateway"].explanation
    assert "RequestMirror" in by_type["kubernetes_gateway_http_route"].explanation
    assert "cross-namespace" in by_type["kubernetes_gateway_reference_grant"].explanation
    assert "wildcard DNS" in by_type["kubernetes_cert_manager_certificate"].explanation
    assert "all installed ingress" in by_type["kubernetes_cert_manager_cluster_issuer"].explanation
    assert (
        "no namespace conditions"
        in by_type["kubernetes_external_secrets_cluster_secret_store"].explanation
    )
    assert "bulk import" in by_type["kubernetes_external_secrets_external_secret"].explanation
    assert (
        "exports Kubernetes Secret"
        in by_type["kubernetes_external_secrets_push_secret"].explanation
    )


@pytest.mark.parametrize(
    ("api_version", "kind", "expected_type"),
    [
        ("argoproj.io/v1alpha1", "WorkflowTemplate", "kubernetes_argo_workflow_template"),
        (
            "argoproj.io/v1alpha1",
            "ClusterWorkflowTemplate",
            "kubernetes_argo_cluster_workflow_template",
        ),
        ("argoproj.io/v1alpha1", "CronWorkflow", "kubernetes_argo_cron_workflow"),
        ("gateway.networking.k8s.io/v1", "GRPCRoute", "kubernetes_gateway_grpc_route"),
        ("gateway.networking.k8s.io/v1alpha2", "TLSRoute", "kubernetes_gateway_tls_route"),
        ("gateway.networking.k8s.io/v1alpha2", "TCPRoute", "kubernetes_gateway_tcp_route"),
        ("gateway.networking.k8s.io/v1alpha2", "UDPRoute", "kubernetes_gateway_udp_route"),
        (
            "gateway.networking.x-k8s.io/v1alpha1",
            "ListenerSet",
            "kubernetes_gateway_listener_set",
        ),
        ("cert-manager.io/v1", "Issuer", "kubernetes_cert_manager_issuer"),
        ("acme.cert-manager.io/v1", "Order", "kubernetes_cert_manager_acme_order"),
        ("acme.cert-manager.io/v1", "Challenge", "kubernetes_cert_manager_acme_challenge"),
        (
            "external-secrets.io/v1",
            "SecretStore",
            "kubernetes_external_secrets_secret_store",
        ),
        (
            "external-secrets.io/v1alpha1",
            "ClusterPushSecret",
            "kubernetes_external_secrets_cluster_push_secret",
        ),
    ],
)
def test_known_controller_api_types_normalize_and_escalate(
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
        ("argoproj.io/v1alpha1", "Workflow"),
        ("gateway.networking.k8s.io/v1", "HTTPRoute"),
        ("cert-manager.io/v1", "Certificate"),
        ("external-secrets.io/v1", "ExternalSecret"),
    ],
)
def test_controller_resource_deletion_is_irreversible(api_version: str, kind: str) -> None:
    old = f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: example\nspec: {{}}\n"
    data = {"old_manifests": parse_kubernetes_input(old)["resources"], "new_manifests": []}
    change = KubernetesAdapter().analyze(data, tool_name="Kubernetes")[0]
    assert change.risk == "irreversible"


def test_same_kind_from_unrelated_api_group_stays_generic() -> None:
    change = _analyze(
        "apiVersion: example.io/v1\nkind: Certificate\nmetadata:\n  name: example\nspec: {}\n"
    )[0]
    assert change.resource_type == "kubernetes_certificate"
    assert change.risk == "review"
