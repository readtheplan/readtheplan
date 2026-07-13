from __future__ import annotations

from pathlib import Path

import pytest

from readtheplan.adapters.kubernetes import KubernetesAdapter, parse_kubernetes_input

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(source: str):
    return KubernetesAdapter().analyze(parse_kubernetes_input(source), tool_name="Kubernetes")


def test_infrastructure_controller_fixture_receives_first_party_rules() -> None:
    changes = _analyze((FIXTURES / "kubernetes_infra_controllers_risky.yml").read_text())
    by_type = {change.resource_type: change for change in changes}

    expected = {
        "kubernetes_capi_cluster",
        "kubernetes_capi_cluster_class",
        "kubernetes_capi_machine_deployment",
        "kubernetes_capi_machine_health_check",
        "kubernetes_capi_kubeadm_control_plane",
        "kubernetes_capi_kubeadm_config",
        "kubernetes_capi_extension_config",
        "kubernetes_capi_cluster_resource_set",
        "kubernetes_capi_machine_drain_rule",
        "kubernetes_capi_infrastructure_aws_cluster",
        "kubernetes_karpenter_node_pool",
        "kubernetes_karpenter_node_claim",
        "kubernetes_karpenter_node_class",
    }
    assert expected <= set(by_type)
    assert {by_type[resource_type].risk for resource_type in expected} == {"dangerous"}

    assert "entire workload cluster" in by_type["kubernetes_capi_cluster"].explanation
    assert "scale the managed fleet to zero" in by_type[
        "kubernetes_capi_machine_deployment"
    ].explanation
    assert "even control-plane replica count" in by_type[
        "kubernetes_capi_kubeadm_control_plane"
    ].explanation
    assert "without CA verification" in by_type["kubernetes_capi_kubeadm_config"].explanation
    assert "fail open" in by_type["kubernetes_capi_extension_config"].explanation
    assert "Secret-backed" in by_type["kubernetes_capi_cluster_resource_set"].explanation
    assert "default voluntary-disruption budget" in by_type[
        "kubernetes_karpenter_node_pool"
    ].explanation
    assert "mutable AMIs" in by_type["kubernetes_karpenter_node_class"].explanation


def test_infrastructure_controller_explanations_do_not_echo_bootstrap_payloads() -> None:
    changes = _analyze((FIXTURES / "kubernetes_infra_controllers_risky.yml").read_text())
    explanations = "\n".join(change.explanation for change in changes)

    assert "fixture-private-control-plane-value" not in explanations
    assert "fixture-bootstrap-secret-value" not in explanations
    assert "fixture-ssh-public-key" not in explanations
    assert "do-not-leak-this-value" not in explanations


@pytest.mark.parametrize(
    ("api_version", "kind", "expected_type"),
    [
        ("cluster.x-k8s.io/v1beta1", "Cluster", "kubernetes_capi_cluster"),
        ("cluster.x-k8s.io/v1beta2", "Machine", "kubernetes_capi_machine"),
        (
            "controlplane.cluster.x-k8s.io/v1beta2",
            "KubeadmControlPlane",
            "kubernetes_capi_kubeadm_control_plane",
        ),
        (
            "bootstrap.cluster.x-k8s.io/v1beta2",
            "KubeadmConfigTemplate",
            "kubernetes_capi_kubeadm_config_template",
        ),
        ("karpenter.sh/v1", "NodePool", "kubernetes_karpenter_node_pool"),
        ("karpenter.sh/v1", "NodeClaim", "kubernetes_karpenter_node_claim"),
        (
            "karpenter.k8s.aws/v1",
            "EC2NodeClass",
            "kubernetes_karpenter_node_class",
        ),
    ],
)
def test_infrastructure_controller_api_types_normalize_and_escalate(
    api_version: str, kind: str, expected_type: str
) -> None:
    change = _analyze(
        f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: example\nspec: {{}}\n"
    )[0]
    assert change.resource_type == expected_type
    assert change.risk == "dangerous"


def test_cluster_api_provider_kind_normalizes_dynamically() -> None:
    change = _analyze(
        "apiVersion: infrastructure.cluster.x-k8s.io/v1beta2\n"
        "kind: AzureManagedControlPlane\n"
        "metadata:\n  name: example\n"
        "spec: {}\n"
    )[0]
    assert change.resource_type == "kubernetes_capi_infrastructure_azure_managed_control_plane"
    assert change.risk == "dangerous"


@pytest.mark.parametrize(
    ("api_version", "kind"),
    [
        ("cluster.x-k8s.io/v1beta2", "Cluster"),
        ("cluster.x-k8s.io/v1beta2", "MachineDeployment"),
        ("infrastructure.cluster.x-k8s.io/v1beta2", "AWSCluster"),
        ("karpenter.sh/v1", "NodePool"),
        ("karpenter.sh/v1", "NodeClaim"),
    ],
)
def test_infrastructure_controller_deletion_is_irreversible(
    api_version: str, kind: str
) -> None:
    old = f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: example\nspec: {{}}\n"
    data = {"old_manifests": parse_kubernetes_input(old)["resources"], "new_manifests": []}
    change = KubernetesAdapter().analyze(data, tool_name="Kubernetes")[0]
    assert change.risk == "irreversible"


@pytest.mark.parametrize(
    ("api_version", "kind", "old_spec", "new_spec", "expected_explanation"),
    [
        (
            "cluster.x-k8s.io/v1beta2",
            "MachineDeployment",
            "replicas: 3",
            "replicas: 0",
            "scale the managed fleet to zero",
        ),
        (
            "karpenter.sh/v1",
            "NodePool",
            "limits:\n    cpu: 100",
            "disruption:\n    consolidateAfter: 0s",
            "immediately eligible for disruption",
        ),
    ],
)
def test_infrastructure_controller_updates_use_desired_lifecycle_state(
    api_version: str,
    kind: str,
    old_spec: str,
    new_spec: str,
    expected_explanation: str,
) -> None:
    prefix = f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: example\nspec:\n  "
    old = parse_kubernetes_input(prefix + old_spec.replace("\n", "\n  "))["resources"]
    new = parse_kubernetes_input(prefix + new_spec.replace("\n", "\n  "))["resources"]
    change = KubernetesAdapter().analyze(
        {"old_manifests": old, "new_manifests": new}, tool_name="Kubernetes"
    )[0]

    assert change.actions == ("update",)
    assert change.risk == "dangerous"
    assert expected_explanation in change.explanation


@pytest.mark.parametrize("kind", ["NodePool", "NodeClaim", "EC2NodeClass"])
def test_same_kind_from_unrelated_api_group_stays_generic_and_namespaced(kind: str) -> None:
    change = _analyze(
        f"apiVersion: example.io/v1\nkind: {kind}\n"
        "metadata:\n  name: example\n  namespace: tenant-a\n"
        "spec: {}\n"
    )[0]
    assert change.resource_type == f"kubernetes_{kind.lower()}"
    assert change.address == "tenant-a/example"
    assert change.risk == "review"
