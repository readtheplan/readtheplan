from __future__ import annotations

from pathlib import Path

import pytest

from readtheplan.adapters.kubernetes import KubernetesAdapter, parse_kubernetes_input

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(source: str):
    data = parse_kubernetes_input(source)
    return KubernetesAdapter().analyze(data, tool_name="Kubernetes")


def test_flux_risky_gitops_resources_receive_native_rules() -> None:
    changes = _analyze((FIXTURES / "flux_gitops_risky.yml").read_text(encoding="utf-8"))
    by_type = {change.resource_type: change for change in changes}

    assert by_type["kubernetes_flux_git_repository"].risk == "dangerous"
    assert "credential scope" in by_type["kubernetes_flux_git_repository"].explanation
    assert by_type["kubernetes_flux_kustomization"].risk == "dangerous"
    assert "prune resources" in by_type["kubernetes_flux_kustomization"].explanation
    assert by_type["kubernetes_flux_helm_release"].risk == "dangerous"
    assert "secret-backed values" in by_type["kubernetes_flux_helm_release"].explanation
    assert by_type["kubernetes_flux_image_update_automation"].risk == "dangerous"
    assert "commit and push" in by_type["kubernetes_flux_image_update_automation"].explanation
    assert by_type["kubernetes_flux_receiver"].risk == "dangerous"
    assert "webhook" in by_type["kubernetes_flux_receiver"].explanation


@pytest.mark.parametrize(
    ("api_version", "kind", "expected_type"),
    [
        (
            "source.toolkit.fluxcd.io/v1",
            "OCIRepository",
            "kubernetes_flux_oci_repository",
        ),
        (
            "source.toolkit.fluxcd.io/v1",
            "HelmRepository",
            "kubernetes_flux_helm_repository",
        ),
        (
            "image.toolkit.fluxcd.io/v1beta2",
            "ImagePolicy",
            "kubernetes_flux_image_policy",
        ),
        (
            "notification.toolkit.fluxcd.io/v1beta3",
            "Provider",
            "kubernetes_flux_provider",
        ),
    ],
)
def test_flux_api_groups_normalize_known_resources(
    api_version: str,
    kind: str,
    expected_type: str,
) -> None:
    change = _analyze(
        f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: example\nspec: {{}}\n"
    )[0]
    assert change.resource_type == expected_type
    assert change.risk == "review"


def test_non_flux_kustomization_stays_generic() -> None:
    change = _analyze(
        "apiVersion: example.io/v1\nkind: Kustomization\nmetadata:\n  name: example\nspec: {}\n"
    )[0]
    assert change.resource_type == "kubernetes_kustomization"
    assert change.risk == "review"


@pytest.mark.parametrize(
    ("kind", "api_version", "spec", "expected_type"),
    [
        (
            "Kustomization",
            "kustomize.toolkit.fluxcd.io/v1",
            {"prune": True},
            "kubernetes_flux_kustomization",
        ),
        (
            "HelmRelease",
            "helm.toolkit.fluxcd.io/v2",
            {},
            "kubernetes_flux_helm_release",
        ),
    ],
)
def test_flux_controller_deletion_is_irreversible(
    kind: str,
    api_version: str,
    spec: dict[str, object],
    expected_type: str,
) -> None:
    data = {
        "old_manifests": [
            {
                "apiVersion": api_version,
                "kind": kind,
                "metadata": {"name": "production", "namespace": "flux-system"},
                "spec": spec,
            }
        ],
        "new_manifests": [],
    }
    change = KubernetesAdapter().analyze(data, tool_name="Kubernetes")[0]
    assert change.resource_type == expected_type
    assert change.risk == "irreversible"


def test_flux_pinned_verified_source_still_requires_review() -> None:
    change = _analyze(
        """
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: platform
spec:
  url: https://github.com/example/platform.git
  ref:
    commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  verify:
    mode: HEAD
    secretRef:
      name: authors
"""
    )[0]
    assert change.risk == "review"
    assert "immutable revision" in change.explanation
    assert "Source verification is configured" in change.explanation


@pytest.mark.parametrize(
    ("kind", "api_version", "spec", "explanation"),
    [
        (
            "GitRepository",
            "source.toolkit.fluxcd.io/v1",
            {"url": "http://git.internal/platform.git"},
            "unencrypted HTTP",
        ),
        (
            "OCIRepository",
            "source.toolkit.fluxcd.io/v1",
            {"url": "oci://registry.example/platform", "suspend": True},
            "suspends reconciliation",
        ),
        (
            "Kustomization",
            "kustomize.toolkit.fluxcd.io/v1",
            {"kubeConfig": {"secretRef": {"name": "remote"}}},
            "remote cluster",
        ),
        (
            "HelmRelease",
            "helm.toolkit.fluxcd.io/v2",
            {"kubeConfig": {"configMapRef": {"name": "remote"}}},
            "remote cluster",
        ),
    ],
)
def test_flux_high_risk_boundaries_are_dangerous(
    kind: str,
    api_version: str,
    spec: dict[str, object],
    explanation: str,
) -> None:
    data = {
        "resources": [
            {
                "apiVersion": api_version,
                "kind": kind,
                "metadata": {"name": "example", "namespace": "flux-system"},
                "spec": spec,
            }
        ]
    }
    change = KubernetesAdapter().analyze(data, tool_name="Kubernetes")[0]
    assert change.risk == "dangerous"
    assert explanation in change.explanation
