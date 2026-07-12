from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from readtheplan.plan import analyze_plan_file
from readtheplan.rules._shared import _RULE_REGISTRY
from readtheplan.rules.kubernetes_provider import KUBERNETES_PROVIDER_RESOURCES

FIXTURES = Path(__file__).parent / "fixtures"


def _summary_for(*changes: dict):
    return analyze_plan_file(
        {
            "format_version": "1.2",
            "terraform_version": "1.11.4",
            "resource_changes": list(changes),
        }
    )


def _change(
    resource_type: str,
    actions: list[str],
    *,
    before=None,
    after=None,
) -> dict:
    return {
        "address": f"{resource_type}.example",
        "type": resource_type,
        "name": "example",
        "change": {"actions": actions, "before": before, "after": after},
    }


def test_kubernetes_and_helm_fixture_receives_resource_aware_rules() -> None:
    plan = json.loads(
        (FIXTURES / "kubernetes_helm_provider_plan_risky.json").read_text()
    )
    changes = analyze_plan_file(plan).resource_changes
    by_address = {change.address: change for change in changes}

    assert len(changes) == 36
    assert Counter(change.risk for change in changes) == {
        "dangerous": 28,
        "irreversible": 4,
        "review": 4,
    }
    assert "privileged or host-level access" in by_address[
        "kubernetes_pod_v1.debug"
    ].explanation
    assert "external metrics" in by_address[
        "kubernetes_horizontal_pod_autoscaler_v2.api"
    ].explanation
    assert "skipping webhook TLS verification" in by_address[
        "kubernetes_mutating_webhook_configuration_v1.injector"
    ].explanation
    assert "arbitrary ClusterRoleBinding" in by_address[
        "kubernetes_manifest.cluster_admin"
    ].explanation
    assert "bearer token" in by_address[
        "kubernetes_token_request_v1.deployer"
    ].explanation
    assert "identity certificate" in by_address[
        "kubernetes_certificate_signing_request_v1.admin"
    ].explanation
    assert "may evict running pods" in by_address[
        "kubernetes_node_taint_via_patch.worker"
    ].explanation
    assert "wildcard apiGroups, resources, verbs" in by_address[
        "kubernetes_role_v1.wildcard"
    ].explanation
    assert "namespace-wide default-deny" in by_address[
        "kubernetes_network_policy_v1.default_deny"
    ].explanation
    assert "cryptographic provenance verification" in by_address[
        "helm_release.platform"
    ].explanation
    assert by_address["helm_release.legacy"].risk == "irreversible"
    assert by_address["kubernetes_namespace_v1.staging"].risk == "review"


def test_published_kubernetes_provider_catalog_never_falls_back_to_safe() -> None:
    assert len(KUBERNETES_PROVIDER_RESOURCES) == 83
    assert KUBERNETES_PROVIDER_RESOURCES <= set(_RULE_REGISTRY)

    for resource_type in sorted(KUBERNETES_PROVIDER_RESOURCES):
        result = _summary_for(
            _change(resource_type, ["create"], after={})
        ).resource_changes[0]
        assert result.risk in {"review", "dangerous"}, resource_type
        assert result.source == "builtin", resource_type


@pytest.mark.parametrize(
    ("resource_type", "after", "phrase"),
    [
        (
            "kubernetes_pod_v1",
            {"spec": {"host_network": True}},
            "host-level access",
        ),
        (
            "kubernetes_manifest",
            {"manifest": {"kind": "CustomResourceDefinition"}},
            "arbitrary CustomResourceDefinition",
        ),
        (
            "kubernetes_mutating_webhook_configuration_v1",
            {"webhook": [{"insecure_skip_tls_verify": True}]},
            "skipping webhook TLS verification",
        ),
        (
            "kubernetes_role_v1",
            {"rule": [{"api_groups": ["*"], "resources": ["*"], "verbs": ["*"]}]},
            "wildcard apiGroups, resources, verbs",
        ),
        (
            "kubernetes_token_request_v1",
            {"spec": {"audiences": ["cluster"]}},
            "mints a bearer token",
        ),
        (
            "helm_release",
            {"chart": "platform", "force_update": True, "verify": False},
            "force replacement or restart",
        ),
    ],
)
def test_high_value_kubernetes_and_helm_surfaces_have_first_party_semantics(
    resource_type: str, after: dict, phrase: str
) -> None:
    result = _summary_for(_change(resource_type, ["create"], after=after)).resource_changes[0]
    assert result.risk == "dangerous"
    assert phrase in result.explanation


@pytest.mark.parametrize(
    "resource_type",
    [
        "kubernetes_config_map_v1",
        "kubernetes_persistent_volume_v1",
        "kubernetes_persistent_volume_claim_v1",
        "helm_release",
    ],
)
def test_data_bearing_kubernetes_and_helm_deletes_require_recovery(
    resource_type: str,
) -> None:
    result = _summary_for(
        _change(resource_type, ["delete"], before={"metadata": {"name": "old"}})
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "recover" in result.explanation or "recovery" in result.explanation


def test_helm_release_replacement_explains_uninstall_and_reinstall() -> None:
    result = _summary_for(
        _change(
            "helm_release",
            ["delete", "create"],
            before={"chart": "old"},
            after={"chart": "new"},
        )
    ).resource_changes[0]
    assert result.risk == "dangerous"
    assert "uninstalling and reinstalling" in result.explanation


def test_unrelated_provider_resource_keeps_generic_baseline() -> None:
    result = _summary_for(
        _change("example_manifest", ["create"], after={"kind": "Pod"})
    ).resource_changes[0]
    assert result.risk == "safe"
    assert "Kubernetes" not in result.explanation
