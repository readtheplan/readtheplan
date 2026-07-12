from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.crossplane import (
    CrossplaneAdapter,
    CrossplaneInputError,
    parse_crossplane_input,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks() -> dict[str, list[str]]:
    source = (FIXTURES / "crossplane_risky.yml").read_text(encoding="utf-8")
    data = parse_crossplane_input(source)
    result: dict[str, list[str]] = defaultdict(list)
    for change in CrossplaneAdapter().analyze(data, tool_name="crossplane"):
        result[change.resource_type].append(change.risk)
    return result


def test_crossplane_surfaces_package_supply_chain_and_runtime_controls() -> None:
    risks = _risks()
    assert risks["crossplane_package_install"] == ["dangerous"]
    assert risks["crossplane_unpinned_package"] == ["dangerous"]
    assert risks["crossplane_mutable_package_pull"] == ["dangerous"]
    assert risks["crossplane_automatic_revision"] == ["review"]
    assert risks["crossplane_skipDependencyResolution"] == ["dangerous"]
    assert risks["crossplane_ignoreCrossplaneConstraints"] == ["dangerous"]
    assert len(risks["crossplane_runtime_config"]) == 3
    assert len(risks["crossplane_registry_credentials"]) == 2
    assert risks["crossplane_image_policy"] == ["review"]
    assert risks["crossplane_broad_image_policy"] == ["dangerous"]
    assert risks["crossplane_image_rewrite"] == ["dangerous"]
    assert risks["crossplane_signature_policy"] == ["review"]
    assert risks["crossplane_privileged_runtime"] == ["dangerous"]
    assert risks["crossplane_runtime_identity"] == ["dangerous"]


def test_crossplane_surfaces_api_composition_and_activation_controls() -> None:
    risks = _risks()
    assert risks["crossplane_composite_api_definition"] == ["dangerous"]
    assert risks["crossplane_claim_api"] == ["review"]
    assert risks["crossplane_conversion_webhook"] == ["dangerous"]
    assert risks["crossplane_default_composition"] == ["review"]
    assert risks["crossplane_enforced_composition"] == ["dangerous"]
    assert len(risks["crossplane_automatic_composition_update"]) == 2
    assert risks["crossplane_composition"] == ["dangerous"]
    assert risks["crossplane_composition_function"] == ["dangerous"]
    assert risks["crossplane_function_input"] == ["review"]
    assert risks["crossplane_function_credentials"] == ["dangerous"]
    assert risks["crossplane_connection_secret_destination"] == ["dangerous"]
    assert risks["crossplane_managed_resource_definition"] == ["irreversible"]
    assert risks["crossplane_environment_config"] == ["review"]
    assert risks["crossplane_secret_material"] == ["dangerous"]
    assert risks["crossplane_deletion_dependency"] == ["dangerous"]


def test_crossplane_surfaces_identity_and_managed_resource_lifecycle() -> None:
    risks = _risks()
    assert risks["crossplane_provider_credentials"] == ["dangerous"]
    assert risks["crossplane_credential_secret_ref"] == ["review"]
    assert risks["crossplane_cluster_wide_credentials"] == ["dangerous"]
    assert risks["crossplane_inline_credentials"] == []
    assert len(risks["crossplane_managed_resource"]) == 2
    assert risks["crossplane_external_delete_permission"] == ["dangerous"]
    assert risks["crossplane_observe_only"] == ["safe"]
    assert risks["crossplane_external_deletion_policy"] == ["dangerous", "review"]
    assert risks["crossplane_provider_identity"] == ["review"]
    assert risks["crossplane_implicit_provider_identity"] == ["dangerous"]
    assert risks["crossplane_connection_details"] == ["dangerous"]
    assert risks["crossplane_create_only_fields"] == ["review"]
    assert risks["crossplane_resource_reference"] == ["review"]
    assert risks["crossplane_external_resource_binding"] == ["review"]
    assert risks["crossplane_paused_reconciliation"] == ["review"]


def test_crossplane_surfaces_composite_selection_and_package_metadata() -> None:
    risks = _risks()
    assert risks["crossplane_composite_resource"] == ["dangerous"]
    assert risks["crossplane_dynamic_composition_selection"] == ["dangerous"]
    assert risks["crossplane_pinned_composition_revision"] == ["review"]
    assert risks["crossplane_package_metadata"] == ["review"]
    assert risks["crossplane_package_dependency"] == ["dangerous"]


def test_versioned_package_and_manual_activation_avoid_mutability_findings() -> None:
    data = parse_crossplane_input(
        """\
apiVersion: pkg.crossplane.io/v1
kind: Function
metadata:
  name: stable-function
spec:
  package: xpkg.crossplane.io/crossplane/function:v1.2.3
  revisionActivationPolicy: Manual
"""
    )
    kinds = {
        change.resource_type for change in CrossplaneAdapter().analyze(data, tool_name="crossplane")
    }
    assert "crossplane_package_source" in kinds
    assert "crossplane_unpinned_package" not in kinds
    assert "crossplane_automatic_revision" not in kinds


def test_mixed_source_preserves_embedded_kubernetes_risk() -> None:
    data = parse_crossplane_input(
        """\
apiVersion: pkg.crossplane.io/v1
kind: Function
metadata:
  name: render
spec:
  package: example.com/functions/render:v1.0.0
---
apiVersion: v1
kind: Secret
metadata:
  name: provider-credentials
stringData:
  token: plaintext
"""
    )
    changes = CrossplaneAdapter().analyze(data, tool_name="crossplane")
    embedded = [
        change
        for change in changes
        if change.resource_type == "crossplane_embedded_kubernetes_secret"
    ]
    assert len(embedded) == 1
    assert embedded[0].risk == "dangerous"


@pytest.mark.parametrize(
    "source",
    ["", "[]", "apiVersion: v1\nkind: ConfigMap", "{broken"],
)
def test_parser_rejects_empty_invalid_and_non_crossplane_input(source: str) -> None:
    with pytest.raises(CrossplaneInputError):
        parse_crossplane_input(source)


def test_crossplane_cli_supports_framework_checks(capsys) -> None:
    assert (
        main(
            [
                "crossplane",
                "--framework",
                "soc2",
                str(FIXTURES / "crossplane_risky.yml"),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "crossplane"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
