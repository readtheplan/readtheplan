from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.helm import HelmAdapter, HelmInputError, parse_helm_source
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(fixture: str) -> dict[str, list[str]]:
    data = parse_helm_source((FIXTURES / fixture).read_text(encoding="utf-8"))
    result: dict[str, list[str]] = defaultdict(list)
    for change in HelmAdapter().analyze(data, tool_name="helm"):
        result[change.resource_type].append(change.risk)
    return result


def test_chart_metadata_surfaces_dependencies_versioning_and_transport() -> None:
    risks = _risks("helm_chart_risky.yml")
    assert risks["helm_chart_metadata"] == ["review"]
    assert risks["helm_legacy_chart_api"] == ["review"]
    assert risks["helm_unconstrained_kubernetes"] == ["review"]
    assert risks["helm_deprecated_chart"] == ["dangerous"]
    assert risks["helm_chart_dependency"] == ["dangerous"]
    assert risks["helm_unpinned_dependency"] == ["dangerous"]
    assert risks["helm_plaintext_repository"] == ["dangerous"]
    assert risks["helm_conditional_dependency"] == ["review"]
    assert risks["helm_imported_values"] == ["review"]


def test_values_surface_images_exposure_privilege_and_secrets() -> None:
    risks = _risks("helm_values_risky.yml")
    assert risks["helm_values"] == ["review"]
    assert risks["helm_container_image"] == ["dangerous"]
    assert risks["helm_service_exposure"] == ["dangerous"]
    assert risks["helm_public_exposure"] == ["dangerous"]
    assert len(risks["helm_privileged_workload"]) == 2
    assert len(risks["helm_disabled_hardening"]) == 2
    assert risks["helm_service_account_token"] == ["dangerous"]
    assert risks["helm_plaintext_endpoint"] == ["dangerous"]
    assert risks["helm_secret_material"] == ["dangerous"]


def test_template_surfaces_cluster_dynamic_file_hook_and_secret_functions() -> None:
    risks = _risks("helm_template_risky.yaml")
    assert risks["helm_template_execution"] == ["review"]
    assert risks["helm_cluster_lookup"] == ["dangerous"]
    assert risks["helm_dynamic_template"] == ["dangerous"]
    assert risks["helm_chart_file_access"] == ["review"]
    assert risks["helm_named_template"] == ["review"]
    assert risks["helm_nondeterministic_template"] == ["review"]
    assert risks["helm_generated_secret"] == ["dangerous"]
    assert risks["helm_dns_lookup"] == ["dangerous"]
    assert risks["helm_release_hook"] == ["dangerous"]
    assert risks["helm_hook_deletion"] == ["dangerous"]
    assert risks["helm_unresolved_values"] == ["review"]
    assert risks["helm_cluster_capabilities"] == ["review"]


def test_pinned_chart_values_image_is_review() -> None:
    data = parse_helm_source("image:\n  repository: example/platform\n  digest: sha256:abcdef\n")
    changes = HelmAdapter().analyze(data, tool_name="helm")
    risks = {change.resource_type: change.risk for change in changes}
    assert risks["helm_container_image"] == "review"


@pytest.mark.parametrize("source", ["", "[]", "{{ .Values.image", "- item"])
def test_parser_rejects_invalid_inputs(source: str) -> None:
    with pytest.raises(HelmInputError):
        parse_helm_source(source)


@pytest.mark.parametrize(
    "fixture", ["helm_chart_risky.yml", "helm_values_risky.yml", "helm_template_risky.yaml"]
)
def test_helm_cli_supports_all_artifacts(capsys, fixture: str) -> None:
    assert main(["helm", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "helm"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
