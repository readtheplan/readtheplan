from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.kustomize import (
    KustomizeAdapter,
    KustomizeInputError,
    parse_kustomization,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks() -> dict[str, list[str]]:
    data = parse_kustomization((FIXTURES / "kustomization_risky.yml").read_text(encoding="utf-8"))
    result: dict[str, list[str]] = defaultdict(list)
    for change in KustomizeAdapter().analyze(data, tool_name="kustomize"):
        result[change.resource_type].append(change.risk)
    return result


def test_kustomization_surfaces_composition_generators_patches_images_and_plugins() -> None:
    risks = _risks()
    assert len(risks["kustomize_resource_reference"]) == 2
    assert len(risks["kustomize_remote_resource"]) == 2
    assert risks["kustomize_unpinned_remote"] == ["dangerous"]
    assert len(risks["kustomize_patch"]) == 2
    assert risks["kustomize_replacement"] == ["review"]
    assert risks["kustomize_config_generator"] == ["review"]
    assert risks["kustomize_secret_generator"] == ["dangerous"]
    assert len(risks["kustomize_secret_material"]) == 2
    assert len(risks["kustomize_external_generator_input"]) == 2
    assert risks["kustomize_stable_generated_name"] == ["dangerous"]
    assert risks["kustomize_image_override"] == ["dangerous", "review"]
    assert risks["kustomize_helm_inflation"] == ["dangerous"]
    assert risks["kustomize_unpinned_chart"] == ["dangerous"]
    assert risks["kustomize_plaintext_repository"] == ["dangerous"]
    assert risks["kustomize_helm_values"] == ["review"]
    assert risks["kustomize_generator_plugin"] == ["dangerous"]
    assert risks["kustomize_transformer_plugin"] == ["dangerous"]
    assert risks["kustomize_openapi_schema"] == ["review"]
    assert risks["kustomize_deprecated_vars"] == ["review"]
    assert risks["kustomize_replica_override"] == ["review"]


def test_pinned_remote_and_digest_do_not_emit_unpinned_findings() -> None:
    data = parse_kustomization(
        "resources:\n  - https://github.com/example/base?ref=v1.0.0\n"
        "images:\n  - name: app\n    digest: sha256:abcdef\n"
    )
    changes = KustomizeAdapter().analyze(data, tool_name="kustomize")
    kinds = {change.resource_type for change in changes}
    assert "kustomize_unpinned_remote" not in kinds
    assert {
        change.risk for change in changes if change.resource_type == "kustomize_image_override"
    } == {"review"}


@pytest.mark.parametrize("source", ["", "[]", "apiVersion: v1\nkind: ConfigMap", "{broken"])
def test_parser_rejects_invalid_or_unrecognized_input(source: str) -> None:
    with pytest.raises(KustomizeInputError):
        parse_kustomization(source)


def test_kustomize_cli_supports_framework_checks(capsys) -> None:
    assert (
        main(["kustomize", "--framework", "soc2", str(FIXTURES / "kustomization_risky.yml")]) == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "kustomize"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
