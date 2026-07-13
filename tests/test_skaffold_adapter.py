from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.skaffold import (
    SkaffoldAdapter,
    SkaffoldInputError,
    analyze_skaffold,
    parse_skaffold,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes():
    data = parse_skaffold((FIXTURES / "skaffold_risky.yaml").read_text(encoding="utf-8"))
    return data, SkaffoldAdapter().analyze(data, tool_name="Skaffold")


def test_skaffold_detects_build_render_deploy_actions_profiles_and_boundaries() -> None:
    data, changes = _changes()
    assert len(data["skaffold"]["configs"]) == 2
    kinds = {change.resource_type for change in changes}
    assert {
        "skaffold_legacy_api_version",
        "skaffold_config_dependency",
        "skaffold_build_backend",
        "skaffold_insecure_registry",
        "skaffold_image_target",
        "skaffold_external_build_context",
        "skaffold_custom_build",
        "skaffold_artifact_builder",
        "skaffold_build_reproducibility",
        "skaffold_host_hook",
        "skaffold_mutable_tag_policy",
        "skaffold_manifest_source",
        "skaffold_kustomize_render",
        "skaffold_kustomize_plugin_boundary",
        "skaffold_helm_render",
        "skaffold_deployment_engine",
        "skaffold_deployment_validation_bypass",
        "skaffold_container_hook",
        "skaffold_verification_action",
        "skaffold_cluster_verification",
        "skaffold_execution_image",
        "skaffold_container_command",
        "skaffold_custom_action",
        "skaffold_port_forward",
        "skaffold_profile_override",
        "skaffold_profile_patch",
        "skaffold_literal_secret",
        "skaffold_evaluation_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 20


def test_digest_pinned_supporting_image_is_review() -> None:
    _, changes = _changes()
    image = next(
        change
        for change in changes
        if change.address == "config.supporting.build.artifacts[0].image"
    )
    assert image.risk == "review"


def test_gate_contract_redacts_secrets() -> None:
    data, _ = _changes()
    gate = analyze_skaffold(data)
    assert gate["adapter"] == "skaffold"
    assert gate["config_count"] == 2
    assert gate["decision"] == "block"
    assert "literal-example" not in json.dumps(gate)


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("", "empty"),
        ("[]", "objects"),
        ("kind: Config\napiVersion: other/v1", "Skaffold Config"),
        ("apiVersion: skaffold/v4beta13\nkind: Other", "Skaffold Config"),
        (
            "apiVersion: skaffold/v4beta13\nkind: Config\nbuild: {}\nbuild: {}",
            "duplicate YAML key",
        ),
        ("apiVersion: skaffold/v4beta13\nkind: Config\nbuild: [", "invalid"),
    ],
)
def test_rejects_malformed_or_ambiguous_input(source: str, message: str) -> None:
    with pytest.raises(SkaffoldInputError, match=message):
        parse_skaffold(source)


def test_skaffold_never_executes_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Skaffold execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _changes()
    assert changes


def test_cli_emits_gate_contract(capsys) -> None:
    path = FIXTURES / "skaffold_risky.yaml"
    assert main(["skaffold", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "skaffold"
    assert payload["config_count"] == 2
    assert payload["decision"] == "block"
    assert "literal-example" not in json.dumps(payload)
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
