from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.jsonnet import (
    JsonnetAdapter,
    JsonnetInputError,
    analyze_jsonnet,
    parse_jsonnet,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(name: str):
    path = FIXTURES / name
    logical_names = {
        "tanka_spec_risky.json": "spec.json",
        "jsonnetfile_risky.json": "jsonnetfile.json",
        "jsonnetfile_lock_risky.json": "jsonnetfile.lock.json",
    }
    data = parse_jsonnet(path.read_text(encoding="utf-8"), logical_names.get(name, path.name))
    return data, JsonnetAdapter().analyze(data, tool_name="Jsonnet/Tanka")


def test_source_detects_imports_native_renderers_targets_secrets_and_boundaries() -> None:
    data, changes = _analyze("tanka_main_risky.jsonnet")
    assert data["jsonnet"]["artifact_type"] == "source"
    kinds = {change.resource_type for change in changes}
    assert {
        "jsonnet_import_dependency",
        "jsonnet_importstr_dependency",
        "jsonnet_importbin_dependency",
        "jsonnet_dynamic_import",
        "jsonnet_external_variable",
        "jsonnet_native_callback",
        "jsonnet_helm_render",
        "jsonnet_kustomize_render",
        "jsonnet_generated_kubernetes",
        "jsonnet_generated_configuration",
        "jsonnet_tanka_targeting",
        "jsonnet_credential_data",
        "jsonnet_evaluation_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 7


def test_tanka_environment_tracks_cluster_diff_ownership_and_boundary() -> None:
    data, changes = _analyze("tanka_spec_risky.json")
    assert data["jsonnet"]["artifact_type"] == "tanka-environment"
    assert {
        "jsonnet_tanka_environment",
        "jsonnet_cluster_endpoint",
        "jsonnet_kubeconfig_context",
        "jsonnet_sensitive_namespace",
        "jsonnet_subset_diff",
        "jsonnet_ownership_labels_disabled",
        "jsonnet_cluster_boundary",
    } <= {change.resource_type for change in changes}


def test_manifest_distinguishes_floating_and_pinned_dependencies() -> None:
    _, changes = _analyze("jsonnetfile_risky.json")
    dependencies = [
        change for change in changes if change.resource_type == "jsonnet_direct_dependency"
    ]
    assert [change.risk for change in dependencies] == ["dangerous", "review"]


def test_lock_requires_immutable_version_and_sha256() -> None:
    data, changes = _analyze("jsonnetfile_lock_risky.json")
    assert data["jsonnet"]["artifact_type"] == "lock"
    dependencies = [
        change for change in changes if change.resource_type == "jsonnet_locked_dependency"
    ]
    assert [change.risk for change in dependencies] == ["review", "dangerous"]


def test_gate_redacts_secret_values() -> None:
    data, _ = _analyze("tanka_main_risky.jsonnet")
    gate = analyze_jsonnet(data)
    assert gate["adapter"] == "jsonnet"
    assert gate["decision"] == "block"
    assert "literal-example" not in json.dumps(gate)


@pytest.mark.parametrize(
    ("source", "filename"),
    [
        ("", "main.jsonnet"),
        ("hello world", "main.jsonnet"),
        ("{}", "main.txt"),
        ('{"apiVersion":"v1","kind":"Other"}', "spec.json"),
        ('{"dependencies":[],"dependencies":[]}', "jsonnetfile.json"),
    ],
)
def test_rejects_invalid_input(source: str, filename: str) -> None:
    with pytest.raises(JsonnetInputError):
        parse_jsonnet(source, filename)


def test_jsonnet_never_executes_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "subprocess.run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("execution forbidden")),
    )
    _, changes = _analyze("tanka_main_risky.jsonnet")
    assert changes


@pytest.mark.parametrize("command", ["jsonnet", "tanka"])
def test_cli_aliases_emit_gate_contract(command: str, capsys) -> None:
    path = FIXTURES / "tanka_main_risky.jsonnet"
    assert main([command, "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "jsonnet"
    assert payload["decision"] == "block"
    assert "literal-example" not in json.dumps(payload)
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
