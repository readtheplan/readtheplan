from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.devspace import (
    DevSpaceAdapter,
    DevSpaceInputError,
    analyze_devspace,
    parse_devspace,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes():
    data = parse_devspace((FIXTURES / "devspace_risky.yaml").read_text(encoding="utf-8"))
    return data, DevSpaceAdapter().analyze(data, tool_name="DevSpace")


def test_devspace_detects_execution_build_deploy_dev_and_supply_chain_boundaries() -> None:
    data, changes = _changes()
    assert data["devspace"]["config"]["name"] == "platform"
    kinds = {change.resource_type for change in changes}
    assert {
        "devspace_config_import",
        "devspace_project_dependency",
        "devspace_shell_function",
        "devspace_pipeline_script",
        "devspace_dynamic_shell_execution",
        "devspace_execution_failure_policy",
        "devspace_image_target",
        "devspace_external_build_context",
        "devspace_image_builder",
        "devspace_dockerfile_mutation",
        "devspace_helm_deployment",
        "devspace_kubernetes_deployment",
        "devspace_external_manifest_source",
        "devspace_development_session",
        "devspace_container_execution",
        "devspace_bidirectional_file_sync",
        "devspace_port_forward",
        "devspace_ssh_tunnel",
        "devspace_custom_command",
        "devspace_profile_override",
        "devspace_profile_patch",
        "devspace_registry_credentials",
        "devspace_host_hook",
        "devspace_container_hook",
        "devspace_hook_file_transfer",
        "devspace_local_registry",
        "devspace_required_plugin",
        "devspace_literal_secret",
        "devspace_evaluation_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 25


def test_gate_contract_redacts_secret_values() -> None:
    data, _ = _changes()
    gate = analyze_devspace(data)
    assert gate["adapter"] == "devspace"
    assert gate["project_name"] == "platform"
    assert gate["decision"] == "block"
    assert "literal-example" not in json.dumps(gate)


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("", "empty"),
        ("[]", "one configuration object"),
        ("name: missing-version", "supported DevSpace version"),
        ("version: v3", "supported DevSpace version"),
        ("version: v2beta1\n---\nversion: v2beta1", "one configuration object"),
        ("version: v2beta1\nname: a\nname: b", "duplicate YAML key"),
        ("version: v2beta1\nimages: [", "invalid"),
    ],
)
def test_rejects_malformed_or_ambiguous_input(source: str, message: str) -> None:
    with pytest.raises(DevSpaceInputError, match=message):
        parse_devspace(source)


def test_devspace_never_executes_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("DevSpace execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _changes()
    assert changes


def test_cli_emits_gate_contract(capsys) -> None:
    path = FIXTURES / "devspace_risky.yaml"
    assert main(["devspace", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "devspace"
    assert payload["project_name"] == "platform"
    assert payload["decision"] == "block"
    assert "literal-example" not in json.dumps(payload)
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
