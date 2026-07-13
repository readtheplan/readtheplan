from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.terramate import (
    TerramateAdapter,
    TerramateInputError,
    analyze_terramate,
    parse_terramate,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(name: str):
    path = FIXTURES / name
    data = parse_terramate(path.read_text(encoding="utf-8"), path.name)
    return data, TerramateAdapter().analyze(data, tool_name="Terramate")


def test_configuration_detects_orchestration_generation_execution_and_sharing() -> None:
    data, changes = _analyze("terramate_risky.tm.hcl")
    assert data["terramate"]["artifact_type"] == "configuration"
    kinds = {change.resource_type for change in changes}
    assert {
        "terramate_project_configuration",
        "terramate_disabled_orchestration_safeguards",
        "terramate_run_environment",
        "terramate_executable_path_override",
        "terramate_cloud_integration",
        "terramate_weakened_change_detection",
        "terramate_experimental_features",
        "terramate_stack",
        "terramate_stack_orchestration_edge",
        "terramate_external_change_trigger",
        "terramate_configuration_import",
        "terramate_vendor_configuration",
        "terramate_generated_file",
        "terramate_generated_hcl",
        "terramate_conditional_generation",
        "terramate_fail_open_generation_assertion",
        "terramate_generation_file_read",
        "terramate_module_vendoring",
        "terramate_dynamic_generation_input",
        "terramate_script",
        "terramate_command",
        "terramate_mutating_command",
        "terramate_cloud_result_sync",
        "terramate_mocked_dependency_fail_open",
        "terramate_output_sharing_backend",
        "terramate_unsafe_sharing_destination",
        "terramate_shared_stack_input",
        "terramate_shared_stack_output",
        "terramate_literal_secret",
        "terramate_evaluation_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 18


def test_tmgen_tracks_blueprint_functions_and_evaluation_boundary() -> None:
    data, changes = _analyze("backend_risky.tf.tmgen")
    assert data["terramate"]["artifact_type"] == "tmgen"
    assert {
        "terramate_hcl_blueprint",
        "terramate_generation_file_read",
        "terramate_module_vendoring",
        "terramate_dynamic_generation_input",
        "terramate_evaluation_boundary",
    } <= {change.resource_type for change in changes}


def test_gate_redacts_literal_credentials() -> None:
    data, _ = _analyze("terramate_risky.tm.hcl")
    gate = analyze_terramate(data)
    encoded = json.dumps(gate)
    assert gate["adapter"] == "terramate"
    assert gate["decision"] == "block"
    assert "literal-terramate-token" not in encoded
    assert "literal-database-password" not in encoded


@pytest.mark.parametrize(
    ("source", "filename", "error"),
    [
        ("", "config.tm.hcl", "empty"),
        ("stack {}", "config.hcl", "filename"),
        ("locals { value = true }", "config.tm.hcl", "recognizable"),
        ("stack {", "config.tm.hcl", "invalid Terramate HCL"),
        ('{"stack":{},"stack":{}}', "config.tm.json", "duplicate JSON key"),
    ],
)
def test_rejects_invalid_unrelated_or_duplicate_input(
    source: str, filename: str, error: str
) -> None:
    with pytest.raises(TerramateInputError, match=error):
        parse_terramate(source, filename)


def test_terramate_never_generates_or_executes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Terramate execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _analyze("terramate_risky.tm.hcl")
    assert changes


@pytest.mark.parametrize(
    ("fixture", "artifact"),
    [
        ("terramate_risky.tm.hcl", "configuration"),
        ("backend_risky.tf.tmgen", "tmgen"),
    ],
)
def test_cli_supports_configuration_and_tmgen(capsys, fixture: str, artifact: str) -> None:
    path = FIXTURES / fixture
    assert main(["terramate", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "terramate"
    assert payload["artifact_type"] == artifact
    assert payload["decision"] == "block"
    assert "literal-terramate-token" not in json.dumps(payload)
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
