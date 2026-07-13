from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.cue import CueAdapter, CueInputError, analyze_cue, parse_cue
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _tool_changes():
    path = FIXTURES / "deploy_risky_tool.cue"
    data = parse_cue(path.read_text(encoding="utf-8"), path.name)
    return data, CueAdapter().analyze(data, tool_name="CUE")


def test_cue_tool_detects_workflow_process_file_http_os_and_dynamic_boundaries() -> None:
    data, changes = _tool_changes()
    assert data["cue"]["artifact_type"] == "tool"
    kinds = {change.resource_type for change in changes}
    assert {
        "cue_workflow_capability_import",
        "cue_module_import",
        "cue_workflow_command",
        "cue_interactive_task",
        "cue_process_task",
        "cue_file_mutation_task",
        "cue_http_task",
        "cue_os_state_task",
        "cue_fail_open_process",
        "cue_external_file_path",
        "cue_network_endpoint",
        "cue_literal_secret",
        "cue_embedded_file",
        "cue_runtime_injection_or_constraint",
        "cue_generated_configuration",
        "cue_evaluation_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 8


def test_module_metadata_tracks_identity_dependencies_source_and_registry_boundary() -> None:
    path = FIXTURES / "cue_module_risky.cue"
    data = parse_cue(path.read_text(encoding="utf-8"), "module.cue")
    changes = CueAdapter().analyze(data, tool_name="CUE")
    assert data["cue"]["artifact_type"] == "module"
    by_type = {change.resource_type for change in changes}
    assert {
        "cue_module_identity",
        "cue_module_dependency",
        "cue_module_source",
        "cue_registry_resolution_boundary",
        "cue_evaluation_boundary",
    } <= by_type
    dependencies = [change for change in changes if change.resource_type == "cue_module_dependency"]
    assert {change.risk for change in dependencies} == {"review", "dangerous"}


def test_local_module_replacements_distinguish_local_and_pinned_module() -> None:
    path = FIXTURES / "cue_local_module_risky.cue"
    data = parse_cue(path.read_text(encoding="utf-8"), "local-module.cue")
    changes = CueAdapter().analyze(data, tool_name="CUE")
    replacements = [
        change for change in changes if change.resource_type == "cue_module_replacement"
    ]
    assert [change.risk for change in replacements] == ["dangerous", "review"]


def test_gate_contract_redacts_secret_values() -> None:
    data, _ = _tool_changes()
    gate = analyze_cue(data)
    assert gate["adapter"] == "cue"
    assert gate["artifact_type"] == "tool"
    assert gate["decision"] == "block"
    assert "literal-example" not in json.dumps(gate)


@pytest.mark.parametrize(
    ("source", "filename"),
    [
        ("", "config.cue"),
        ("hello world", "config.cue"),
        ("package example", "config.txt"),
    ],
)
def test_rejects_non_cue_input(source: str, filename: str) -> None:
    with pytest.raises(CueInputError):
        parse_cue(source, filename)


def test_cue_never_executes_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("CUE execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _tool_changes()
    assert changes


def test_cli_emits_gate_contract(capsys) -> None:
    path = FIXTURES / "deploy_risky_tool.cue"
    assert main(["cue", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "cue"
    assert payload["artifact_type"] == "tool"
    assert payload["decision"] == "block"
    assert "literal-example" not in json.dumps(payload)
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
