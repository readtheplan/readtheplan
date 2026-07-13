from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.spacelift import (
    SpaceliftAdapter,
    SpaceliftInputError,
    analyze_spacelift,
    parse_spacelift,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes():
    data = parse_spacelift((FIXTURES / "spacelift_runtime_risky.yml").read_text(encoding="utf-8"))
    return data, SpaceliftAdapter().analyze(data, tool_name="Spacelift")


def test_spacelift_detects_runtime_execution_identity_and_precedence_boundaries() -> None:
    data, changes = _changes()
    assert isinstance(detect_adapter(data), SpaceliftAdapter)
    kinds = {change.resource_type for change in changes}
    assert {
        "spacelift_legacy_precedence",
        "spacelift_runner_image",
        "spacelift_workflow_hook",
        "spacelift_runtime_environment",
        "spacelift_literal_secret_environment",
        "spacelift_sparse_checkout_path",
        "spacelift_stack_override",
        "spacelift_project_root",
        "spacelift_workflow_tool",
        "spacelift_terragrunt_configuration",
        "spacelift_terragrunt_run_all",
        "spacelift_managed_state",
        "spacelift_workflow_version",
        "spacelift_module_test",
        "spacelift_unknown_top_level_settings",
        "spacelift_evaluation_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 10


def test_gate_contract_redacts_commands_and_secret_values() -> None:
    data, _ = _changes()
    gate = analyze_spacelift(data)
    encoded = json.dumps(gate)
    assert gate["adapter"] == "spacelift"
    assert gate["configuration_scope"] == "repository"
    assert gate["stack_count"] == 2
    assert gate["decision"] == "block"
    assert "literal-example-token" not in encoded
    assert "bootstrap.sh" not in encoded
    assert "auto-approve" not in encoded


def test_single_stack_runtime_configuration_is_supported() -> None:
    data = parse_spacelift(
        'runner_image: "runner@example.invalid/acme/worker@sha256:' + "a" * 64 + '"\n'
    )
    gate = analyze_spacelift(data)
    assert gate["configuration_scope"] == "single-stack"
    assert gate["stack_count"] == 0
    changes = SpaceliftAdapter().analyze(data, tool_name="Spacelift")
    assert any(change.resource_type == "spacelift_single_stack_runtime" for change in changes)


def test_module_version_requires_stable_semver() -> None:
    stable = parse_spacelift('version: "2"\nmodule_version: "1.2.3"\ntests: []\n')
    preview = parse_spacelift('version: "2"\nmodule_version: "1.2.3-rc.1"\ntests: []\n')
    stable_change = next(
        change
        for change in SpaceliftAdapter().analyze(stable, tool_name="Spacelift")
        if change.resource_type == "spacelift_module_version"
    )
    preview_change = next(
        change
        for change in SpaceliftAdapter().analyze(preview, tool_name="Spacelift")
        if change.resource_type == "spacelift_module_version"
    )
    assert stable_change.risk == "review"
    assert preview_change.risk == "dangerous"


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("", "empty"),
        ("[]", "one configuration object"),
        ("version: '2'", "must declare"),
        ("stack_defaults: []", "stack_defaults must be a mapping"),
        ("stacks: []", "stacks must be a mapping"),
        ("tests: {}", "tests must be a list"),
        ("stacks: {}\n---\nstacks: {}", "one configuration object"),
        ("stacks: {}\nstacks: {}", "duplicate YAML key"),
        ("stacks: [", "invalid"),
    ],
)
def test_rejects_malformed_or_ambiguous_input(source: str, message: str) -> None:
    with pytest.raises(SpaceliftInputError, match=message):
        parse_spacelift(source)


def test_spacelift_never_executes_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Spacelift execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _changes()
    assert changes


def test_cli_emits_gate_contract(capsys) -> None:
    path = FIXTURES / "spacelift_runtime_risky.yml"
    assert main(["spacelift", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "spacelift"
    assert payload["stack_count"] == 2
    assert payload["decision"] == "block"
    assert "literal-example-token" not in json.dumps(payload)
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
