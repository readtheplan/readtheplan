from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.cfengine import (
    CFEngineAdapter,
    CFEngineInputError,
    analyze_cfengine,
    parse_cfengine,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(name: str):
    data = parse_cfengine((FIXTURES / name).read_text(encoding="utf-8"))
    return data, CFEngineAdapter().analyze(data, tool_name="CFEngine")


def test_cfengine_policy_detects_promises_controls_and_boundaries() -> None:
    data, changes = _changes("cfengine_policy_risky.cf")
    assert data["cfengine"]["artifact_type"] == "policy"
    kinds = {change.resource_type for change in changes}
    assert {
        "cfengine_policy_inputs",
        "cfengine_bundle_sequence",
        "cfengine_missing_input_bypass",
        "cfengine_broad_server_trust",
        "cfengine_clock_validation_bypass",
        "cfengine_scheduled_agent_command",
        "cfengine_execution_schedule",
        "cfengine_commands_promise",
        "cfengine_files_promise",
        "cfengine_packages_promise",
        "cfengine_services_promise",
        "cfengine_processes_promise",
        "cfengine_users_promise",
        "cfengine_methods_promise",
        "cfengine_custom_compliance_promise",
        "cfengine_access_promise",
        "cfengine_roles_promise",
        "cfengine_evaluation_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 16


def test_cfengine_policy_detects_secrets_sources_permissions_and_dependencies() -> None:
    _, changes = _changes("cfengine_policy_risky.cf")
    kinds = {change.resource_type for change in changes}
    assert "cfengine_literal_secret" in kinds
    assert "cfengine_plaintext_source" in kinds
    assert "cfengine_world_writable_permissions" in kinds
    assert "cfengine_promise_dependency" in kinds
    assert "cfengine_dynamic_evaluation" in kinds
    assert "cfengine_embedded_source_credential" in kinds


def test_cfengine_reports_are_safe_but_runtime_boundary_is_review() -> None:
    _, changes = _changes("cfengine_policy_risky.cf")
    report = next(c for c in changes if c.resource_type == "cfengine_reports_promise")
    boundary = next(c for c in changes if c.resource_type == "cfengine_evaluation_boundary")
    assert report.risk == "safe"
    assert boundary.risk == "review"


def test_cfengine_augments_detects_autorun_inputs_secrets_and_nested_data() -> None:
    data, changes = _changes("cfengine_augments_risky.json")
    assert data["cfengine"]["artifact_type"] == "augments"
    kinds = {change.resource_type for change in changes}
    assert {
        "cfengine_policy_input",
        "cfengine_autorun_class",
        "cfengine_augmented_class",
        "cfengine_execution_extension",
        "cfengine_literal_secret",
        "cfengine_nested_augments",
        "cfengine_augments_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 5


def test_cfengine_gate_contract_identifies_artifact() -> None:
    data = parse_cfengine((FIXTURES / "cfengine_policy_risky.cf").read_text())
    gate = analyze_cfengine(data)
    assert gate["adapter"] == "cfengine"
    assert gate["artifact_type"] == "policy"
    assert gate["total_changes"] > 20
    assert gate["decision"] == "block"


def test_cfengine_source_is_never_executed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("CFEngine execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _changes("cfengine_policy_risky.cf")
    assert changes


@pytest.mark.parametrize(
    "source, message",
    [
        ("", "empty"),
        ("reports: 'hello';", "not recognized"),
        ('{"unrelated": true}', "not recognized as CFEngine Augments"),
        ('{"classes": {}, "classes": {}}', "duplicate JSON key"),
        ('{"classes": ', "invalid CFEngine Augments JSON"),
        ('{"inputs": {"bad": true}}', "inputs must be a string or array"),
        ("bundle agent main { commands: '/bin/true';", "unterminated bundle"),
        ('bundle agent main { reports: "unterminated; }', "unterminated quoted string"),
        (
            'bundle agent main {\n reports:\n "missing semicolon"\n }',
            "unterminated CFEngine",
        ),
    ],
)
def test_cfengine_rejects_malformed_or_ambiguous_input(source: str, message: str) -> None:
    with pytest.raises(CFEngineInputError, match=message):
        parse_cfengine(source)


def test_cfengine_comments_do_not_create_findings() -> None:
    data = parse_cfengine(
        '''bundle agent main
        {
          # commands:
          #   "/bin/rm -rf /";
          reports:
            "safe report";
        }
        '''
    )
    changes = CFEngineAdapter().analyze(data, tool_name="CFEngine")
    kinds = {change.resource_type for change in changes}
    assert "cfengine_commands_promise" not in kinds
    assert "cfengine_reports_promise" in kinds


def test_cfengine_accepts_compact_one_line_policy() -> None:
    data = parse_cfengine('bundle agent main { reports: "hello"; }')
    changes = CFEngineAdapter().analyze(data, tool_name="CFEngine")
    assert any(change.resource_type == "cfengine_reports_promise" for change in changes)


def test_cfengine_adapter_rejects_wrong_shape() -> None:
    assert not CFEngineAdapter().can_handle({})
    assert not CFEngineAdapter().can_handle({"cfengine": {"artifact_type": "policy"}})


def test_augments_duplicate_input_names_are_strict_json() -> None:
    source = json.dumps({"classes": {"production": ["any::"]}})
    assert parse_cfengine(source)["cfengine"]["artifact_type"] == "augments"


@pytest.mark.parametrize(
    "fixture, artifact_type",
    [
        ("cfengine_policy_risky.cf", "policy"),
        ("cfengine_augments_risky.json", "augments"),
    ],
)
def test_cfengine_cli_emits_gate_contract(
    fixture: str,
    artifact_type: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["cfengine", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "cfengine"
    assert payload["artifact_type"] == artifact_type
    assert payload["decision"] == "block"
