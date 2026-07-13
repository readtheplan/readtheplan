from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.sentinel import (
    SentinelAdapter,
    SentinelInputError,
    analyze_sentinel,
    parse_sentinel,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(name: str):
    path = FIXTURES / name
    data = parse_sentinel(path.read_text(encoding="utf-8"), path.name)
    return data, SentinelAdapter().analyze(data, tool_name="Sentinel")


def test_policy_detects_imports_http_fail_open_parameters_and_secrets() -> None:
    data, changes = _changes("sentinel_policy_risky.sentinel")
    assert data["sentinel"]["artifact_type"] == "policy"
    kinds = {change.resource_type for change in changes}
    assert {
        "sentinel_network_import",
        "sentinel_runtime_dependency",
        "sentinel_terraform_import",
        "sentinel_host_import",
        "sentinel_network_request",
        "sentinel_unconditional_pass",
        "sentinel_sensitive_parameter",
        "sentinel_undefined_fallback",
        "sentinel_literal_secret",
        "sentinel_evaluation_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 5


def test_policy_comments_and_strings_do_not_create_http_calls() -> None:
    data = parse_sentinel(
        """// http.get("https://ignored.example")
message = "http.send(request)"
main = rule { false }
""",
        "safe.sentinel",
    )
    changes = SentinelAdapter().analyze(data, tool_name="Sentinel")
    assert not any(change.resource_type == "sentinel_network_request" for change in changes)


def test_configuration_detects_remote_policy_plugin_paths_secrets_and_tests() -> None:
    data, changes = _changes("sentinel_config_risky.hcl")
    assert data["sentinel"]["artifact_type"] == "configuration"
    kinds = {change.resource_type for change in changes}
    assert {
        "sentinel_policy_source",
        "sentinel_policy_enforcement",
        "sentinel_executable_import_plugin",
        "sentinel_plugin_source",
        "sentinel_module_source",
        "sentinel_mock_import",
        "sentinel_mock_module_source",
        "sentinel_param_input",
        "sentinel_missing_main_assertion",
        "sentinel_runtime_configuration",
        "sentinel_literal_secret",
        "sentinel_configuration_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 7


def test_configuration_json_is_strict_and_supported() -> None:
    data = parse_sentinel(
        json.dumps(
            {
                "policy": {
                    "baseline": {
                        "source": "baseline.sentinel",
                        "enforcement_level": "hard-mandatory",
                    }
                }
            }
        ),
        "sentinel.json",
    )
    changes = SentinelAdapter().analyze(data, tool_name="Sentinel")
    assert any(change.resource_type == "sentinel_policy_enforcement" for change in changes)


def test_gate_contract_redacts_secret_values() -> None:
    data, _changes_result = _changes("sentinel_config_risky.hcl")
    gate = analyze_sentinel(data)
    rendered = json.dumps(gate)
    assert "literal-example" not in rendered
    assert gate["adapter"] == "sentinel"
    assert gate["decision"] == "block"


@pytest.mark.parametrize(
    ("source", "filename", "message"),
    [
        ("", "policy.sentinel", "empty"),
        ("this is unrelated", "policy.sentinel", "not recognized"),
        ('main = rule { "unterminated }', "policy.sentinel", "unterminated"),
        ("main = rule { true", "policy.sentinel", "unbalanced"),
        ('{"policy": {}, "policy": {}}', "sentinel.json", "duplicate JSON key"),
        ('{"unrelated": true}', "sentinel.json", "not recognized"),
        ("not valid hcl {", "sentinel.hcl", "invalid Sentinel HCL"),
    ],
)
def test_rejects_malformed_or_ambiguous_input(source: str, filename: str, message: str) -> None:
    with pytest.raises(SentinelInputError, match=message):
        parse_sentinel(source, filename)


def test_sentinel_is_never_executed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Sentinel execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _changes("sentinel_policy_risky.sentinel")
    assert changes


@pytest.mark.parametrize(
    ("fixture", "artifact_type"),
    [
        ("sentinel_policy_risky.sentinel", "policy"),
        ("sentinel_config_risky.hcl", "configuration"),
    ],
)
def test_cli_emits_gate_contract(
    fixture: str, artifact_type: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["sentinel", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "sentinel"
    assert payload["artifact_type"] == artifact_type
    assert payload["decision"] == "block"
