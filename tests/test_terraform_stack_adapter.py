from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.terraform_stack import (
    TerraformStackAdapter,
    TerraformStackInputError,
    analyze_terraform_stack,
    parse_terraform_stack,
)
from readtheplan.cli import main
from readtheplan.mcp_server import MCPToolInputError, agent_gate_terraform_stack
from readtheplan.project_scan import discover_project_inputs, scan_project

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(filename: str) -> dict[str, list[str]]:
    source = (FIXTURES / filename).read_text(encoding="utf-8")
    data = parse_terraform_stack(source, filename)
    grouped: dict[str, list[str]] = defaultdict(list)
    for change in TerraformStackAdapter().analyze(data):
        grouped[change.resource_type.removeprefix("terraform_stack_")].append(change.risk)
    return grouped


def test_component_stack_flags_supply_chain_secrets_fanout_and_removal() -> None:
    risks = _risks("terraform_stack_risky.tfcomponent.hcl")
    assert "review" in risks["floating_source_version"]
    assert "dangerous" in risks["unconstrained_source"]
    assert "dangerous" in risks["floating_source"]
    assert risks["literal_secret"] == ["dangerous", "dangerous"]
    assert risks["component_fanout"] == ["review"]
    assert risks["provider_fanout"] == ["review"]
    assert risks["removed_component"] == ["irreversible"]
    assert risks["secret_default"] == ["dangerous"]
    assert risks["unmarked_sensitive_input"] == ["dangerous"]
    assert risks["exposed_sensitive_output"] == ["dangerous"]


def test_deployment_stack_flags_destroy_import_approval_identity_and_sharing() -> None:
    risks = _risks("terraform_stack_risky.tfdeploy.hcl")
    assert risks["deployment_fanout"] == ["review"]
    assert risks["deployment_destroy"] == ["irreversible"]
    assert risks["deployment_import"] == ["review"]
    assert risks["automatic_approval"] == ["dangerous"]
    assert risks["group_auto_approval"] == ["dangerous"]
    assert risks["oidc_identity"] == ["review"]
    assert risks["external_store"] == ["review"]
    assert risks["cross_stack_output"] == ["dangerous"]
    assert risks["cross_stack_input"] == ["review"]


def test_gate_redacts_literal_secret_values() -> None:
    filename = "terraform_stack_risky.tfdeploy.hcl"
    source = (FIXTURES / filename).read_text(encoding="utf-8")
    payload = analyze_terraform_stack(parse_terraform_stack(source, filename))
    encoded = json.dumps(payload)
    assert payload["adapter"] == "terraform-stack"
    assert payload["artifact_type"] == "deployment"
    assert payload["decision"] == "block"
    assert "not-a-real-token" not in encoded


def test_nested_credential_fields_are_detected_without_exposing_values() -> None:
    data = parse_terraform_stack(
        '''component "service" {
          source = "./service"
          inputs = { auth = { client_secret = "nested-secret-value" } }
          providers = {}
        }''',
        "service.tfcomponent.hcl",
    )
    payload = analyze_terraform_stack(data)
    assert payload["risk_counts"]["dangerous"] == 1
    assert "nested-secret-value" not in json.dumps(payload)


def test_cli_and_mcp_emit_framework_gate(monkeypatch, tmp_path, capsys) -> None:
    source_path = FIXTURES / "terraform_stack_risky.tfcomponent.hcl"
    target = tmp_path / source_path.name
    target.write_text(source_path.read_text(encoding="utf-8"), encoding="utf-8")
    assert main(["terraform-stack", "--framework", "soc2", str(target)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "terraform-stack"
    assert payload["required_checks"]

    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    mcp_payload = agent_gate_terraform_stack(str(target), "soc2")
    assert mcp_payload["adapter"] == "terraform-stack"
    assert mcp_payload["required_checks"]


def test_project_scan_discovers_and_analyzes_both_stack_file_types(tmp_path) -> None:
    for filename in (
        "terraform_stack_risky.tfcomponent.hcl",
        "terraform_stack_risky.tfdeploy.hcl",
    ):
        (tmp_path / filename).write_text(
            (FIXTURES / filename).read_text(encoding="utf-8"), encoding="utf-8"
        )
    discovered = discover_project_inputs(tmp_path)
    assert [item.tool for item in discovered] == ["terraform-stack", "terraform-stack"]
    payload = scan_project(tmp_path, display_root=str(tmp_path))
    assert payload["scanned_file_count"] == 2
    assert payload["error_count"] == 0
    assert payload["decision"] == "block"


@pytest.mark.parametrize(
    ("source", "filename"),
    [
        ("", "stack.tfcomponent.hcl"),
        ("resource \"x\" \"y\" {}", "stack.tfcomponent.hcl"),
        (
            'component "x" { source = "./x" inputs = {} providers = {} }\n'
            'resource "x" "y" {}',
            "stack.tfcomponent.hcl",
        ),
        ("deployment \"x\" { inputs = {} }", "stack.tfcomponent.hcl"),
        ("component \"x\" { source = \"./x\" }", "main.tf"),
        ("locals { value = 1 }", "stack.tfdeploy.hcl"),
    ],
)
def test_parser_rejects_invalid_or_mismatched_inputs(source: str, filename: str) -> None:
    with pytest.raises(TerraformStackInputError):
        parse_terraform_stack(source, filename)


def test_mcp_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.tfdeploy.hcl"
    outside.write_text('deployment "x" { inputs = {} }', encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))
    with pytest.raises(MCPToolInputError):
        agent_gate_terraform_stack(str(outside))
