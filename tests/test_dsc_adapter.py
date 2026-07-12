from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.dsc import (
    DscAdapter,
    DscInputError,
    analyze_dsc,
    parse_dsc,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(name: str):
    data = parse_dsc((FIXTURES / name).read_text(encoding="utf-8"))
    return data, DscAdapter().analyze(data, tool_name="DSC")


def test_dsc_v3_document_detects_resource_and_supply_chain_risks() -> None:
    data, changes = _changes("dsc_document_risky.yaml")
    assert data["dsc"]["artifact_type"] == "document"
    kinds = {change.resource_type for change in changes}
    assert "dsc_resource_instance" in kinds
    assert "dsc_plaintext_source" in kinds
    assert "dsc_embedded_source_credential" in kinds
    assert "dsc_dependency_order" in kinds
    assert "dsc_literal_secret" in kinds
    assert "dsc_credential_reference" in kinds
    assert "dsc_evaluation_boundary" in kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 8


def test_dsc_v3_recurses_into_adapter_resources() -> None:
    _, changes = _changes("dsc_document_risky.yaml")
    nested = [change for change in changes if ".resources[0]" in change.address]
    assert nested
    assert any(change.risk == "dangerous" for change in nested)


def test_powershell_dsc_detects_execution_lcm_and_credential_risks() -> None:
    data, changes = _changes("powershell_dsc_risky.ps1")
    assert data["dsc"]["artifact_type"] == "powershell"
    kinds = {change.resource_type for change in changes}
    assert {
        "dsc_module_dependency",
        "dsc_broad_node_target",
        "dsc_resource_block",
        "dsc_privileged_credential",
        "dsc_plaintext_source",
        "dsc_plaintext_passwords",
        "dsc_constructed_plaintext_credential",
        "dsc_automatic_remediation",
        "dsc_automatic_reboot",
        "dsc_plaintext_pull_endpoint",
        "dsc_module_overwrite",
        "dsc_compilation_boundary",
    } <= kinds


def test_powershell_dsc_never_executes_source(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("PowerShell execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _changes("powershell_dsc_risky.ps1")
    assert changes


def test_dsc_json_document_and_gate_contract() -> None:
    source = """{
      "$schema": "https://aka.ms/dsc/schemas/v3/bundled/config/document.json",
      "resources": [{
        "name": "registry setting",
        "type": "Microsoft.Windows/Registry",
        "properties": {"keyPath": "HKLM\\\\Software\\\\Contoso"}
      }]
    }"""
    data = parse_dsc(source)
    gate = analyze_dsc(data)
    assert gate["adapter"] == "dsc"
    assert gate["artifact_type"] == "document"
    assert gate["total_changes"] == 2


@pytest.mark.parametrize(
    "source, message",
    [
        ("", "empty"),
        ("Write-Host hello", "not recognized"),
        (
            '{"$schema":"https://aka.ms/dsc/schema.json",'
            '"resources":[],"resources":[]}',
            "duplicate JSON key",
        ),
        (
            "$schema: https://aka.ms/dsc/schema.json\nresources: []\nresources: []\n",
            "duplicate YAML key",
        ),
        (
            '{"$schema":"https://example.invalid/schema.json","resources":[]}',
            r"DSC \$schema",
        ),
    ],
)
def test_dsc_rejects_ambiguous_or_malformed_input(source: str, message: str) -> None:
    with pytest.raises(DscInputError, match=message):
        parse_dsc(source)


def test_dsc_adapter_rejects_wrong_shape() -> None:
    assert not DscAdapter().can_handle({})
    assert not DscAdapter().can_handle({"dsc": {"artifact_type": "document"}})


def test_dsc_rejects_duplicate_resource_names() -> None:
    source = """{
      "$schema": "https://aka.ms/dsc/schemas/v3/bundled/config/document.json",
      "resources": [
        {"name":"same","type":"Contoso/One","properties":{}},
        {"name":"same","type":"Contoso/Two","properties":{}}
      ]
    }"""
    with pytest.raises(DscInputError, match="duplicate DSC resource name"):
        parse_dsc(source)


def test_secure_parameter_without_default_is_not_reported_as_literal() -> None:
    source = """{
      "$schema": "https://aka.ms/dsc/schemas/v3/bundled/config/document.json",
      "parameters": {"adminPassword": {"type": "secureString"}},
      "resources": [{"name":"one","type":"Contoso/Resource","properties":{}}]
    }"""
    data = parse_dsc(source)
    changes = DscAdapter().analyze(data, tool_name="DSC")
    assert all(change.resource_type != "dsc_literal_secret" for change in changes)


def test_comments_do_not_create_false_powershell_findings() -> None:
    data = parse_dsc(
        """Configuration SafeDsc {
        # PSDscAllowPlainTextPassword = $true
        Node 'server01' {
            File Config { DestinationPath = 'C:\\\\app'; Ensure = 'Present' }
        }
    }"""
    )
    kinds = {change.resource_type for change in DscAdapter().analyze(data, tool_name="DSC")}
    assert "dsc_plaintext_passwords" not in kinds


def test_powershell_here_string_does_not_break_comment_or_brace_scanning() -> None:
    data = parse_dsc(
        '''Configuration HereStringDsc {
        Node 'server01' {
            Script RenderConfig {
                SetScript = {
                    $content = @"
                    # not a PowerShell comment
                    { "nested": true }
"@
                    Set-Content C:\\app\\config.json $content
                }
                TestScript = { $false }
                GetScript = { @{} }
            }
        }
    }'''
    )
    changes = DscAdapter().analyze(data, tool_name="DSC")
    assert any(change.resource_type == "dsc_resource_block" for change in changes)


@pytest.mark.parametrize(
    "fixture, artifact_type",
    [
        ("dsc_document_risky.yaml", "document"),
        ("powershell_dsc_risky.ps1", "powershell"),
    ],
)
def test_dsc_cli_emits_gate_contract(
    fixture: str,
    artifact_type: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["dsc", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "dsc"
    assert payload["artifact_type"] == artifact_type
    assert payload["decision"] == "block"
