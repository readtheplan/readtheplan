from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.bicep import (
    BicepAdapter,
    BicepInputError,
    analyze_bicep,
    parse_bicep_source,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(fixture: str):
    source = (FIXTURES / fixture).read_text(encoding="utf-8")
    data = parse_bicep_source(source)
    return BicepAdapter().analyze(data, tool_name="Azure Bicep")


def test_bicep_source_surfaces_scope_identity_execution_exposure_and_secrets() -> None:
    changes = _changes("bicep_source_risky.bicep")
    by_type: dict[str, list] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change)

    assert by_type["bicep_target_scope"][0].risk == "dangerous"
    assert by_type["bicep_secure_parameter_default"][0].risk == "dangerous"
    assert by_type["bicep_insecure_parameter"][0].address == "param.apiToken"
    assert by_type["bicep_role_assignment"][0].risk == "dangerous"
    assert by_type["bicep_deployment_script"][0].risk == "dangerous"
    assert by_type["bicep_public_access"][0].risk == "dangerous"
    assert by_type["bicep_complete_deployment"][0].risk == "irreversible"
    assert by_type["bicep_module_source"][0].risk == "dangerous"
    assert by_type["bicep_sensitive_output"][0].risk == "dangerous"
    assert by_type["bicep_secret_function"][0].risk == "dangerous"
    assert by_type["bicep_external_file"][0].risk == "review"
    assert by_type["bicep_hardcoded_environment_url"][0].risk == "review"


def test_bicep_secure_parameter_and_private_resource_avoid_false_danger() -> None:
    changes = _changes("bicep_source_review.bicep")
    kinds = {change.resource_type for change in changes}
    assert "bicep_insecure_parameter" not in kinds
    assert "bicep_secure_parameter_default" not in kinds
    assert "bicep_public_access" not in kinds
    assert {change.risk for change in changes} == {"review"}


@pytest.mark.parametrize(
    "source,error",
    [
        ("", "empty"),
        ("this is not bicep", "recognized Bicep declaration"),
        ("resource broken 'Microsoft.Storage/storageAccounts@2023-05-01' = {", "unterminated"),
    ],
)
def test_bicep_parser_rejects_invalid_source(source: str, error: str) -> None:
    with pytest.raises(BicepInputError, match=error):
        parse_bicep_source(source)


def test_bicep_multiline_dynamic_declaration_fails_closed() -> None:
    data = parse_bicep_source(
        """resource gated 'Microsoft.Storage/storageAccounts@2023-05-01' = if (
  true
) {
  name: 'gatedstorage'
}
"""
    )
    kinds = {finding["kind"] for finding in data["bicep_findings"]}
    assert "bicep_unparsed_declaration" in kinds


def test_bicep_gate_uses_shared_contract_and_framework() -> None:
    source = (FIXTURES / "bicep_source_risky.bicep").read_text(encoding="utf-8")
    gate = analyze_bicep(parse_bicep_source(source))
    assert gate["adapter"] == "bicep"
    assert gate["decision"] == "block"
    assert gate["total_changes"] == sum(gate["risk_counts"].values())


def test_bicep_cli_reads_source(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "main.bicep"
    source.write_text(
        (FIXTURES / "bicep_source_risky.bicep").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    assert main(["bicep", "--framework", "soc2", str(source)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "bicep"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
