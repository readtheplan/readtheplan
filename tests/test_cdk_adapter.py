from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from readtheplan.adapters.cdk import (
    CdkAdapter,
    CdkInputError,
    analyze_cdk,
    parse_cdk_manifest,
)
from readtheplan.cli import main
from readtheplan.mcp_server import MCPToolInputError, agent_gate_cdk

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(fixture: str):
    data = parse_cdk_manifest((FIXTURES / fixture).read_text(encoding="utf-8"))
    return CdkAdapter().analyze(data, tool_name="AWS CDK")


def test_assembly_surfaces_context_stack_roles_metadata_graph_and_boundaries() -> None:
    changes = _changes("cdk_assembly_risky.json")
    kinds = {change.resource_type for change in changes}

    assert len(changes) == 16
    assert sum(change.risk == "dangerous" for change in changes) == 9
    assert "cdk_missing_context" in kinds
    assert "cdk_cloudformation_stack" in kinds
    assert "cdk_disabled_template_validation" in kinds
    assert "cdk_literal_stack_parameter_secret" in kinds
    assert "cdk_synthesis_error" in kinds
    assert "cdk_nested_assembly" in kinds
    assert "cdk_missing_artifact_dependency" in kinds
    assert "cdk_cyclic_artifact_dependency" in kinds
    unknown = next(
        change for change in changes if change.address == "assembly.artifact.VendorInstruction"
    )
    assert unknown.risk == "dangerous"
    stack = next(change for change in changes if change.resource_type == "cdk_cloudformation_stack")
    assert "privileged role" in stack.explanation
    assert "escapes" in stack.explanation


def test_asset_manifest_surfaces_executables_docker_secrets_ssh_network_and_tags() -> None:
    changes = _changes("cdk_assets_risky.json")
    files = [change for change in changes if change.resource_type == "cdk_file_asset"]
    images = [change for change in changes if change.resource_type == "cdk_docker_image_asset"]

    assert len(changes) == 6
    assert len(files) == 2
    assert len(images) == 2
    assert sum(change.risk == "dangerous" for change in changes) == 2
    assert any("external command" in change.explanation for change in files)
    risky_image = next(change for change in images if change.risk == "dangerous")
    assert "SSH credentials" in risky_image.explanation
    assert "secret mount" in risky_image.explanation
    assert "host network" in risky_image.explanation
    assert "not content-addressed" in risky_image.explanation


def test_minimal_hardened_assembly_stays_review_only() -> None:
    data = parse_cdk_manifest(
        json.dumps(
            {
                "version": "38.0.1",
                "artifacts": {
                    "Stack": {
                        "type": "aws:cloudformation:stack",
                        "environment": "aws://111111111111/us-east-1",
                        "properties": {"templateFile": "Stack.template.json"},
                    }
                },
            }
        )
    )
    changes = CdkAdapter().analyze(data)
    assert {change.risk for change in changes} == {"review"}


@pytest.mark.parametrize(
    ("source", "error"),
    [
        ("", "empty"),
        ("[]", "must be a JSON object"),
        ('{"hello":"world"}', "not a recognized"),
        ('{"version":"1","version":"2","artifacts":{}}', "duplicate JSON key"),
        ('{"version":"1","artifacts":[]}', "artifacts must be a JSON object"),
        (
            '{"version":"1","artifacts":{"Stack":{"properties":{}}}}',
            "must have a type",
        ),
        ('{"version":"1","files":{"asset":[]}}', "must be a JSON object"),
        (
            '{"version":"1","dockerImages":{"image":{"destinations":[]}}}',
            "destinations must be a JSON object",
        ),
        (
            '{"version":"1","artifacts":{"Stack":{"type":'
            '"aws:cloudformation:stack","dependencies":[1]}}}',
            "dependencies must contain only strings",
        ),
        (
            '{"version":"1","dockerImages":{"image":{"dockerBuildContexts":[], '
            '"destinations":{}}}}',
            "dockerBuildContexts must be a JSON object",
        ),
    ],
)
def test_parser_rejects_unrelated_duplicate_or_malformed_input(source: str, error: str) -> None:
    with pytest.raises(CdkInputError, match=error):
        parse_cdk_manifest(source)


def test_parser_rejects_deeply_nested_json_as_input_error() -> None:
    with (
        patch("readtheplan.adapters.cdk.json.loads", side_effect=RecursionError),
        pytest.raises(CdkInputError, match="deeply nested JSON"),
    ):
        parse_cdk_manifest('{"version":"1","artifacts":{}}')


def test_cdk_public_surfaces_reject_deep_json_without_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    input_path = FIXTURES / "cdk_assembly_risky.json"

    with patch("readtheplan.adapters.cdk.json.loads", side_effect=RecursionError):
        exit_code = main(["cdk", str(input_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "deeply nested JSON" in captured.err
    assert "Traceback" not in captured.err

    with (
        patch("readtheplan.adapters.cdk.json.loads", side_effect=RecursionError),
        pytest.raises(MCPToolInputError) as exc_info,
    ):
        agent_gate_cdk(str(input_path))

    assert exc_info.value.code == "INVALID_INPUT"
    assert "deeply nested JSON" in exc_info.value.message


def test_cli_has_last_resort_recursion_guard(capsys: pytest.CaptureFixture[str]) -> None:
    input_path = FIXTURES / "cdk_assembly_risky.json"

    with patch(
        "readtheplan.adapters.cdk.parse_cdk_manifest",
        side_effect=RecursionError,
    ):
        exit_code = main(["cdk", str(input_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "Error: input contains deeply nested data\n"
    assert "Traceback" not in captured.err


def test_cdk_mcp_rejects_non_utf8_with_stable_error(tmp_path: Path) -> None:
    input_path = tmp_path / "cdk.json"
    input_path.write_bytes(b"\xff\xfe")

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_cdk(str(input_path))

    assert exc_info.value.code == "INPUT_ERROR"
    assert exc_info.value.message == f"CDK input is not valid UTF-8: {input_path}"


@pytest.mark.parametrize(
    ("fixture", "artifact_type"),
    [
        ("cdk_assembly_risky.json", "assembly"),
        ("cdk_assets_risky.json", "assets"),
    ],
)
def test_gate_and_cli_support_both_manifest_types(
    fixture: str,
    artifact_type: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = parse_cdk_manifest((FIXTURES / fixture).read_text(encoding="utf-8"))
    gate = analyze_cdk(data)
    assert gate["adapter"] == "cdk"
    assert gate["artifact_type"] == artifact_type
    assert gate["decision"] == "block"
    assert gate["total_changes"] == sum(gate["risk_counts"].values())

    assert main(["cdk", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "cdk"
    assert payload["artifact_type"] == artifact_type
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


def test_cdk_mcp_gate_supports_framework_checks() -> None:
    result = agent_gate_cdk(str(FIXTURES / "cdk_assembly_risky.json"), "soc2")
    assert result["adapter"] == "cdk"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]
