from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from readtheplan.cli import _build_parser, main
from readtheplan.mcp_server import (
    MCPToolInputError,
    MissingMCPDependencyError,
    agent_gate,
    analyze_plan,
    create_server,
)


FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_plan_matches_cli_json(capsys) -> None:
    plan = FIXTURES / "valid_plan.json"
    exit_code = main(["analyze", "--format", "json", str(plan)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert analyze_plan(str(plan)) == json.loads(captured.out)


def test_agent_gate_matches_cli_json(capsys) -> None:
    plan = FIXTURES / "valid_plan.json"
    exit_code = main(["agent-gate", str(plan)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert agent_gate(str(plan)) == json.loads(captured.out)


@pytest.mark.parametrize(
    ("plan_path", "expected"),
    [
        ("", "INVALID_INPUT"),
        ("missing.json", "PLAN_ERROR"),
    ],
)
def test_analyze_plan_rejects_missing_or_invalid_inputs(
    plan_path: str,
    expected: str,
) -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(plan_path)

    assert exc_info.value.code == expected
    assert exc_info.value.to_dict()["code"] == expected


def test_analyze_plan_rejects_invalid_json() -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(str(FIXTURES / "invalid_plan.json"))

    assert exc_info.value.code == "PLAN_ERROR"
    assert "invalid JSON" in exc_info.value.message


def test_analyze_plan_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(str(tmp_path))

    assert exc_info.value.code == "PLAN_ERROR"
    assert "directory" in exc_info.value.message


def test_analyze_plan_rejects_unsupported_plan_shape(tmp_path: Path) -> None:
    plan = tmp_path / "unsupported.json"
    plan.write_text(json.dumps({"resource_changes": {}}), encoding="utf-8")

    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(str(plan))

    assert exc_info.value.code == "PLAN_ERROR"
    assert "resource_changes" in exc_info.value.message


def test_create_server_registers_analyze_plan_tool(monkeypatch) -> None:
    registered: dict[str, object] = {}

    class FakeFastMCP:
        def __init__(self, name: str) -> None:
            self.name = name

        def tool(self, *, name: str):
            def decorator(func):
                registered[name] = func
                return func

            return decorator

    monkeypatch.setattr("readtheplan.mcp_server._load_fastmcp", lambda: FakeFastMCP)

    server = create_server()

    assert isinstance(server, FakeFastMCP)
    assert server.name == "readtheplan"
    assert "analyze_plan" in registered
    assert "agent_gate" in registered


def test_cli_parser_has_mcp_subcommand() -> None:
    parser = _build_parser()
    args = parser.parse_args(["mcp"])

    assert isinstance(args, argparse.Namespace)
    assert args.command == "mcp"


def test_cli_mcp_subcommand_runs_mcp_main(monkeypatch, capsys) -> None:
    called = False

    def fake_main() -> None:
        nonlocal called
        called = True

    monkeypatch.setattr("readtheplan.mcp_server.main", fake_main)

    assert main(["mcp"]) == 0
    assert called
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_cli_mcp_subcommand_reports_missing_extra(monkeypatch, capsys) -> None:
    def fake_main() -> None:
        raise MissingMCPDependencyError(
            'MCP preview requires the optional dependency. Install it with: pip install "readtheplan[mcp]"'
        )

    monkeypatch.setattr("readtheplan.mcp_server.main", fake_main)

    assert main(["mcp"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "readtheplan[mcp]" in captured.err
