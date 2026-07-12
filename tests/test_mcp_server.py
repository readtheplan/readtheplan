from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

import pytest

from readtheplan.cli import _build_parser, main
from readtheplan.mcp_server import (
    MCPToolInputError,
    MissingMCPDependencyError,
    _validate_path,
    _working_root,
    agent_gate,
    agent_gate_cloudformation,
    agent_gate_kubernetes,
    agent_gate_pulumi,
    analyze_plan,
    create_server,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ── existing tests (preserved) ────────────────────────────────────────


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

    assert exit_code == 2
    assert agent_gate(str(plan)) == json.loads(captured.out)


def test_agent_gate_pulumi_supports_framework_checks() -> None:
    result = agent_gate_pulumi(str(FIXTURES / "pulumi_preview_mixed.json"), "soc2")
    assert result["adapter"] == "pulumi"
    assert result["decision"] == "block"
    assert any(
        str(check).startswith("rtp.control.soc2.")
        for check in result["required_checks"]
    )


def test_agent_gate_pulumi_rejects_invalid_preview(tmp_path: Path) -> None:
    invalid = tmp_path / "preview.json"
    invalid.write_text("not-json", encoding="utf-8")
    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_pulumi(str(invalid))
    assert exc_info.value.code == "INVALID_JSON"


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
            'MCP preview requires the optional dependency. Install it with: pip install "readtheplan[mcp]"'  # noqa: E501
        )

    monkeypatch.setattr("readtheplan.mcp_server.main", fake_main)

    assert main(["mcp"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "readtheplan[mcp]" in captured.err


# ── framework parameter ───────────────────────────────────────────────


def test_analyze_plan_with_framework_returns_controls() -> None:
    plan = FIXTURES / "soc2_plan.json"
    result = analyze_plan(str(plan), framework="soc2")

    assert "framework" in result
    assert result["framework"]["name"] == "soc2"
    assert "version" in result["framework"]
    assert "schema_version" in result["framework"]

    for change in result["changes"]:
        assert "controls" in change
        assert isinstance(change["controls"], list)
        for control in change["controls"]:
            assert "id" in control
            assert "title" in control
            assert "rationale" in control


def test_analyze_plan_framework_matches_cli(capsys) -> None:
    """Framework-enriched MCP output must match the CLI --framework JSON."""
    plan = FIXTURES / "soc2_plan.json"
    exit_code = main(
        ["analyze", "--format", "json", "--framework", "soc2", str(plan)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    cli_result = json.loads(captured.out)
    mcp_result = analyze_plan(str(plan), framework="soc2")

    assert mcp_result == cli_result
    assert "framework" in mcp_result
    assert mcp_result["framework"]["name"] == "soc2"


def test_analyze_plan_rejects_unknown_framework() -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(str(FIXTURES / "valid_plan.json"), framework="nonexistent")

    assert exc_info.value.code == "FRAMEWORK_NOT_FOUND"
    assert "nonexistent" in exc_info.value.message


def test_analyze_plan_without_framework_has_no_controls() -> None:
    result = analyze_plan(str(FIXTURES / "valid_plan.json"))

    assert "framework" not in result
    for change in result["changes"]:
        assert "controls" not in change


def test_agent_gate_with_framework_adds_control_checks() -> None:
    result = agent_gate(str(FIXTURES / "soc2_plan.json"), framework="soc2")

    control_checks = [
        c for c in result["required_checks"] if c.startswith("rtp.control.soc2.")
    ]
    assert len(control_checks) > 0


# ── path traversal protection ─────────────────────────────────────────


def test_working_root_returns_none_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("MCP_ROOT", raising=False)
    assert _working_root() is None


def test_working_root_returns_path_when_set(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    assert _working_root() == tmp_path.resolve()


def test_validate_path_allows_inside_root(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    allowed = tmp_path / "foo.json"
    allowed.write_text("{}")
    result = _validate_path(str(allowed))
    assert result == allowed.resolve()


def test_validate_path_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    outside = tmp_path.parent / "outside.json"

    with pytest.raises(MCPToolInputError) as exc_info:
        _validate_path(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"
    assert "outside the allowed working root" in exc_info.value.message


def test_validate_path_allows_path_when_mcp_root_unset(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("MCP_ROOT", raising=False)
    f = tmp_path / "any.json"
    f.write_text("{}")
    result = _validate_path(str(f))
    assert result == f.resolve()


def test_analyze_plan_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    """End-to-end: analyze_plan with MCP_ROOT set rejects traversal."""
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    outside = tmp_path.parent / "plan.json"
    # copy a valid plan fixture outside the root
    outside.write_text((FIXTURES / "valid_plan.json").read_text())

    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    """agent_gate also validates paths when MCP_ROOT is set."""
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    outside = tmp_path.parent / "plan.json"
    outside.write_text((FIXTURES / "valid_plan.json").read_text())

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_cloudformation_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    """CloudFormation MCP tool must enforce the same MCP_ROOT boundary."""
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    outside = tmp_path.parent / "cfn.json"
    outside.write_text((FIXTURES / "cfn_change_set_mixed.json").read_text())

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_cloudformation(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


@pytest.mark.parametrize(
    ("handler", "fixture_name", "result_key", "expected_value"),
    [
        (analyze_plan, "valid_plan.json", "resource_change_count", 3),
        (agent_gate, "valid_plan.json", "schema", "rtp-agent-gate-v1"),
        (
            agent_gate_cloudformation,
            "cfn_change_set_mixed.json",
            "adapter",
            "cloudformation",
        ),
        (agent_gate_pulumi, "pulumi_preview_mixed.json", "adapter", "pulumi"),
    ],
)
def test_non_kubernetes_handlers_use_confined_read_boundary(
    monkeypatch,
    tmp_path,
    handler,
    fixture_name,
    result_key,
    expected_value,
) -> None:
    """Each file-backed MCP handler consumes bytes from the confined reader."""
    root = tmp_path / "root"
    root.mkdir()
    input_file = root / "input.json"
    input_file.write_text("not valid JSON", encoding="utf-8")
    fixture_bytes = (FIXTURES / fixture_name).read_bytes()
    calls: list[str] = []
    monkeypatch.setenv("MCP_ROOT", str(root))

    def fake_read_confined_bytes(path: str) -> bytes:
        calls.append(path)
        return fixture_bytes

    monkeypatch.setattr(
        "readtheplan.mcp_server._read_confined_bytes",
        fake_read_confined_bytes,
    )

    result = handler(str(input_file))

    assert calls == [str(input_file.resolve())]
    assert result[result_key] == expected_value


@pytest.mark.parametrize(
    ("handler", "fixture_name", "result_key", "expected_value"),
    [
        (analyze_plan, "valid_plan.json", "resource_change_count", 3),
        (agent_gate, "valid_plan.json", "schema", "rtp-agent-gate-v1"),
        (
            agent_gate_cloudformation,
            "cfn_change_set_mixed.json",
            "adapter",
            "cloudformation",
        ),
        (agent_gate_pulumi, "pulumi_preview_mixed.json", "adapter", "pulumi"),
    ],
)
def test_non_kubernetes_handlers_allow_path_inside_root(
    monkeypatch,
    tmp_path,
    handler,
    fixture_name,
    result_key,
    expected_value,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    input_file = root / "input.json"
    input_file.write_bytes((FIXTURES / fixture_name).read_bytes())
    monkeypatch.setenv("MCP_ROOT", str(root))

    result = handler(str(input_file))

    assert result[result_key] == expected_value


@pytest.mark.parametrize(
    ("handler", "fixture_name"),
    [
        (analyze_plan, "valid_plan.json"),
        (agent_gate, "valid_plan.json"),
        (agent_gate_cloudformation, "cfn_change_set_mixed.json"),
        (agent_gate_pulumi, "pulumi_preview_mixed.json"),
    ],
)
def test_non_kubernetes_handlers_reject_validate_open_swap(
    monkeypatch,
    tmp_path,
    handler,
    fixture_name,
) -> None:
    """Swapping an authorized input cannot redirect any sibling handler."""
    root = tmp_path / "root"
    root.mkdir()
    fixture_bytes = (FIXTURES / fixture_name).read_bytes()
    inside = root / "input.json"
    inside.write_bytes(fixture_bytes)
    outside = tmp_path / "outside.json"
    outside.write_bytes(fixture_bytes)
    inside_path = str(inside.resolve())
    monkeypatch.setenv("MCP_ROOT", str(root))

    real_open = os.open
    swapped = False

    def swapping_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and os.fspath(path) == inside_path:
            inside.unlink()
            try:
                inside.symlink_to(outside)
            except OSError as exc:
                pytest.skip(f"file symlinks unavailable: {exc}")
            swapped = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("readtheplan.mcp_server.os.open", swapping_open)

    with pytest.raises(MCPToolInputError) as exc_info:
        handler(str(inside))

    assert swapped is True
    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_kubernetes_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    """Kubernetes inputs are confined to MCP_ROOT like the other MCP tools."""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "k8s.json"
    outside.write_text(json.dumps({"resources": []}), encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_kubernetes(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_kubernetes_allows_path_inside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    manifest = root / "k8s.json"
    manifest.write_text(json.dumps({"resources": []}), encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    result = agent_gate_kubernetes(str(manifest))

    assert result["adapter"] == "kubernetes"


def test_agent_gate_kubernetes_rejects_symlink_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "k8s.json"
    outside.write_text(json.dumps({"resources": []}), encoding="utf-8")
    linked = root / "linked.json"
    try:
        linked.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_kubernetes(str(linked))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_kubernetes_rejects_validate_open_swap(monkeypatch, tmp_path) -> None:
    """Swapping an authorized file to an outside symlink cannot win a TOCTOU race."""
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "k8s.json"
    inside.write_text(json.dumps({"resources": []}), encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"resources": []}), encoding="utf-8")
    inside_path = str(inside.resolve())
    monkeypatch.setenv("MCP_ROOT", str(root))

    real_open = os.open
    swapped = False

    def swapping_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and os.fspath(path) == inside_path:
            inside.unlink()
            try:
                inside.symlink_to(outside)
            except OSError as exc:
                pytest.skip(f"file symlinks unavailable: {exc}")
            swapped = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("readtheplan.mcp_server.os.open", swapping_open)

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_kubernetes(str(inside))

    assert swapped is True
    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_analyze_plan_allows_path_inside_root(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    plan = tmp_path / "plan.json"
    plan.write_text((FIXTURES / "valid_plan.json").read_text())

    result = analyze_plan(str(plan))
    assert result["resource_change_count"] == 3


# ── stdio integration test ────────────────────────────────────────────


def _importable(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ModuleNotFoundError:
        return False


def _cli_on_path() -> bool:
    import shutil

    return shutil.which("readtheplan") is not None


pytestmark_stdio = pytest.mark.skipif(
    not (_importable("mcp.server.fastmcp") and _cli_on_path()),
    reason="mcp optional dep or readtheplan CLI not on PATH (pip install -e .[mcp])",
)


def _send_jsonrpc(proc: subprocess.Popen, payload: dict) -> dict:
    """Write a single JSON-RPC line to the server and read the response."""
    line = json.dumps(payload) + "\n"
    proc.stdin.write(line.encode("utf-8"))  # type: ignore[union-attr]
    proc.stdin.flush()  # type: ignore[union-attr]

    # read lines until we get a non-empty response
    for _ in range(20):
        raw = proc.stdout.readline()  # type: ignore[union-attr]
        if not raw:
            raise RuntimeError("Server closed stdout unexpectedly")
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            continue

    raise RuntimeError("No valid JSON-RPC response received")


def _mcp_initialize(proc: subprocess.Popen) -> dict:
    """Perform the MCP initialize handshake."""
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1.0"},
        },
    }
    response = _send_jsonrpc(proc, init_req)
    assert "result" in response, f"Initialize failed: {response}"
    # send initialized notification
    notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    proc.stdin.write((json.dumps(notif) + "\n").encode("utf-8"))  # type: ignore[union-attr]
    proc.stdin.flush()  # type: ignore[union-attr]
    return response["result"]


@pytestmark_stdio
def test_stdio_server_tools_list() -> None:
    """Start the real MCP stdio server, list tools, and call analyze_plan."""
    plan = FIXTURES / "valid_plan.json"

    # start the server subprocess via the CLI entry point
    proc = subprocess.Popen(
        ["readtheplan", "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    try:
        # --- initialize ---
        _mcp_initialize(proc)

        # --- tools/list ---
        tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        tools_resp = _send_jsonrpc(proc, tools_req)
        assert "result" in tools_resp, f"tools/list failed: {tools_resp}"
        tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
        assert "analyze_plan" in tool_names
        assert "agent_gate" in tool_names
        assert "agent_gate_cloudformation" in tool_names
        assert "agent_gate_pulumi" in tool_names

        # --- tools/call: analyze_plan ---
        call_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "analyze_plan",
                "arguments": {"plan_path": str(plan.resolve())},
            },
        }
        call_resp = _send_jsonrpc(proc, call_req)
        assert "result" in call_resp, f"tools/call failed: {call_resp}"

        # MCP wraps tool results as content items
        content = call_resp["result"]["content"]
        assert len(content) == 1
        assert content[0]["type"] == "text"
        mcp_summary = json.loads(content[0]["text"])

        # compare with CLI JSON output
        import subprocess as sp

        cli_out = sp.check_output(
            [
                "readtheplan",
                "analyze",
                "--format",
                "json",
                str(plan),
            ],
            text=True,
        )
        cli_summary = json.loads(cli_out)

        assert mcp_summary == cli_summary

    finally:
        proc.stdin.close()  # type: ignore[union-attr]
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        # stderr should not contain raw plan JSON
        stderr_text = proc.stderr.read().decode("utf-8", errors="replace")  # type: ignore[union-attr]
        # The valid_plan.json contains "resource_changes" — stderr should
        # NOT leak the raw plan payload (only file paths, error messages).
        assert "resource_changes" not in stderr_text, (
            "MCP server stderr must not include raw plan JSON"
        )


@pytestmark_stdio
def test_stdio_server_analyze_plan_with_framework() -> None:
    """Stdio integration: analyze_plan with framework parameter."""
    plan = FIXTURES / "soc2_plan.json"

    proc = subprocess.Popen(
        ["readtheplan", "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    try:
        _mcp_initialize(proc)

        call_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "analyze_plan",
                "arguments": {
                    "plan_path": str(plan.resolve()),
                    "framework": "soc2",
                },
            },
        }
        call_resp = _send_jsonrpc(proc, call_req)
        assert "result" in call_resp, f"tools/call failed: {call_resp}"

        content = call_resp["result"]["content"]
        mcp_summary = json.loads(content[0]["text"])

        assert "framework" in mcp_summary
        assert mcp_summary["framework"]["name"] == "soc2"
        for change in mcp_summary["changes"]:
            assert "controls" in change

    finally:
        proc.stdin.close()  # type: ignore[union-attr]
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
