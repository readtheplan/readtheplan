from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "parse_action_output.py"


def _load_parser() -> ModuleType:
    spec = importlib.util.spec_from_file_location("parse_action_output", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load parse_action_output.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_parser(tmp_path: Path, payload: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:  # noqa: E501
    parser = _load_parser()
    output_json = tmp_path / "output.json"
    github_output = tmp_path / "github-output.txt"
    step_summary = tmp_path / "step-summary.md"
    count_file = tmp_path / "count.txt"
    output_json.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "parse_action_output.py",
            str(output_json),
            str(github_output),
            str(step_summary),
            str(count_file),
        ],
    )
    parser.main()
    return github_output, step_summary, count_file


def test_parse_action_output_writes_compact_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "resource_change_count": 1,
        "actions": {"update": 1},
        "risks": {"review": 1},
        "changes": [
            {
                "risk": "review",
                "actions": ["update"],
                "address": "aws_s3_bucket.logs",
                "type": "aws_s3_bucket",
                "explanation": "Tag update requires review.",
            }
        ],
    }

    github_output, step_summary, count_file = _run_parser(tmp_path, payload, monkeypatch)

    output = github_output.read_text(encoding="utf-8")
    assert "summary-json<<READTHEPLAN_JSON" in output
    assert "resource-change-count=1" in output
    assert 'action-counts={"update":1}' in output
    assert 'risk-counts={"review":1}' in output
    assert "| review | update | aws_s3_bucket.logs | aws_s3_bucket |" in step_summary.read_text(encoding="utf-8")  # noqa: E501
    assert count_file.read_text(encoding="utf-8") == "1"


def test_parse_action_output_skips_oversized_summary_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = {
        "resource_change_count": 1000,
        "actions": {"update": 1000},
        "risks": {"review": 1000},
        "changes": [
            {
                "risk": "review",
                "actions": ["update"],
                "address": f"custom_resource.example_{index}",
                "type": "custom_resource",
                "explanation": "x" * 1100,
            }
            for index in range(1000)
        ],
    }

    github_output, _, _ = _run_parser(tmp_path, payload, monkeypatch)

    captured = capsys.readouterr()
    output = github_output.read_text(encoding="utf-8")
    assert "::warning::readtheplan summary-json" in captured.out
    assert "summary-json=\n" in output
    assert "summary-json<<READTHEPLAN_JSON" not in output
    assert 'action-counts={"update":1000}' in output


def test_parse_action_output_accepts_agent_gate_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "schema": "rtp-agent-gate-v1",
        "adapter": "pulumi",
        "total_changes": 3,
        "decision": "block",
        "risk": "irreversible",
        "risk_counts": {"safe": 1, "dangerous": 1, "irreversible": 1},
        "pr_comment": "**readtheplan agent gate:** BLOCK\n\nHuman approval required.",
    }

    github_output, step_summary, count_file = _run_parser(tmp_path, payload, monkeypatch)

    output = github_output.read_text(encoding="utf-8")
    assert "resource-change-count=3" in output
    assert "action-counts={}" in output
    assert 'risk-counts={"dangerous":1,"irreversible":1,"safe":1}' in output
    assert "readtheplan agent gate:** BLOCK" in step_summary.read_text(encoding="utf-8")
    assert count_file.read_text(encoding="utf-8") == "3"


def test_parse_action_output_rejects_malformed_agent_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = _load_parser()
    output_json = tmp_path / "output.json"
    output_json.write_text('{"schema":"rtp-agent-gate-v1"}', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "parse_action_output.py",
            str(output_json),
            str(tmp_path / "outputs"),
            str(tmp_path / "summary"),
            str(tmp_path / "count"),
        ],
    )
    with pytest.raises(SystemExit):
        parser.main()
