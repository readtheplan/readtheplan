from __future__ import annotations

import json
from pathlib import Path

from readtheplan.cli import main


FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_valid_plan_prints_summary(capsys) -> None:
    exit_code = main(["analyze", str(FIXTURES / "valid_plan.json")])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Resource changes: 3" in captured.out
    assert "aws_s3_bucket.logs" in captured.out
    assert "dangerous" in captured.out
    assert captured.err == ""


def test_analyze_valid_plan_can_print_json(capsys) -> None:
    exit_code = main(["analyze", "--format", "json", str(FIXTURES / "valid_plan.json")])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert captured.err == ""
    assert payload["resource_change_count"] == 3
    assert payload["actions"] == {
        "create": 1,
        "delete/create": 1,
        "update": 1,
    }
    assert payload["risks"] == {
        "dangerous": 1,
        "review": 1,
        "safe": 1,
    }
    assert payload["changes"][0] == {
        "address": "aws_s3_bucket.logs",
        "type": "aws_s3_bucket",
        "actions": ["create"],
        "risk": "safe",
    }


def test_analyze_invalid_plan_prints_stderr(capsys) -> None:
    exit_code = main(["analyze", str(FIXTURES / "invalid_plan.json")])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error: invalid JSON" in captured.err


def test_analyze_invalid_plan_with_json_format_still_prints_stderr(capsys) -> None:
    exit_code = main(["analyze", "--format", "json", str(FIXTURES / "invalid_plan.json")])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error: invalid JSON" in captured.err


def test_analyze_missing_file_exits_one(capsys) -> None:
    exit_code = main(["analyze", "missing.json"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "does not exist" in captured.err


def test_analyze_directory_exits_one(tmp_path: Path, capsys) -> None:
    exit_code = main(["analyze", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "directory" in captured.err
