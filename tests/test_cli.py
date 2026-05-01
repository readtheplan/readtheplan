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
        "explanation": (
            "Terraform will create S3 bucket infrastructure. Confirm public access "
            "blocks and data classification before storing sensitive data."
        ),
    }


def test_analyze_can_disable_resource_rules(tmp_path: Path, capsys) -> None:
    plan = tmp_path / "rds_major_update.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "aws_rds_cluster.main",
                        "type": "aws_rds_cluster",
                        "change": {
                            "actions": ["update"],
                            "before": {"engine_version": "13.8"},
                            "after": {"engine_version": "14.1"},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(["analyze", "--format", "json", "--no-rules", str(plan)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["risks"] == {"review": 1}
    assert payload["changes"][0]["risk"] == "review"


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
