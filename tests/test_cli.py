from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.cli import main


FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_rejects_json_array_as_invalid_plan(tmp_path: Path, capsys) -> None:
    """CLI fast path must reject top-level JSON arrays with a clean error
    instead of a raw TypeError. Found by Codex Desktop peer review,
    confirmed by Claude Desktop."""
    bad = tmp_path / "array.json"
    bad.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    exit_code = main(["analyze", str(bad)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "must be an object" in captured.err
    assert "TypeError" not in captured.err


def test_version_flag_prints_package_version(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert captured.out.strip().startswith("readtheplan ")
    assert captured.err == ""


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


def test_agent_gate_prints_json_contract(capsys) -> None:
    exit_code = main(["agent-gate", str(FIXTURES / "valid_plan.json")])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert captured.err == ""
    assert payload["schema"] == "rtp-agent-gate-v1"
    assert payload["decision"] == "block"
    assert payload["risk"] == "dangerous"
    assert "rtp.check.human_approval" in payload["required_checks"]
    assert "apply" in payload["prohibited_next_actions"]
    assert payload["risk_counts"] == {
        "safe": 1,
        "review": 1,
        "dangerous": 1,
        "irreversible": 0,
    }


def test_agent_gate_can_include_framework_check_ids(capsys) -> None:
    exit_code = main(
        ["agent-gate", "--framework", "soc2", str(FIXTURES / "soc2_plan.json")]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert captured.err == ""
    assert any(
        check.startswith("rtp.control.soc2.")
        for check in payload["required_checks"]
    )


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


def test_analyze_malformed_json_exits_one(tmp_path: Path, capsys) -> None:
    """Issue #70: malformed plan.json should produce a graceful error message."""
    plan = tmp_path / "garbage.json"
    plan.write_text("this is not json at all {{{", encoding="utf-8")

    exit_code = main(["analyze", str(plan)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error" in captured.err
