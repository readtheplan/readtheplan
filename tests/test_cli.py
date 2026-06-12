from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.cli import main


FIXTURES = Path(__file__).parent / "fixtures"


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


def test_analyze_non_utf8_plan_exits_one_without_traceback(
    tmp_path: Path, capsys
) -> None:
    plan = tmp_path / "binary.tfplan"
    plan.write_bytes(b"\x00\xa6\xff")

    exit_code = main(["analyze", str(plan)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error:" in captured.err
    assert "not UTF-8 JSON" in captured.err
    assert "Traceback" not in captured.err


def test_analyze_invalid_resource_changes_exits_one_without_traceback(
    tmp_path: Path, capsys
) -> None:
    plan = tmp_path / "invalid-resource-changes.json"
    plan.write_text('{"resource_changes": "foo"}', encoding="utf-8")

    exit_code = main(["analyze", str(plan)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error:" in captured.err
    assert "Traceback" not in captured.err


def test_analyze_fail_on_dangerous_exits_two_after_report(capsys) -> None:
    exit_code = main(
        [
            "analyze",
            "--fail-on",
            "dangerous",
            str(FIXTURES / "valid_plan.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Resource changes: 3" in captured.out
    assert captured.err == "fail-on: 1 change(s) at or above dangerous\n"


def test_analyze_fail_on_dangerous_preserves_json_output(capsys) -> None:
    exit_code = main(
        [
            "analyze",
            "--format",
            "json",
            "--fail-on",
            "dangerous",
            str(FIXTURES / "valid_plan.json"),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 2
    assert payload["resource_change_count"] == 3
    assert captured.err == "fail-on: 1 change(s) at or above dangerous\n"


def test_analyze_fail_on_irreversible_allows_dangerous_plan(capsys) -> None:
    exit_code = main(
        [
            "analyze",
            "--fail-on",
            "irreversible",
            str(FIXTURES / "valid_plan.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Resource changes: 3" in captured.out
    assert captured.err == ""


def test_analyze_fail_on_review_allows_safe_plan(tmp_path: Path, capsys) -> None:
    plan = tmp_path / "safe-plan.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "aws_s3_bucket.logs",
                        "type": "aws_s3_bucket",
                        "change": {"actions": ["create"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(["analyze", "--fail-on", "review", str(plan)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "safe" in captured.out
    assert captured.err == ""


def test_analyze_fail_on_keeps_malformed_input_at_exit_one(
    tmp_path: Path, capsys
) -> None:
    plan = tmp_path / "malformed-plan.json"
    plan.write_text('{"resource_changes": "foo"}', encoding="utf-8")

    exit_code = main(["analyze", "--fail-on", "safe", str(plan)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error:" in captured.err
    assert "fail-on:" not in captured.err
