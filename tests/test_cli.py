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
    assert payload["risk_level"] == "dangerous"
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
        "rule_id": "resource-rule",
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


def test_analyze_can_apply_rule_override_file(tmp_path: Path, capsys) -> None:
    plan = tmp_path / "plan.json"
    rules = tmp_path / "rules.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "aws_lambda_function.checkout",
                        "type": "aws_lambda_function",
                        "change": {
                            "actions": ["update"],
                            "after": {"tags": {"compliance": "pci"}},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "pci-tag-dangerous",
                        "risk": "dangerous",
                        "match": {"tags": {"compliance": "pci"}},
                        "explanation": "PCI-scoped $address requires release review.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(["analyze", "--format", "json", "--rules-file", str(rules), str(plan)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["risk_level"] == "dangerous"
    assert payload["changes"][0]["rule_id"] == "pci-tag-dangerous"
    assert "PCI-scoped aws_lambda_function.checkout" in payload["changes"][0]["explanation"]


def test_attest_emits_plan_read_header(capsys) -> None:
    exit_code = main(
        [
            "attest",
            "--agent-id",
            "codex",
            "--run-id",
            "run-123",
            str(FIXTURES / "valid_plan.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out.startswith("x-readtheplan-agent-read: rtp-attest-v1;")
    assert "agent=codex" in captured.out
    assert "run_id=run-123" in captured.out


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
