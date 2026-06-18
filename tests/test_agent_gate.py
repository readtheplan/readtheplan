from __future__ import annotations

import json
from pathlib import Path

from readtheplan.agent_gate import SCHEMA, agent_gate_to_dict
from readtheplan.controls import load_catalog
from readtheplan.plan import analyze_plan_file


def _write_plan(
    tmp_path: Path,
    actions: list[str],
    resource_type: str = "aws_s3_bucket",
) -> Path:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": f"{resource_type}.example",
                        "type": resource_type,
                        "change": {"actions": actions},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return plan


def test_agent_gate_safe_changes_proceed(tmp_path: Path) -> None:
    summary = analyze_plan_file(_write_plan(tmp_path, ["create"]))

    gate = agent_gate_to_dict(summary)

    assert gate["schema"] == SCHEMA
    assert gate["decision"] == "proceed"
    assert gate["risk"] == "safe"
    assert gate["required_checks"] == []
    assert "continue" in gate["allowed_next_actions"]
    assert gate["prohibited_next_actions"] == ["auto_apply_without_policy"]
    assert gate["risk_counts"]["safe"] == 1


def test_agent_gate_review_changes_warn(tmp_path: Path) -> None:
    summary = analyze_plan_file(_write_plan(tmp_path, ["update"]))

    gate = agent_gate_to_dict(summary)

    assert gate["decision"] == "warn"
    assert gate["risk"] == "review"
    assert "rtp.check.peer_review" in gate["required_checks"]
    assert "rtp.check.change_evidence" in gate["required_checks"]
    assert "request_review" in gate["allowed_next_actions"]
    assert "apply_without_review" in gate["prohibited_next_actions"]


def test_agent_gate_dangerous_changes_block(tmp_path: Path) -> None:
    summary = analyze_plan_file(
        _write_plan(tmp_path, ["delete", "create"], "custom_resource")
    )

    gate = agent_gate_to_dict(summary)

    assert gate["decision"] == "block"
    assert gate["risk"] == "dangerous"
    assert "rtp.check.human_approval" in gate["required_checks"]
    assert "rtp.check.security_review" in gate["required_checks"]
    assert "apply" in gate["prohibited_next_actions"]
    assert "BLOCK" in gate["pr_comment"]


def test_agent_gate_irreversible_changes_block_with_recovery_check(
    tmp_path: Path,
) -> None:
    summary = analyze_plan_file(_write_plan(tmp_path, ["delete"]))

    gate = agent_gate_to_dict(summary)

    assert gate["decision"] == "block"
    assert gate["risk"] == "irreversible"
    assert "rtp.check.recovery_plan" in gate["required_checks"]


def test_agent_gate_can_include_framework_control_checks(tmp_path: Path) -> None:
    summary = analyze_plan_file(_write_plan(tmp_path, ["update"]))

    gate = agent_gate_to_dict(summary, load_catalog("soc2"))

    assert any(
        check.startswith("rtp.control.soc2.")
        for check in gate["required_checks"]
    )


def test_pr_comment_shows_truncation_indicator(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": f"aws_s3_bucket.example{i}",
                        "type": "aws_s3_bucket",
                        "change": {"actions": ["delete"]},
                    }
                    for i in range(10)
                ]
            }
        ),
        encoding="utf-8",
    )
    summary = analyze_plan_file(plan)
    gate = agent_gate_to_dict(summary)
    comment = gate["pr_comment"]
    assert comment.count("aws_s3_bucket.example") == 5
    assert "...and 5 more" in comment
