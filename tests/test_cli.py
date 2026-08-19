from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from readtheplan.cli import _package_version, main

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


def test_package_version_can_skip_git_enrichment(monkeypatch) -> None:
    def unexpected_git(*args, **kwargs):
        raise AssertionError("git enrichment must be skipped")

    monkeypatch.setattr("readtheplan.cli.subprocess.run", unexpected_git)

    assert _package_version(include_git=False)


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


def test_analyze_plan_integrity_outputs_findings_without_sensitive_values(capsys) -> None:
    exit_code = main(
        [
            "analyze",
            "--format",
            "json",
            "--framework",
            "soc2",
            "--fail-on",
            "dangerous",
            str(FIXTURES / "terraform_plan_integrity_risky.json"),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 2
    assert payload["resource_change_count"] == 1
    assert payload["plan_finding_count"] == 13
    assert payload["risks"] == {"dangerous": 9, "review": 4, "safe": 1}
    assert len(payload["plan_findings"]) == 13
    assert all(finding["controls"] for finding in payload["plan_findings"])
    assert captured.err == "fail-on: 9 change(s) at or above dangerous\n"
    encoded = json.dumps(payload)
    assert "fixture-action-payload-secret-do-not-leak" not in encoded
    assert "fixture-ansible-token-do-not-leak" not in encoded


def test_agent_gate_plan_integrity_blocks_action_only_and_partial_plans(capsys) -> None:
    exit_code = main(
        ["agent-gate", str(FIXTURES / "terraform_plan_integrity_risky.json")]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 2
    assert payload["decision"] == "block"
    assert payload["resource_change_count"] == 1
    assert payload["plan_finding_count"] == 13
    assert payload["total_changes"] == 14
    assert "fixture-function-do-not-leak" not in captured.out


def test_analyze_plan_integrity_human_summary_separates_resource_and_plan_findings(
    capsys,
) -> None:
    exit_code = main(
        ["analyze", str(FIXTURES / "terraform_plan_integrity_risky.json")]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Plan format version: 1.2" in captured.out
    assert "Resource changes: 1" in captured.out
    assert "Plan-level findings: 13" in captured.out
    assert "## Changes" in captured.out
    assert "## Plan-level findings" in captured.out
    assert "terraform_action_invocation" in captured.out
    assert "fixture-action-payload-secret-do-not-leak" not in captured.out


def test_analyze_kernel_mode_does_not_construct_evolution_engine(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_if_called():
        pytest.fail("kernel mode must not construct the evolution engine")

    monkeypatch.setattr("readtheplan.cli.get_engine", fail_if_called)

    exit_code = main(["analyze", str(FIXTURES / "valid_plan.json")])

    assert exit_code == 0
    assert "Resource changes: 3" in capsys.readouterr().out


def test_analyze_self_improving_records_via_agent_gate_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from readtheplan.evolution import EvolutionEngine

    engine = EvolutionEngine(data_dir=tmp_path / "evolution")
    monkeypatch.setattr("readtheplan.cli.get_engine", lambda: engine)

    exit_code = main(
        [
            "analyze",
            "--format",
            "json",
            "--mode",
            "self-improving",
            str(FIXTURES / "valid_plan.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)["resource_change_count"] == 3
    assert engine.get_recent_runs(limit=1)


def test_agent_gate_prints_json_contract(capsys) -> None:
    exit_code = main(["agent-gate", str(FIXTURES / "valid_plan.json")])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 2
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
    assert exit_code == 2
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


def test_analyze_rejects_utf16_json_as_non_utf8(tmp_path: Path, capsys) -> None:
    plan = tmp_path / "utf16-plan.json"
    plan.write_bytes(json.dumps({"resource_changes": []}).encode("utf-16"))

    exit_code = main(["analyze", str(plan)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "not UTF-8 JSON" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("command", ["agent-gate", "cloudformation", "jenkins"])
def test_cli_commands_reject_non_utf8_without_traceback(
    command: str, tmp_path: Path, capsys
) -> None:
    input_file = tmp_path / "binary.input"
    input_file.write_bytes(b"\xff\xfe")

    exit_code = main([command, str(input_file)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error:" in captured.err
    assert "UTF-8" in captured.err or "utf-8" in captured.err
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


# ── CloudFormation gate --framework ────────────────────────────────────

def test_cfn_gate_without_framework_has_no_control_checks() -> None:
    """cloudformation gate without --framework emits no control check IDs."""
    exit_code = main(
        ["cloudformation", str(FIXTURES / "cfn_change_set_mixed.json")]
    )
    assert exit_code == 2


def test_cfn_gate_with_framework_emits_control_checks() -> None:
    """cloudformation gate with --framework soc2 emits control check IDs."""
    exit_code = main(
        [
            "cloudformation",
            "--framework",
            "soc2",
            str(FIXTURES / "cfn_change_set_mixed.json"),
        ]
    )
    assert exit_code == 2


def test_cfn_gate_with_framework_includes_control_ids(capsys) -> None:
    """cloudformation gate with --framework includes rtp.control.* in output."""
    exit_code = main(
        [
            "cloudformation",
            "--framework",
            "soc2",
            str(FIXTURES / "cfn_change_set_mixed.json"),
        ]
    )
    assert exit_code == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    checks = payload.get("required_checks", [])
    control_checks = [c for c in checks if "rtp.control.soc2" in c]
    assert len(control_checks) > 0, (
        f"Expected SOC2 control check IDs in required_checks, got: {checks}"
    )


def test_cfn_gate_without_framework_omits_control_ids(capsys) -> None:
    """cloudformation gate without --framework has no rtp.control.* checks."""
    exit_code = main(
        ["cloudformation", str(FIXTURES / "cfn_change_set_mixed.json")]
    )
    assert exit_code == 2
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    checks = payload.get("required_checks", [])
    control_checks = [c for c in checks if "rtp.control" in c]
    assert len(control_checks) == 0, (
        f"Expected no control check IDs without --framework, got: {control_checks}"
    )



# ── Agent-gate exit codes ─────────────────────────────────────────────

def test_agent_gate_safe_plan_exits_zero(capsys) -> None:
    exit_code = main(["agent-gate", "demo/scenarios/01-safe-add-s3-bucket.json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["decision"] == "proceed"


def test_agent_gate_warn_plan_exits_one(capsys) -> None:
    exit_code = main(["agent-gate", "demo/scenarios/02-review-update-s3-tags.json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 1
    assert payload["decision"] == "warn"


def test_agent_gate_block_plan_exits_two(capsys) -> None:
    exit_code = main(["agent-gate", "demo/scenarios/03-dangerous-replace-ec2.json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 2
    assert payload["decision"] == "block"


# ── RecursionError hardening ──────────────────────────────────────────

def test_analyze_recursion_error_exits_one_without_traceback(
    tmp_path: Path, capsys
) -> None:
    """The RecursionError handler prints a friendly message, not a traceback."""
    plan = tmp_path / "nested.json"
    plan.write_text('{"valid": "json"}', encoding="utf-8")

    # Python 3.12+ uses an iterative C JSON parser that never raises
    # RecursionError from deeply nested input.  Mock json.loads so the
    # production handler is exercised on every supported Python version.
    with patch("readtheplan.cli.json.loads", side_effect=RecursionError):
        exit_code = main(["analyze", str(plan)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error:" in captured.err
    assert "deeply nested" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("command", ["cloudformation", "azure"])
def test_json_adapter_recursion_error_exits_one_without_traceback(
    command: str, tmp_path: Path, capsys
) -> None:
    input_file = tmp_path / "nested.json"
    input_file.write_text("{}", encoding="utf-8")

    with patch("readtheplan.cli.json.loads", side_effect=RecursionError):
        exit_code = main([command, str(input_file)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error:" in captured.err
    assert "deeply nested" in captured.err
    assert "Traceback" not in captured.err
