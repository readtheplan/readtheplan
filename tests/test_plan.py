from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from readtheplan.plan import PlanError, analyze_plan_file, load_plan

FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_valid_plan_counts_actions_and_risk() -> None:
    summary = analyze_plan_file(FIXTURES / "valid_plan.json")

    assert summary.terraform_version == "1.6.6"
    assert len(summary.resource_changes) == 3
    assert summary.action_counts["create"] == 1
    assert summary.action_counts["delete/create"] == 1
    assert summary.action_counts["update"] == 1
    assert summary.risk_counts["safe"] == 1
    assert summary.risk_counts["dangerous"] == 1
    assert summary.risk_counts["review"] == 1


def test_missing_file_is_descriptive(tmp_path: Path) -> None:
    with pytest.raises(PlanError, match="does not exist"):
        load_plan(tmp_path / "missing.json")


def test_directory_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PlanError, match="directory"):
        load_plan(tmp_path)


def test_empty_file_is_rejected(tmp_path: Path) -> None:
    plan = tmp_path / "empty.json"
    plan.write_text("", encoding="utf-8")

    with pytest.raises(PlanError, match="empty"):
        load_plan(plan)


def test_invalid_json_is_rejected() -> None:
    with pytest.raises(PlanError, match="invalid JSON"):
        load_plan(FIXTURES / "invalid_plan.json")


def test_non_utf8_json_is_rejected_as_plan_error(tmp_path: Path) -> None:
    plan = tmp_path / "binary.json"
    plan.write_bytes(b"\xff\xfe")

    with pytest.raises(PlanError, match="not valid UTF-8 JSON"):
        load_plan(plan)


def test_deeply_nested_json_is_rejected_as_plan_error(tmp_path: Path) -> None:
    plan = tmp_path / "nested.json"
    plan.write_text("{}", encoding="utf-8")

    with (
        patch("readtheplan.plan.json.loads", side_effect=RecursionError),
        pytest.raises(PlanError, match="deeply nested JSON"),
    ):
        load_plan(plan)


def test_non_object_json_is_rejected(tmp_path: Path) -> None:
    plan = tmp_path / "array.json"
    plan.write_text("[]", encoding="utf-8")

    with pytest.raises(PlanError, match="must be an object"):
        load_plan(plan)


def test_resource_changes_must_be_list(tmp_path: Path) -> None:
    plan = tmp_path / "bad_resource_changes.json"
    plan.write_text('{"resource_changes": {}}', encoding="utf-8")

    with pytest.raises(PlanError, match="resource_changes"):
        analyze_plan_file(plan)


def test_valid_json_without_resource_changes_is_allowed(tmp_path: Path) -> None:
    plan = tmp_path / "minimal.json"
    plan.write_text('{"format_version": "1.2"}', encoding="utf-8")

    summary = analyze_plan_file(plan)

    assert summary.resource_changes == ()


def test_empty_action_list_requires_review(tmp_path: Path) -> None:
    plan = tmp_path / "empty_actions.json"
    plan.write_text(
        '{"resource_changes": [{"address": "aws_s3_bucket.logs", '
        '"type": "aws_s3_bucket", "change": {"actions": []}}]}',
        encoding="utf-8",
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "missing or unknown" in summary.resource_changes[0].explanation


def test_analyze_public_api_import() -> None:
    """The public ``analyze`` function is importable from the package root."""
    from readtheplan import PlanSummary, ResourceChange, analyze

    # dict input (most common programmatic usage)
    plan: dict = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.logs",
                "type": "aws_s3_bucket",
                "change": {"actions": ["create"]},
            }
        ],
    }
    summary = analyze(plan)
    assert isinstance(summary, PlanSummary)
    assert len(summary.resource_changes) == 1
    change = summary.resource_changes[0]
    assert isinstance(change, ResourceChange)
    assert change.address == "aws_s3_bucket.logs"
    assert change.resource_type == "aws_s3_bucket"
    assert change.actions == ("create",)
    assert change.risk == "safe"


def test_analyze_public_api_accepts_path(tmp_path: Path) -> None:
    """The public ``analyze`` function also accepts file paths."""
    from readtheplan import analyze

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        '{"resource_changes": [{"address": "x", "type": "x", '
        '"change": {"actions": ["delete"]}}]}',
        encoding="utf-8",
    )
    summary = analyze(plan_file)
    assert len(summary.resource_changes) == 1
    assert summary.resource_changes[0].risk == "irreversible"


def test_plan_integrity_and_non_resource_signals_are_first_class_and_redacted() -> None:
    summary = analyze_plan_file(FIXTURES / "terraform_plan_integrity_risky.json")
    by_type = {finding.resource_type: [] for finding in summary.plan_findings}
    for finding in summary.plan_findings:
        by_type[finding.resource_type].append(finding)

    assert summary.format_version == "1.2"
    assert len(summary.resource_changes) == 1
    assert len(summary.plan_findings) == 13
    assert len(summary.all_changes) == 14
    assert summary.risk_counts == {
        "safe": 1,
        "review": 4,
        "dangerous": 9,
    }
    assert set(by_type) == {
        "terraform_plan_errored",
        "terraform_plan_not_applyable",
        "terraform_plan_incomplete",
        "terraform_deferred_change",
        "terraform_resource_drift",
        "terraform_output_change",
        "terraform_output_sensitive_exposure",
        "terraform_check_fail",
        "terraform_check_error",
        "terraform_check_unknown",
        "terraform_action_invocation",
    }
    assert len(by_type["terraform_resource_drift"]) == 2
    assert len(by_type["terraform_action_invocation"]) == 2
    assert by_type["terraform_output_sensitive_exposure"][0].risk == "dangerous"
    assert by_type["terraform_check_unknown"][0].risk == "review"
    assert {finding.address for finding in by_type["terraform_action_invocation"]} == {
        "action.ansible_playbook.reconfigure",
        "action.aws_lambda_invoke.rotate",
    }

    encoded = json.dumps(summary.to_dict())
    for secret in (
        "fixture-plan-bucket-do-not-leak",
        "fixture-deferred-secret-do-not-leak",
        "fixture-drift-password-do-not-leak",
        "fixture-new-output-secret-do-not-leak",
        "fixture-check-message-secret-do-not-leak",
        "fixture-action-payload-secret-do-not-leak",
        "fixture-ansible-token-do-not-leak",
    ):
        assert secret not in encoded


@pytest.mark.parametrize("version", ["0.1", "1.0", "1.99", "1.2.3"])
def test_supported_plan_format_versions_are_accepted(
    tmp_path: Path, version: str
) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps({"format_version": version, "resource_changes": []}),
        encoding="utf-8",
    )

    assert analyze_plan_file(plan).format_version == version


@pytest.mark.parametrize("version", ["0.0", "2.0", "3.1"])
def test_unsupported_plan_format_versions_are_rejected(
    tmp_path: Path, version: str
) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps({"format_version": version, "resource_changes": []}),
        encoding="utf-8",
    )

    with pytest.raises(PlanError, match="format version is not supported"):
        analyze_plan_file(plan)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("format_version", 1.2, "format_version.*string"),
        ("format_version", "latest", "format_version.*malformed"),
        ("terraform_version", {}, "terraform_version.*string"),
        ("applyable", "false", "applyable.*boolean"),
        ("complete", 0, "complete.*boolean"),
        ("errored", [], "errored.*boolean"),
        ("deferred_changes", {}, "deferred_changes.*list"),
        ("resource_drift", {}, "resource_drift.*list"),
        ("output_changes", [], "output_changes.*object"),
        ("checks", {}, "checks.*list"),
        ("action_invocations", {}, "action_invocations.*list"),
    ],
)
def test_plan_integrity_fields_are_strict(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps({"resource_changes": [], field: value}), encoding="utf-8"
    )

    with pytest.raises(PlanError, match=message):
        analyze_plan_file(plan)


def test_forget_action_blocks_state_detachment(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "aws_s3_bucket.legacy",
                        "type": "aws_s3_bucket",
                        "change": {"actions": ["forget"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    change = analyze_plan_file(plan, use_rules=False).resource_changes[0]
    assert change.risk == "dangerous"
    assert "remove this resource from state" in change.explanation


def test_check_instances_replace_parent_aggregate_and_wrapped_output_is_supported(
    tmp_path: Path,
) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [],
                "output_changes": {
                    "endpoint": {
                        "change": {
                            "actions": ["create"],
                            "after_sensitive": False,
                        }
                    }
                },
                "checks": [
                    {
                        "address": {"to_display": "aws_instance.web"},
                        "status": "fail",
                        "instances": [
                            {
                                "address": {"to_display": "aws_instance.web[0]"},
                                "status": "pass",
                            },
                            {
                                "address": {"to_display": "aws_instance.web[1]"},
                                "status": "unknown",
                            },
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    summary = analyze_plan_file(plan)
    assert [finding.resource_type for finding in summary.plan_findings] == [
        "terraform_output_change",
        "terraform_check_unknown",
    ]
    assert summary.plan_findings[1].address == "aws_instance.web[1]"


def test_malformed_plan_metadata_cannot_be_reflected_as_secret_output(
    tmp_path: Path,
) -> None:
    secret = "fixture-malformed-metadata-secret-do-not-leak"
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": {"secret": secret},
                        "type": [secret],
                        "change": {"actions": [{"secret": secret}]},
                    }
                ],
                "action_invocations": [
                    {"address": {"secret": secret}, "type": [secret]}
                ],
            }
        ),
        encoding="utf-8",
    )

    encoded = json.dumps(analyze_plan_file(plan, use_rules=False).to_dict())
    assert secret not in encoded
    assert "<unknown>" in encoded
