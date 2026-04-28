from __future__ import annotations

from pathlib import Path

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
