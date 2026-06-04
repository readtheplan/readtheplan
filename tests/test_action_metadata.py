from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_action_uses_json_cli_contract() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    parser = (ROOT / "scripts" / "parse_action_output.py").read_text(encoding="utf-8")

    assert "readtheplan analyze --format json" in action
    assert "summary-json" in action
    assert "$GITHUB_ACTION_PATH" in action
    assert "install-source" in action
    assert "parse_action_output.py" in action
    assert "fail-on-any-change" in action
    assert "fail-on-threshold" in action
    assert "deprecationMessage" in action
    assert "risk_counts=" in action
    assert "threshold_reached" in action
    assert "FAIL_ON_CHANGES: ${{ inputs.fail-on-changes }}" in action
    assert 'FAIL_ON_CHANGES="${{ inputs.fail-on-changes }}"' not in action
    assert "resource_change_count" in parser
    assert "### Changes" in parser
    assert "_markdown_cell" in parser
    assert "payload[\"changes\"][:20]" in parser
    assert "MAX_GITHUB_OUTPUT_BYTES" in parser
    assert "grep" not in action
    assert "pip install readtheplan" not in action


def test_action_workflow_covers_success_and_failure_paths() -> None:
    workflow = (ROOT / ".github" / "workflows" / "test-action.yml").read_text(
        encoding="utf-8"
    )

    assert "tests/fixtures/valid_plan.json" in workflow
    assert "tests/fixtures/invalid_plan.json" in workflow
    assert "tests/fixtures/does-not-exist.json" in workflow
    assert "fail-on-any-change: \"true\"" in workflow
    assert "fail-on-threshold: \"dangerous\"" in workflow
    assert "steps.invalid.outcome != 'failure'" in workflow
    assert "steps.fail_on_changes.outcome != 'failure'" in workflow
    assert "steps.fail_on_threshold.outcome != 'failure'" in workflow


def test_repository_collaboration_templates_exist() -> None:
    codeowners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    bug = ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml"
    feature = ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.yml"
    pr_template = ROOT / ".github" / "pull_request_template.md"
    dependabot = ROOT / ".github" / "dependabot.yml"

    assert "* @texasich" in codeowners
    assert bug.exists()
    assert feature.exists()
    assert "Tests added or updated" in pr_template.read_text(encoding="utf-8")
    assert "AI assistance disclosed" in pr_template.read_text(encoding="utf-8")
    assert "github-actions" in dependabot.read_text(encoding="utf-8")
