from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_action_uses_json_cli_contract() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")

    assert "readtheplan analyze --format json" in action
    assert "resource_change_count" in action
    assert "summary-json" in action
    assert "risk-level" in action
    assert "attestation-header" in action
    assert "--rules-file" in action
    assert "readtheplan attest --agent-id" in action
    assert "$GITHUB_ACTION_PATH" in action
    assert "install-source" in action
    assert "### Changes" in action
    assert "_markdown_cell" in action
    assert "payload[\"changes\"][:20]" in action
    assert "grep" not in action
    assert "pip install readtheplan" not in action


def test_action_workflow_covers_success_and_failure_paths() -> None:
    workflow = (ROOT / ".github" / "workflows" / "test-action.yml").read_text(
        encoding="utf-8"
    )

    assert "tests/fixtures/valid_plan.json" in workflow
    assert "tests/fixtures/invalid_plan.json" in workflow
    assert "tests/fixtures/does-not-exist.json" in workflow
    assert "fail-on-changes: \"true\"" in workflow
    assert "steps.invalid.outcome != 'failure'" in workflow
    assert "steps.fail_on_changes.outcome != 'failure'" in workflow
