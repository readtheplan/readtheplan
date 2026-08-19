from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
SITE = ROOT / "site"
README = ROOT / "README.md"


def test_agent_gate_ci_example_exists() -> None:
    example_dir = EXAMPLES / "04-agent-gate-ci"
    assert example_dir.exists()
    assert (example_dir / "README.md").exists()
    assert (example_dir / "agent-gate.json").exists()
    assert (example_dir / "github-actions.yml").exists()


def test_agent_gate_json_schema() -> None:
    gate_json_path = EXAMPLES / "04-agent-gate-ci" / "agent-gate.json"
    data = json.loads(gate_json_path.read_text(encoding="utf-8"))
    
    assert data["schema"] == "rtp-agent-gate-v1"
    assert "decision" in data
    assert "risk" in data
    assert "allowed_next_actions" in data
    assert "prohibited_next_actions" in data
    assert "pr_comment" in data


def test_agent_gate_workflow_is_valid() -> None:
    workflow_path = EXAMPLES / "04-agent-gate-ci" / "github-actions.yml"
    content = workflow_path.read_text(encoding="utf-8")
    
    assert "readtheplan agent-gate" in content
    assert "SCHEMA=$(jq -r '.schema'" in content
    assert 'if [ "$SCHEMA" != "rtp-agent-gate-v1" ]; then' in content
    assert "jq -r '.decision'" in content
    assert "proceed|warn|block" in content
    assert "jq -r '.pr_comment'" in content
    assert 'if [ "$DECISION" = "block" ]; then' in content
    assert "uses: actions/download-artifact@v4" in content
    assert "workflow_run:" in content
    assert "GITHUB_STEP_SUMMARY" in content
    assert "pull-requests: write" not in content
    
    # Negative checks to ensure no hosted/upload language or raw-plan publishing.
    assert "actions/upload-artifact" not in content
    assert "readtheplan.dev" not in content
    assert "api.readtheplan" not in content

    workflow = yaml.safe_load(content)
    assert workflow["permissions"] == {"contents": "read", "actions": "read"}


def test_readme_mentions_agent_gate_ci() -> None:
    content = README.read_text(encoding="utf-8")
    assert "### GitHub Action" in content
    assert "readtheplan agent-gate plan.json" in content
    assert "Full GitHub Actions workflow" in content
    assert "uses: readtheplan/readtheplan@v0.5.0" in content


def test_examples_readme_mentions_agent_gate_ci() -> None:
    content = (EXAMPLES / "README.md").read_text(encoding="utf-8")
    assert "## 04-agent-gate-ci" in content
    assert "Dogfood example of `readtheplan agent-gate`" in content


def test_site_mcp_docs_explicit_fields() -> None:
    mcp_html = (SITE / "mcp" / "index.html").read_text(encoding="utf-8")
    assert "rtp-agent-gate-v1" in mcp_html
    assert "allowed_next_actions" in mcp_html
    assert "prohibited_next_actions" in mcp_html
    assert "pr_comment" in mcp_html
