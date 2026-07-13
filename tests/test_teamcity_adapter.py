from __future__ import annotations

import json
from pathlib import Path

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.teamcity import TeamCityAdapter, analyze_teamcity
from readtheplan.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "teamcity_risky.kts"


def test_teamcity_flags_commands_credentials_agents_and_dsl_execution() -> None:
    source = FIXTURE.read_text(encoding="utf-8")
    data = {"teamcity": source}
    adapter = detect_adapter(data)
    assert isinstance(adapter, TeamCityAdapter)
    changes = adapter.analyze(data, use_rules=False)
    kinds: dict[str, list[str]] = {}
    for change in changes:
        kinds.setdefault(change.resource_type, []).append(change.risk)

    assert kinds["teamcity_command"] == ["dangerous"]
    assert all(risk == "dangerous" for risk in kinds["teamcity_secret_input"])
    assert kinds["teamcity_vcs_root"] == ["review", "review"]
    assert kinds["teamcity_vcs_authentication"] == ["dangerous"]
    assert kinds["teamcity_trigger"] == ["review"]
    assert kinds["teamcity_dependency"] == ["review", "review"]
    assert kinds["teamcity_agent_requirement"] == ["review", "review"]
    assert kinds["teamcity_external_integration"] == ["dangerous"]
    assert kinds["teamcity_cleanup"] == ["dangerous"]
    assert kinds["teamcity_image"] == ["dangerous"]
    assert kinds["teamcity_artifact"] == ["review"]
    assert kinds["teamcity_dsl_execution"] == ["dangerous"]
    assert kinds["teamcity_dsl_file_access"] == ["dangerous"]

    payload = analyze_teamcity(data)
    encoded = json.dumps(payload)
    assert "literal-teamcity-token" not in encoded
    assert "repo-token" not in encoded


def test_teamcity_comment_only_patterns_are_ignored() -> None:
    source = """
import jetbrains.buildServer.configs.kotlin.*
project {
    // scriptContent = "dangerous"
    /* ProcessBuilder("sh") */
}
"""
    changes = TeamCityAdapter().analyze({"teamcity": source}, use_rules=False)
    kinds = {change.resource_type for change in changes}
    assert "teamcity_command" not in kinds
    assert "teamcity_dsl_execution" not in kinds


def test_teamcity_digest_pinned_image_is_review() -> None:
    digest = "a" * 64
    source = (
        "import jetbrains.buildServer.configs.kotlin.*\n"
        f'project {{ image = "alpine@sha256:{digest}" }}\n'
    )
    changes = TeamCityAdapter().analyze({"teamcity": source}, use_rules=False)
    image = next(change for change in changes if change.resource_type == "teamcity_image")
    assert image.risk == "review"


def test_teamcity_cli_emits_framework_gate(capsys) -> None:
    assert main(["teamcity", "--framework", "soc2", str(FIXTURE)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "teamcity"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
