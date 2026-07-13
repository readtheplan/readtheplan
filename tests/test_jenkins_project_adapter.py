from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.jenkins_project import (
    JenkinsProjectAdapter,
    JenkinsProjectInputError,
    analyze_jenkins_project,
    parse_jenkins_project,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(fixture: str):
    source = (FIXTURES / fixture).read_text(encoding="utf-8")
    data = parse_jenkins_project(source, filename=fixture)
    return JenkinsProjectAdapter().analyze(data, tool_name="Jenkins project")


def test_text_catalog_surfaces_mutable_experimental_incremental_and_url_sources() -> None:
    changes = _changes("jenkins_plugins_risky.txt")
    plugins = [
        change for change in changes if change.resource_type == "jenkins_project_plugin"
    ]
    encoded = json.dumps(
        [{"address": change.address, "explanation": change.explanation} for change in changes]
    )

    assert len(changes) == 8
    assert len(plugins) == 7
    assert sum(change.risk == "dangerous" for change in changes) == 5
    assert sum(change.risk == "review" for change in changes) == 3
    assert any("mutable latest" in change.explanation for change in changes)
    assert any("experimental update center" in change.explanation for change in changes)
    assert any("pinned incremental" in change.explanation for change in changes)
    assert any("two-field URL form is ambiguous" in change.explanation for change in changes)
    assert any("privileged controller boundary" in change.explanation for change in changes)
    assert "fixture-user" not in encoded
    assert "fixture-password" not in encoded
    assert "plugins.internal.example" not in encoded


def test_yaml_catalog_with_exact_versions_stays_review_only() -> None:
    changes = _changes("jenkins_plugins_review.yaml")

    assert len(changes) == 4
    assert {change.risk for change in changes} == {"review"}
    assert any("credential storage" in change.explanation for change in changes)
    assert any("custom Maven group" in change.explanation for change in changes)


def test_yaml_latest_and_direct_url_are_dangerous() -> None:
    data = parse_jenkins_project(
        "plugins:\n"
        "  - artifactId: workflow-cps\n"
        "    source:\n"
        "      version: latest\n"
        "  - artifactId: script-security\n"
        "    source:\n"
        "      version: 1.0\n"
        "      url: file:///tmp/plugin.hpi\n",
        filename="plugins.yaml",
    )
    changes = JenkinsProjectAdapter().analyze(data)
    plugins = [
        change for change in changes if change.resource_type == "jenkins_project_plugin"
    ]

    assert len(plugins) == 2
    assert {change.risk for change in plugins} == {"dangerous"}
    assert any("local or plaintext transport" in change.explanation for change in plugins)


def test_text_catalog_supports_every_official_coordinate_shape() -> None:
    data = parse_jenkins_project(
        "git\n"
        "mailer:1.32\n"
        "job-dsl::https://plugins.example/job-dsl.hpi\n"
        "workflow-api:2.40:https://plugins.example/workflow-api.hpi\n"
        "workflow-support:incrementals;org.jenkins-ci.plugins.workflow;1.2-rc3\n",
        filename="plugins.txt",
    )
    plugins = data["jenkins_project"]["document"]["plugins"]

    assert len(plugins) == 5
    assert plugins[0]["version"] == ""
    assert plugins[1]["version"] == "1.32"
    assert plugins[2]["url"].startswith("https://")
    assert plugins[3]["version"] == "2.40"
    assert plugins[4]["version"].startswith("incrementals;")


@pytest.mark.parametrize(
    ("source", "filename", "error"),
    [
        ("", "plugins.txt", "empty"),
        ("bad plugin:1.0\n", "plugins.txt", "whitespace"),
        ("git:\n", "plugins.txt", "missing plugin version"),
        ("git:1.0:not-a-url\n", "plugins.txt", "invalid plugin download URL"),
        ("git:1.0\nGIT:2.0\n", "plugins.txt", "duplicate plugin artifact ID"),
        ("plugins: {}\n", "plugins.yaml", "plugins must be a list"),
        ("plugins:\n  - git\n", "plugins.yaml", "must be a mapping"),
        ("plugins:\n  - artifactId: git\n    extra: true\n", "plugins.yaml", "unsupported"),
        (
            "plugins:\n  - artifactId: git\n    source:\n      checksum: abc\n",
            "plugins.yaml",
            "unsupported plugin source",
        ),
        (
            "plugins:\n  - artifactId: git\n    artifactId: mailer\n",
            "plugins.yaml",
            "duplicate YAML key",
        ),
        (
            "plugins:\n  - artifactId: git\n  - artifactId: git\n",
            "plugins.yaml",
            "duplicate plugin artifact ID",
        ),
        ("hello: world\n", "plugins.yaml", "only a plugins list"),
    ],
)
def test_parser_rejects_empty_ambiguous_duplicate_or_malformed_catalogs(
    source: str,
    filename: str,
    error: str,
) -> None:
    with pytest.raises(JenkinsProjectInputError, match=error):
        parse_jenkins_project(source, filename=filename)


def test_parser_handles_long_adversarial_plugin_id_linearly() -> None:
    with pytest.raises(JenkinsProjectInputError, match="invalid plugin artifact ID"):
        parse_jenkins_project("a" * 100_000 + "!:1.0\n", filename="plugins.txt")


@pytest.mark.parametrize(
    ("fixture", "artifact_type", "exit_code", "decision", "total_changes"),
    [
        ("jenkins_plugins_risky.txt", "plugins_txt", 2, "block", 8),
        ("jenkins_plugins_review.yaml", "plugins_yaml", 1, "warn", 4),
    ],
)
def test_gate_and_cli_support_text_and_yaml_catalogs(
    fixture: str,
    artifact_type: str,
    exit_code: int,
    decision: str,
    total_changes: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = (FIXTURES / fixture).read_text(encoding="utf-8")
    data = parse_jenkins_project(source, filename=fixture)
    gate = analyze_jenkins_project(data)

    assert gate["adapter"] == "jenkins-project"
    assert gate["artifact_type"] == artifact_type
    assert gate["plugin_count"] == total_changes - 1
    assert gate["total_changes"] == total_changes
    assert gate["decision"] == decision

    assert main(["jenkins-project", "--framework", "soc2", str(FIXTURES / fixture)]) == exit_code
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "jenkins-project"
    assert payload["artifact_type"] == artifact_type
    assert payload["plugin_count"] == total_changes - 1
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
