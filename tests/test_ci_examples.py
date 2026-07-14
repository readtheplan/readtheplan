from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "ci"

YAML_EXAMPLES = [
    "gitlab-ci.example.yml",
    "azure-pipelines.example.yml",
    "circleci.example.yml",
    "buildkite.example.yml",
    "bitbucket-pipelines.example.yml",
]


def _project_version() -> str:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert match is not None
    return match.group(1)


def test_ci_examples_are_parseable_and_pin_the_current_release() -> None:
    expected_pin = f'readtheplan=={_project_version()}'

    for name in YAML_EXAMPLES:
        text = (CI / name).read_text(encoding="utf-8")
        assert yaml.safe_load(text) is not None, name
        assert expected_pin in text, name
        assert "--fail-on dangerous" in text, name
        assert "plan.json" in text, name
        assert "readtheplan-summary.json" in text, name
        assert "readtheplan-evidence.json" in text, name


def test_jenkins_example_uses_the_same_portable_contract() -> None:
    text = (CI / "Jenkinsfile.example").read_text(encoding="utf-8")

    assert f'readtheplan=={_project_version()}' in text
    assert "--fail-on dangerous" in text
    assert "plan.json" in text
    assert "archiveArtifacts" in text
    assert "readtheplan-summary.json" in text
    assert "readtheplan-evidence.json" in text


def test_ci_examples_do_not_publish_raw_plan_json() -> None:
    artifact_markers = {
        "gitlab-ci.example.yml": "paths:",
        "azure-pipelines.example.yml": "- publish:",
        "circleci.example.yml": "- store_artifacts:",
        "buildkite.example.yml": "artifact_paths:",
        "bitbucket-pipelines.example.yml": "artifacts:",
        "Jenkinsfile.example": "archiveArtifacts artifacts:",
    }

    for name, marker in artifact_markers.items():
        text = (CI / name).read_text(encoding="utf-8")
        artifact_section = text.split(marker, maxsplit=1)[1]
        assert "plan.json" not in artifact_section, name


def test_ci_documentation_names_native_and_portable_paths() -> None:
    ci_readme = (CI / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "ci-integrations.md").read_text(encoding="utf-8")
    combined = ci_readme + guide

    for provider in [
        "GitHub Actions",
        "GitLab CI",
        "Jenkins",
        "Azure DevOps",
        "CircleCI",
        "Buildkite",
        "Bitbucket Pipelines",
    ]:
        assert provider in combined

    assert "Terraform plan JSON can contain sensitive values" in combined
    assert "The GitHub Action is a native convenience wrapper" in combined
