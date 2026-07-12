from __future__ import annotations

import json

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.pipelines import (
    CircleCIAdapter,
    GitHubActionsAdapter,
    GitLabCIAdapter,
    PipelineInputError,
    parse_pipeline_yaml,
)
from readtheplan.cli import main


def test_github_actions_preserves_on_and_flags_privileged_steps() -> None:
    data = parse_pipeline_yaml(
        """
name: deploy
on: [push]
permissions: write-all
jobs:
  deploy:
    environment: production
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh --token '${{ secrets.DEPLOY_TOKEN }}'
""",
        "github-actions",
    )
    assert "on" in data["github_actions"]
    adapter = detect_adapter(data)
    assert isinstance(adapter, GitHubActionsAdapter)

    changes = adapter.analyze(data, use_rules=False)
    by_type = {change.resource_type: change for change in changes}
    assert by_type["github_actions_permissions"].risk == "dangerous"
    assert by_type["github_actions_environment"].risk == "review"
    assert by_type["github_actions_action"].risk == "dangerous"
    assert by_type["github_actions_run"].risk == "dangerous"
    assert by_type["github_actions_secret_input"].risk == "dangerous"


def test_github_actions_full_sha_and_empty_permissions_reduce_risk() -> None:
    sha = "a" * 40
    data = parse_pipeline_yaml(
        f"permissions: {{}}\njobs:\n  test:\n    steps:\n      - uses: owner/action@{sha}\n",
        "github-actions",
    )
    changes = GitHubActionsAdapter().analyze(data, use_rules=False)
    assert [change.risk for change in changes] == ["safe", "review"]


def test_gitlab_ci_flags_remote_include_script_environment_and_token() -> None:
    data = parse_pipeline_yaml(
        """
include:
  - remote: https://example.com/pipeline.yml
deploy:
  script: ./deploy.sh $CI_JOB_TOKEN
  environment: production
""",
        "gitlab-ci",
    )
    adapter = detect_adapter(data)
    assert isinstance(adapter, GitLabCIAdapter)
    changes = adapter.analyze(data, use_rules=False)
    by_type = {change.resource_type: change for change in changes}
    assert by_type["gitlab_ci_include"].risk == "dangerous"
    assert by_type["gitlab_ci_script"].risk == "dangerous"
    assert by_type["gitlab_ci_environment"].risk == "review"
    assert by_type["gitlab_ci_secret_input"].risk == "dangerous"


def test_circleci_flags_orbs_keys_remote_docker_and_run() -> None:
    data = parse_pipeline_yaml(
        """
version: 2.1
orbs:
  tools: example/tools@volatile
jobs:
  deploy:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - add_ssh_keys
      - setup_remote_docker
      - run: ./deploy.sh
""",
        "circleci",
    )
    adapter = detect_adapter(data)
    assert isinstance(adapter, CircleCIAdapter)
    changes = adapter.analyze(data, use_rules=False)
    assert [change.risk for change in changes] == [
        "dangerous",
        "dangerous",
        "safe",
        "dangerous",
        "dangerous",
        "dangerous",
    ]


@pytest.mark.parametrize(
    ("tool", "source", "expected_code", "expected_adapter"),
    [
        (
            "github-actions",
            "permissions: {}\njobs:\n  docs:\n    steps:\n      - uses: ./local-action\n",
            1,
            "github-actions",
        ),
        ("gitlab-ci", "deploy:\n  script: ./deploy.sh\n", 2, "gitlab-ci"),
        (
            "circleci",
            "version: 2.1\njobs:\n  docs:\n    steps:\n      - checkout\n",
            0,
            "circleci",
        ),
    ],
)
def test_pipeline_cli_and_framework_baseline(
    tool: str,
    source: str,
    expected_code: int,
    expected_adapter: str,
    tmp_path,
    capsys,
) -> None:
    config = tmp_path / f"{tool}.yml"
    config.write_text(source, encoding="utf-8")

    assert main([tool, "--framework", "soc2", str(config)]) == expected_code
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == expected_adapter
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize("source", ["", "[]", "jobs: [unterminated"])
def test_pipeline_parser_rejects_invalid_input(source: str) -> None:
    with pytest.raises(PipelineInputError):
        parse_pipeline_yaml(source, "github-actions")


def test_pipeline_parser_rejects_unknown_ecosystem() -> None:
    with pytest.raises(PipelineInputError, match="unsupported pipeline ecosystem"):
        parse_pipeline_yaml("jobs: {}", "unknown")
