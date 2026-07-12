from __future__ import annotations

import json

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.pipelines import (
    AzurePipelinesAdapter,
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


def test_azure_pipelines_flags_protected_resources_and_deployment_steps() -> None:
    data = parse_pipeline_yaml(
        """
resources:
  repositories:
    - repository: templates
      type: git
      name: Platform/Templates
      ref: refs/heads/main
      endpoint: external-git
  containers:
    - container: builder
      image: ubuntu:latest
variables:
  - group: production-secrets
  - name: API_TOKEN
    value: inline-secret
stages:
  - stage: Deploy
    jobs:
      - deployment: production
        environment: production
        pool: private-agents
        strategy:
          runOnce:
            deploy:
              steps:
                - task: AzureCLI@2
                  inputs:
                    azureSubscription: production-subscription
                - bash: ./deploy.sh
                  env:
                    API_TOKEN: $(PRODUCTION_TOKEN)
""",
        "azure-pipelines",
    )
    adapter = detect_adapter(data)
    assert isinstance(adapter, AzurePipelinesAdapter)
    changes = adapter.analyze(data, use_rules=False)
    by_type: dict[str, list[str]] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change.risk)

    assert by_type["azure_pipelines_repository"] == ["dangerous"]
    assert by_type["azure_pipelines_service_connection"] == [
        "dangerous",
        "dangerous",
    ]
    assert by_type["azure_pipelines_image"] == ["dangerous"]
    assert by_type["azure_pipelines_variable_group"] == ["dangerous"]
    assert by_type["azure_pipelines_inline_secret"] == ["dangerous"]
    assert by_type["azure_pipelines_environment"] == ["review"]
    assert by_type["azure_pipelines_pool"] == ["dangerous"]
    assert by_type["azure_pipelines_task"] == ["dangerous"]
    assert by_type["azure_pipelines_script"] == ["dangerous"]
    assert by_type["azure_pipelines_secret_input"] == ["dangerous"]
    assert by_type["azure_pipelines_protected_resources"] == ["review"]


def test_azure_pipelines_pinned_repository_reduces_template_risk() -> None:
    sha = "a" * 40
    data = parse_pipeline_yaml(
        f"""
resources:
  repositories:
    - repository: templates
      type: git
      name: Platform/Templates
      ref: {sha}
extends:
  template: secure.yml@templates
steps:
  - checkout: self
    persistCredentials: false
""",
        "azure-pipelines",
    )
    changes = AzurePipelinesAdapter().analyze(data, use_rules=False)
    assert [change.risk for change in changes] == [
        "review",
        "review",
        "review",
        "review",
    ]


def test_azure_pipelines_triggers_and_failure_hooks_are_discovered() -> None:
    data = parse_pipeline_yaml(
        """
pr:
  branches:
    include: [main]
jobs:
  - deployment: production
    environment: production
    strategy:
      runOnce:
        on:
          failure:
            steps:
              - pwsh: ./rollback.ps1
""",
        "azure-pipelines",
    )
    changes = AzurePipelinesAdapter().analyze(data, use_rules=False)
    by_type = {change.resource_type: change for change in changes}
    assert by_type["azure_pipelines_trigger"].risk == "review"
    assert by_type["azure_pipelines_script"].risk == "dangerous"


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
        (
            "azure-pipelines",
            "steps:\n  - script: ./deploy.sh\n",
            2,
            "azure-pipelines",
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
