from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.pipelines import (
    AzurePipelinesAdapter,
    BitbucketPipelinesAdapter,
    BuildkiteAdapter,
    CircleCIAdapter,
    DroneCIAdapter,
    GitHubActionsAdapter,
    GitLabCIAdapter,
    PipelineInputError,
    TravisCIAdapter,
    WoodpeckerCIAdapter,
    analyze_pipeline,
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


def test_bitbucket_pipelines_classifies_runners_oidc_pipes_and_deployments() -> None:
    data = parse_pipeline_yaml(
        """
image: atlassian/default-image:4
definitions:
  services:
    docker:
      image: docker:27-dind
      type: docker
pipelines:
  default:
    - step:
        runs-on: [self.hosted, linux]
        deployment: production
        oidc: true
        services: [docker]
        script:
          - terraform apply -var token=$API_TOKEN
          - pipe: atlassian/aws-s3-deploy:1.6.1
            variables:
              API_TOKEN: $DEPLOY_TOKEN
""",
        "bitbucket-pipelines",
    )
    adapter = detect_adapter(data)
    assert isinstance(adapter, BitbucketPipelinesAdapter)
    changes = adapter.analyze(data, use_rules=False)
    by_type: dict[str, list[str]] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change.risk)

    assert by_type["bitbucket_pipelines_image"] == ["dangerous"]
    assert by_type["bitbucket_pipelines_service_image"] == ["dangerous"]
    assert by_type["bitbucket_pipelines_docker_service"] == ["dangerous"]
    assert by_type["bitbucket_pipelines_trigger"] == ["review"]
    assert by_type["bitbucket_pipelines_runner"] == ["dangerous"]
    assert by_type["bitbucket_pipelines_deployment"] == ["review"]
    assert by_type["bitbucket_pipelines_oidc"] == ["dangerous"]
    assert by_type["bitbucket_pipelines_service"] == ["dangerous"]
    assert by_type["bitbucket_pipelines_script"] == ["dangerous"]
    assert by_type["bitbucket_pipelines_pipe"] == ["review"]
    assert by_type["bitbucket_pipelines_secret_input"] == [
        "dangerous",
        "dangerous",
    ]
    assert by_type["bitbucket_pipelines_external_settings"] == ["review"]


def test_bitbucket_pipeline_import_and_custom_secret_variable_block() -> None:
    data = parse_pipeline_yaml(
        """
pipelines:
  custom:
    release:
      - variables:
          - name: DEPLOY_TOKEN
      - step:
          type: pipeline
          custom: child-release
          input-variables:
            API_TOKEN: $DEPLOY_TOKEN
    shared:
      import: workspace/shared:main:release
""",
        "bitbucket-pipelines",
    )
    changes = BitbucketPipelinesAdapter().analyze(data, use_rules=False)
    by_type: dict[str, list[str]] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change.risk)
    assert by_type["bitbucket_pipelines_custom_variable"] == ["dangerous"]
    assert by_type["bitbucket_pipelines_child_pipeline"] == ["review"]
    assert by_type["bitbucket_pipelines_secret_input"] == ["dangerous"]
    assert by_type["bitbucket_pipelines_import"] == ["dangerous"]


def test_bitbucket_stage_environment_condition_and_empty_step_require_review() -> None:
    data = parse_pipeline_yaml(
        """
pipelines:
  branches:
    main:
      - stage:
          environment: production
          steps:
            - step:
                condition:
                  changesets:
                    includePaths: [infra/**]
""",
        "bitbucket-pipelines",
    )
    changes = BitbucketPipelinesAdapter().analyze(data, use_rules=False)
    by_type = {change.resource_type: change for change in changes}
    assert by_type["bitbucket_pipelines_deployment"].risk == "review"
    assert by_type["bitbucket_pipelines_condition"].risk == "review"
    assert by_type["bitbucket_pipelines_unresolved"].risk == "review"


def test_buildkite_flags_commands_plugins_secrets_agents_and_dynamic_uploads() -> None:
    source = (Path(__file__).parent / "fixtures" / "buildkite_deploy.yml").read_text(
        encoding="utf-8"
    )
    data = parse_pipeline_yaml(source, "buildkite")
    adapter = detect_adapter(data)
    assert isinstance(adapter, BuildkiteAdapter)
    changes = adapter.analyze(data, use_rules=False)
    by_type: dict[str, list[str]] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change.risk)

    assert by_type["buildkite_environment"] == ["dangerous"]
    assert by_type["buildkite_agents"] == ["review", "review"]
    assert by_type["buildkite_command"] == ["dangerous", "dangerous"]
    assert by_type["buildkite_dynamic_pipeline"] == ["dangerous"]
    assert by_type["buildkite_plugin"] == ["dangerous", "review"]
    assert by_type["buildkite_secret_input"] == ["dangerous"]
    assert by_type["buildkite_soft_fail"] == ["dangerous"]
    assert by_type["buildkite_trigger"] == ["dangerous"]
    assert by_type["buildkite_approval"] == ["review"]
    assert by_type["buildkite_wait"] == ["safe"]


def test_travis_ci_flags_imports_privilege_commands_deploy_and_secrets() -> None:
    source = (Path(__file__).parent / "fixtures" / "travis_ci_risky.yml").read_text(
        encoding="utf-8"
    )
    data = parse_pipeline_yaml(source, "travis-ci")
    adapter = detect_adapter(data)
    assert isinstance(adapter, TravisCIAdapter)
    changes = adapter.analyze(data, use_rules=False)
    by_type: dict[str, list[str]] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change.risk)

    assert by_type["travis_ci_import"] == ["dangerous"]
    assert by_type["travis_ci_privileged"] == ["dangerous"]
    assert by_type["travis_ci_service"] == ["dangerous"]
    assert by_type["travis_ci_script"] == ["dangerous", "dangerous", "dangerous"]
    assert by_type["travis_ci_deployment"] == ["dangerous"]
    assert by_type["travis_ci_secret_input"] == ["dangerous", "dangerous"]
    assert by_type["travis_ci_soft_fail"] == ["dangerous"]
    assert by_type["travis_ci_cache"] == ["review"]
    payload = analyze_pipeline(adapter, data)
    assert "literal-example-token" not in json.dumps(payload)


def test_travis_ci_immutable_import_is_review_instead_of_dangerous() -> None:
    commit = "a" * 40
    data = parse_pipeline_yaml(f"import: example/shared.yml@{commit}\n", "travis-ci")
    adapter = detect_adapter(data)
    assert isinstance(adapter, TravisCIAdapter)
    changes = adapter.analyze(data, use_rules=False)
    imported = next(change for change in changes if change.resource_type == "travis_ci_import")
    assert imported.risk == "review"


def test_drone_ci_supports_multi_document_pipelines_and_signatures() -> None:
    source = (Path(__file__).parent / "fixtures" / "drone_ci_risky.yml").read_text(
        encoding="utf-8"
    )
    data = parse_pipeline_yaml(source, "drone-ci")
    assert len(data["drone_ci"]["documents"]) == 2
    adapter = detect_adapter(data)
    assert isinstance(adapter, DroneCIAdapter)
    changes = adapter.analyze(data, use_rules=False)
    by_type: dict[str, list[str]] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change.risk)

    assert by_type["drone_ci_runner_selection"] == ["review"]
    assert by_type["drone_ci_host_volume"] == ["dangerous", "dangerous"]
    assert by_type["drone_ci_image"] == ["dangerous", "dangerous"]
    assert by_type["drone_ci_service_image"] == ["dangerous"]
    assert by_type["drone_ci_commands"] == ["dangerous", "dangerous"]
    assert by_type["drone_ci_privileged"] == ["dangerous", "dangerous"]
    assert by_type["drone_ci_secret_input"] == ["dangerous"]
    assert by_type["drone_ci_soft_fail"] == ["dangerous"]
    assert by_type["drone_ci_signature"] == ["safe"]


def test_drone_ci_rejects_non_object_yaml_documents() -> None:
    with pytest.raises(PipelineInputError, match="documents must be objects"):
        parse_pipeline_yaml("kind: pipeline\nsteps: []\n---\n- invalid\n", "drone-ci")


def test_woodpecker_ci_flags_runner_host_access_plugins_and_secrets() -> None:
    source = (Path(__file__).parent / "fixtures" / "woodpecker_ci_risky.yml").read_text(
        encoding="utf-8"
    )
    data = parse_pipeline_yaml(source, "woodpecker-ci")
    adapter = detect_adapter(data)
    assert isinstance(adapter, WoodpeckerCIAdapter)
    changes = adapter.analyze(data, use_rules=False)
    by_type: dict[str, list[str]] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change.risk)

    assert by_type["woodpecker_ci_runner_selection"] == ["review"]
    assert by_type["woodpecker_ci_clone"] == ["review"]
    assert by_type["woodpecker_ci_host_volume"] == ["dangerous", "dangerous"]
    assert by_type["woodpecker_ci_image"] == ["dangerous", "dangerous"]
    assert by_type["woodpecker_ci_service_image"] == ["dangerous"]
    assert by_type["woodpecker_ci_commands"] == ["dangerous"]
    assert by_type["woodpecker_ci_privileged"] == ["dangerous", "dangerous"]
    assert by_type["woodpecker_ci_secret_input"] == ["dangerous", "dangerous"]


@pytest.mark.parametrize("ecosystem", ["drone-ci", "woodpecker-ci"])
def test_container_pipeline_digest_pin_and_named_volume_reduce_risk(ecosystem: str) -> None:
    source = """
steps:
  - name: test
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    volumes:
      - cache:/cache
    commands: [echo test]
"""
    if ecosystem == "drone-ci":
        source = "kind: pipeline\ntype: docker\n" + source
    data = parse_pipeline_yaml(source, ecosystem)
    adapter = detect_adapter(data)
    assert adapter is not None
    changes = adapter.analyze(data, use_rules=False)
    by_type = {change.resource_type: change.risk for change in changes}
    prefix = ecosystem.replace("-", "_")
    assert by_type[f"{prefix}_image"] == "review"
    assert by_type[f"{prefix}_volume"] == "review"


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
        (
            "bitbucket-pipelines",
            "pipelines:\n  default:\n    - step:\n        script: [echo hello]\n",
            2,
            "bitbucket-pipelines",
        ),
        (
            "buildkite",
            "steps:\n  - command: ./deploy.sh\n",
            2,
            "buildkite",
        ),
        (
            "travis-ci",
            "language: minimal\nscript: ./deploy.sh\n",
            2,
            "travis-ci",
        ),
        (
            "drone-ci",
            "kind: pipeline\ntype: docker\nsteps:\n"
            "  - name: deploy\n    image: alpine\n    commands: [./deploy.sh]\n",
            2,
            "drone-ci",
        ),
        (
            "woodpecker-ci",
            "steps:\n  - name: deploy\n    image: alpine\n    commands: [./deploy.sh]\n",
            2,
            "woodpecker-ci",
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
