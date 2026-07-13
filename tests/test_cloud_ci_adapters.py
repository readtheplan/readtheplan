from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.cloud_ci import (
    CloudCIInputError,
    CodeBuildAdapter,
    CodePipelineAdapter,
    GoogleCloudBuildAdapter,
    analyze_cloud_ci,
    parse_cloud_ci,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(adapter, data) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for change in adapter.analyze(data, use_rules=False):
        grouped.setdefault(change.resource_type, []).append(change.risk)
    return grouped


def test_codebuild_flags_commands_secrets_identity_artifacts_and_failure_policy() -> None:
    source = (FIXTURES / "codebuild_risky.yml").read_text(encoding="utf-8")
    data = parse_cloud_ci(source, "codebuild")
    adapter = detect_adapter(data)
    assert isinstance(adapter, CodeBuildAdapter)
    risks = _risks(adapter, data)

    assert risks["codebuild_version"] == ["review"]
    assert risks["codebuild_run_as"] == ["dangerous"]
    assert risks["codebuild_secret_input"] == ["dangerous", "dangerous", "dangerous"]
    assert risks["codebuild_exported_environment"] == ["dangerous"]
    assert risks["codebuild_git_credentials"] == ["dangerous"]
    assert len(risks["codebuild_command"]) == 5
    assert risks["codebuild_failure_policy"] == ["dangerous"]
    assert risks["codebuild_artifact"] == ["review"]
    assert risks["codebuild_report"] == ["safe"]
    payload = analyze_cloud_ci(adapter, data)
    assert "literal-codebuild-token" not in json.dumps(payload)


def test_google_cloud_build_flags_images_commands_secrets_identity_and_publication() -> None:
    source = (FIXTURES / "google_cloud_build_risky.yml").read_text(encoding="utf-8")
    data = parse_cloud_ci(source, "cloud-build")
    adapter = detect_adapter(data)
    assert isinstance(adapter, GoogleCloudBuildAdapter)
    risks = _risks(adapter, data)

    assert risks["cloud_build_image"] == ["dangerous", "dangerous"]
    assert risks["cloud_build_command"] == ["dangerous", "dangerous"]
    assert set(risks["cloud_build_secret_input"]) == {"dangerous"}
    assert risks["cloud_build_service_account"] == ["dangerous"]
    assert risks["cloud_build_soft_fail"] == ["dangerous"]
    assert risks["cloud_build_volume"] == ["review"]
    assert risks["cloud_build_image_publish"] == ["dangerous"]
    assert risks["cloud_build_artifact"] == ["dangerous"]
    payload = analyze_cloud_ci(adapter, data)
    assert "literal-cloud-build-token" not in json.dumps(payload)


def test_codepipeline_flags_roles_deployments_invocations_and_artifact_flow() -> None:
    source = (FIXTURES / "codepipeline_risky.json").read_text(encoding="utf-8")
    data = parse_cloud_ci(source, "codepipeline")
    adapter = detect_adapter(data)
    assert isinstance(adapter, CodePipelineAdapter)
    risks = _risks(adapter, data)

    assert risks["codepipeline_service_role"] == ["dangerous"]
    assert risks["codepipeline_artifact_store"] == ["review"]
    assert risks["codepipeline_source_action"] == ["review"]
    assert risks["codepipeline_approval_action"] == ["review"]
    assert risks["codepipeline_deploy_action"] == ["dangerous"]
    assert risks["codepipeline_invoke_action"] == ["dangerous"]
    assert risks["codepipeline_action_role"] == ["dangerous"]
    assert "dangerous" in risks["codepipeline_action_configuration"]
    assert risks["codepipeline_secret_input"] == ["dangerous"]
    assert len(risks["codepipeline_artifact_flow"]) == 2
    payload = analyze_cloud_ci(adapter, data)
    assert "literal-codepipeline-token" not in json.dumps(payload)


def test_google_cloud_build_digest_pinned_image_is_review() -> None:
    digest = "a" * 64
    data = parse_cloud_ci(
        f"steps:\n  - name: gcr.io/example/builder@sha256:{digest}\n    args: [test]\n",
        "cloud-build",
    )
    adapter = detect_adapter(data)
    assert isinstance(adapter, GoogleCloudBuildAdapter)
    risks = _risks(adapter, data)
    assert risks["cloud_build_image"] == ["review"]


@pytest.mark.parametrize("source", ["", "[]", "- invalid"])
def test_cloud_ci_parser_rejects_empty_or_non_object_input(source: str) -> None:
    with pytest.raises(CloudCIInputError):
        parse_cloud_ci(source, "codebuild")


@pytest.mark.parametrize(
    ("tool", "fixture"),
    [
        ("codebuild", "codebuild_risky.yml"),
        ("cloud-build", "google_cloud_build_risky.yml"),
        ("codepipeline", "codepipeline_risky.json"),
    ],
)
def test_cloud_ci_cli_emits_framework_gate(tool: str, fixture: str, capsys) -> None:
    assert main([tool, "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == tool
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
