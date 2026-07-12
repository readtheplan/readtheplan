from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.serverless import (
    SamTemplateAdapter,
    ServerlessFrameworkAdapter,
    ServerlessInputError,
    parse_sam_template,
    parse_serverless_source,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(fixture: str, parser, adapter) -> dict[str, list[str]]:
    data = parser((FIXTURES / fixture).read_text(encoding="utf-8"))
    result: dict[str, list[str]] = defaultdict(list)
    for change in adapter.analyze(data, tool_name=adapter.adapter_name):
        result[change.resource_type].append(change.risk)
    return result


def test_serverless_framework_surfaces_deployment_and_identity_boundaries() -> None:
    risks = _risks(
        "serverless_framework_risky.yml",
        parse_serverless_source,
        ServerlessFrameworkAdapter(),
    )
    assert risks["serverless_service"] == ["review"]
    assert risks["serverless_unpinned_framework"] == ["dangerous"]
    assert risks["serverless_dashboard_integration"] == ["review"]
    assert risks["serverless_relaxed_validation"] == ["dangerous"]
    assert len(risks["serverless_deployment_identity"]) == 2
    assert len(risks["serverless_deployment_target"]) == 2
    assert risks["serverless_direct_deployment"] == ["review"]
    assert risks["serverless_deployment_artifacts"] == ["review"]
    assert risks["serverless_unencrypted_artifacts"] == ["dangerous"]
    assert risks["serverless_public_artifact_boundary"] == ["dangerous"]
    assert risks["serverless_unmanaged_bucket_policy"] == ["dangerous"]
    assert risks["serverless_iam_statement"] == ["dangerous", "dangerous"]
    assert risks["serverless_managed_policies"] == ["dangerous"]
    assert risks["serverless_disabled_logging"] == ["dangerous"]


def test_serverless_framework_surfaces_functions_events_plugins_and_variables() -> None:
    risks = _risks(
        "serverless_framework_risky.yml",
        parse_serverless_source,
        ServerlessFrameworkAdapter(),
    )
    assert len(risks["serverless_function"]) == 2
    assert risks["serverless_function_image"] == ["dangerous"]
    assert risks["serverless_execution_role"] == ["dangerous"]
    assert len(risks["serverless_network_attachment"]) == 2
    assert risks["serverless_filesystem_mount"] == ["dangerous"]
    assert risks["serverless_public_event_ingress"] == ["dangerous"]
    assert risks["serverless_event_source"] == ["dangerous", "review"]
    assert len(risks["serverless_plugin"]) == 2
    assert len(risks["serverless_package_boundary"]) == 3
    assert risks["serverless_plugin_constructs"] == ["dangerous"]
    assert risks["serverless_generated_resource_override"] == ["dangerous"]
    assert risks["serverless_external_file"] == ["dangerous"]
    assert len(risks["serverless_external_variable"]) >= 2
    assert "dangerous" in risks["serverless_secret_material"]
    assert "review" in risks["serverless_secret_material"]


def test_sam_surfaces_transform_function_and_event_semantics() -> None:
    risks = _risks("sam_template_risky.yml", parse_sam_template, SamTemplateAdapter())
    assert risks["sam_template"] == ["review"]
    assert risks["sam_additional_macro"] == ["dangerous"]
    assert risks["sam_global_defaults"] == ["review"]
    assert len(risks["sam_function"]) == 2
    assert risks["sam_inline_code"] == ["dangerous"]
    assert risks["sam_function_image"] == ["dangerous"]
    assert risks["sam_execution_role"] == ["dangerous"]
    assert risks["sam_function_policies"] == ["dangerous"]
    assert "dangerous" in risks["sam_iam_statement"]
    assert risks["sam_public_function_url"] == ["dangerous"]
    assert risks["sam_public_event_ingress"] == ["dangerous"]
    assert risks["sam_event_source"] == ["dangerous", "review"]
    assert risks["sam_custom_build"] == ["dangerous"]


def test_sam_surfaces_api_orchestration_nested_and_lifecycle_semantics() -> None:
    risks = _risks("sam_template_risky.yml", parse_sam_template, SamTemplateAdapter())
    assert risks["sam_api"] == ["dangerous"]
    assert risks["sam_missing_api_auth"] == ["dangerous"]
    assert risks["sam_cors_policy"] == ["review"]
    assert risks["sam_external_api_definition"] == ["dangerous"]
    assert risks["sam_api_resource_policy"] == ["dangerous"]
    assert risks["sam_state_machine"] == ["dangerous"]
    assert risks["sam_external_definition"] == ["dangerous"]
    assert risks["sam_state_machine_identity"] == ["dangerous"]
    assert risks["sam_nested_application"] == ["dangerous"]
    assert risks["sam_unpinned_application"] == ["dangerous"]
    assert risks["sam_connector_permissions"] == ["dangerous"]
    assert risks["sam_compute_or_network_control"] == ["dangerous"]
    assert risks["sam_serverless_resource"] == ["review"]
    assert risks["sam_code_artifact"] == ["review"]
    assert risks["sam_lifecycle_policy"] == ["dangerous", "dangerous"]
    assert len(risks["sam_embedded_cloudformation"]) == 2
    assert "dangerous" in risks["sam_secret_material"]


def test_intrinsic_tags_are_retained_without_execution() -> None:
    data = parse_sam_template(
        """\
Transform: AWS::Serverless-2016-10-31
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: python3.13
      Handler: app.handler
      CodeUri: !Sub s3://${Bucket}/code.zip
"""
    )
    document = data["aws_sam"]["document"]
    assert document["Resources"]["Fn"]["Properties"]["CodeUri"] == {
        "Sub": "s3://${Bucket}/code.zip"
    }


@pytest.mark.parametrize(
    ("parser", "source"),
    [
        (parse_serverless_source, ""),
        (parse_serverless_source, "service: example"),
        (parse_serverless_source, "{broken"),
        (parse_sam_template, "Resources: {}"),
        (parse_sam_template, "Transform: AWS::Serverless-2016-10-31\nResources: []"),
    ],
)
def test_parsers_reject_invalid_or_unrecognized_source(parser, source: str) -> None:
    with pytest.raises(ServerlessInputError):
        parser(source)


@pytest.mark.parametrize(
    ("command", "fixture", "adapter"),
    [
        ("serverless", "serverless_framework_risky.yml", "serverless"),
        ("sam", "sam_template_risky.yml", "sam"),
    ],
)
def test_serverless_clis_support_framework_checks(
    capsys, command: str, fixture: str, adapter: str
) -> None:
    assert main([command, "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == adapter
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
