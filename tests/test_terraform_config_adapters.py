from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.terraform_config import (
    TerraformConfigAdapter,
    TerraformConfigInputError,
    TerragruntAdapter,
    parse_terraform_config,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(ecosystem: str, fixture: str) -> dict[str, list[str]]:
    data = parse_terraform_config((FIXTURES / fixture).read_text(encoding="utf-8"), ecosystem)
    adapter = TerraformConfigAdapter() if ecosystem == "terraform-config" else TerragruntAdapter()
    result: dict[str, list[str]] = defaultdict(list)
    for change in adapter.analyze(data, tool_name=ecosystem):
        result[change.resource_type].append(change.risk)
    return result


def test_terraform_config_surfaces_supply_chain_execution_state_and_exposure() -> None:
    risks = _risks("terraform-config", "terraform_config_risky.tf")
    assert risks["terraform_config_terraform_settings"] == ["review"]
    assert risks["terraform_config_state_backend"] == ["review"]
    assert len(risks["terraform_config_provider_dependency"]) == 2
    assert risks["terraform_config_unpinned_dependency"] == ["dangerous"]
    assert risks["terraform_config_open_version_constraint"] == ["review"]
    assert risks["terraform_config_provider_configuration"] == ["review"]
    assert risks["terraform_config_insecure_provider"] == ["dangerous"]
    assert risks["terraform_config_module_source"] == ["dangerous"]
    assert risks["terraform_config_unpinned_module"] == ["dangerous"]
    assert len(risks["terraform_config_managed_resource"]) == 2
    assert risks["terraform_config_provisioner_execution"] == ["dangerous"]
    assert risks["terraform_config_remote_connection"] == ["dangerous"]
    assert risks["terraform_config_ignored_drift"] == ["dangerous"]
    assert len(risks["terraform_config_public_exposure"]) >= 1
    assert risks["terraform_config_disabled_encryption"] == ["dangerous"]
    assert risks["terraform_config_privileged_or_public"] == ["dangerous"]
    assert risks["terraform_config_data_source"] == ["dangerous"]
    assert risks["terraform_config_external_program"] == ["dangerous"]
    assert risks["terraform_config_state_removal"] == ["irreversible"]
    assert len(risks["terraform_config_sensitive_value"]) == 2
    assert len(risks["terraform_config_secret_material"]) >= 3


def test_terragrunt_surfaces_hooks_sources_state_dependencies_and_generation() -> None:
    risks = _risks("terragrunt", "terragrunt_risky.hcl")
    assert risks["terragrunt_terraform_orchestration"] == ["review"]
    assert risks["terragrunt_module_source"] == ["dangerous"]
    assert risks["terragrunt_unpinned_module"] == ["dangerous"]
    assert len(risks["terragrunt_hook_execution"]) == 3
    assert risks["terragrunt_error_path_execution"] == ["dangerous"]
    assert risks["terragrunt_cli_arguments"] == ["review"]
    assert risks["terragrunt_unsafe_cli_arguments"] == ["dangerous"]
    assert risks["terragrunt_state_backend"] == ["review"]
    assert risks["terragrunt_generated_backend"] == ["dangerous"]
    assert risks["terragrunt_state_encryption"] == ["review"]
    assert risks["terragrunt_configuration_include"] == ["review"]
    assert risks["terragrunt_exposed_include"] == ["review"]
    assert risks["terragrunt_dependency_outputs"] == ["review"]
    assert risks["terragrunt_mocked_dependency"] == ["dangerous"]
    assert risks["terragrunt_dependency_order"] == ["review"]
    assert risks["terragrunt_generated_configuration"] == ["dangerous"]
    assert risks["terragrunt_configuration_overwrite"] == ["dangerous"]
    assert risks["terragrunt_assumed_identity"] == ["dangerous", "dangerous"]
    assert risks["terragrunt_executable_override"] == ["dangerous"]
    assert risks["terragrunt_configuration_command"] == ["dangerous"]
    assert risks["terragrunt_secret_decryption"] == ["dangerous"]
    assert risks["terragrunt_dynamic_config_read"] == ["review"]
    assert len(risks["terragrunt_environment_input"]) >= 2
    assert len(risks["terragrunt_secret_material"]) >= 3


def test_json_variants_are_supported() -> None:
    terraform = parse_terraform_config(
        json.dumps(
            {
                "terraform": {
                    "required_version": ">= 1.5",
                    "backend": {"s3": {"bucket": "state"}},
                },
                "resource": {"aws_s3_bucket": {"logs": {}}},
            }
        ),
        "terraform-config",
    )
    terragrunt = parse_terraform_config(
        json.dumps({"terraform": {"source": "../module"}, "inputs": {"region": "us-east-1"}}),
        "terragrunt",
    )
    assert TerraformConfigAdapter().can_handle(terraform)
    assert TerragruntAdapter().can_handle(terragrunt)


def test_pinned_sources_do_not_emit_unpinned_findings() -> None:
    terraform = parse_terraform_config(
        'module "vpc" { source = "git::https://github.com/example/vpc.git?ref=v1.2.3" }',
        "terraform-config",
    )
    terragrunt = parse_terraform_config(
        'terraform { source = "tfr:///terraform-aws-modules/vpc/aws?version=5.0.0" }',
        "terragrunt",
    )
    tf_kinds = {c.resource_type for c in TerraformConfigAdapter().analyze(terraform)}
    tg_kinds = {c.resource_type for c in TerragruntAdapter().analyze(terragrunt)}
    assert "terraform_config_unpinned_module" not in tf_kinds
    assert "terragrunt_unpinned_module" not in tg_kinds


@pytest.mark.parametrize(
    ("ecosystem", "source"),
    [
        ("terraform-config", ""),
        ("terraform-config", 'terraform { source = "../module" }'),
        ("terragrunt", 'resource "null_resource" "x" {}'),
        ("terragrunt", 'terraform { required_version = ">= 1.5" }'),
        ("unknown", "foo = true"),
    ],
)
def test_parser_rejects_wrong_or_unrecognized_inputs(ecosystem: str, source: str) -> None:
    with pytest.raises(TerraformConfigInputError):
        parse_terraform_config(source, ecosystem)


@pytest.mark.parametrize(
    ("ecosystem", "fixture"),
    [
        ("terraform-config", "terraform_config_risky.tf"),
        ("terragrunt", "terragrunt_risky.hcl"),
    ],
)
def test_cli_supports_framework_checks(capsys, ecosystem: str, fixture: str) -> None:
    assert main([ecosystem, "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == ecosystem
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
