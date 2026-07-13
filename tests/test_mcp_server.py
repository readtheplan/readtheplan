from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from readtheplan.cli import _build_parser, main
from readtheplan.mcp_server import (
    MCPToolInputError,
    MissingMCPDependencyError,
    _validate_path,
    _working_root,
    agent_gate,
    agent_gate_atlantis,
    agent_gate_azure,
    agent_gate_bicep,
    agent_gate_caddy,
    agent_gate_carvel,
    agent_gate_cdk,
    agent_gate_cfengine,
    agent_gate_cloud_init,
    agent_gate_cloudformation,
    agent_gate_configuration_management,
    agent_gate_consul,
    agent_gate_crossplane,
    agent_gate_cue,
    agent_gate_devspace,
    agent_gate_docker_bake,
    agent_gate_dockerfile,
    agent_gate_dsc,
    agent_gate_envoy,
    agent_gate_grafana,
    agent_gate_helm,
    agent_gate_helmfile,
    agent_gate_jsonnet,
    agent_gate_kubernetes,
    agent_gate_kustomize,
    agent_gate_loki,
    agent_gate_monitoring,
    agent_gate_nix,
    agent_gate_opa,
    agent_gate_otel_collector,
    agent_gate_packer,
    agent_gate_pipeline,
    agent_gate_project,
    agent_gate_proxy_config,
    agent_gate_pulumi,
    agent_gate_pulumi_project,
    agent_gate_salt,
    agent_gate_sam,
    agent_gate_sentinel,
    agent_gate_serverless,
    agent_gate_skaffold,
    agent_gate_sops,
    agent_gate_spacelift,
    agent_gate_systemd,
    agent_gate_terraform_config,
    agent_gate_terraform_lock,
    agent_gate_terraform_state,
    agent_gate_terragrunt,
    agent_gate_terramate,
    agent_gate_tilt,
    agent_gate_traefik,
    agent_gate_vagrant,
    agent_gate_vault,
    agent_gate_workload,
    analyze_plan,
    create_server,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ── existing tests (preserved) ────────────────────────────────────────


def test_analyze_plan_matches_cli_json(capsys) -> None:
    plan = FIXTURES / "valid_plan.json"
    exit_code = main(["analyze", "--format", "json", str(plan)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert analyze_plan(str(plan)) == json.loads(captured.out)


def test_agent_gate_opa_supports_framework_checks() -> None:
    result = agent_gate_opa(str(FIXTURES / "opa_policy_risky.rego"), "soc2")
    assert result["adapter"] == "opa"
    assert result["artifact_type"] == "rego"
    assert result["decision"] == "block"


def test_agent_gate_sentinel_supports_framework_checks() -> None:
    result = agent_gate_sentinel(str(FIXTURES / "sentinel_policy_risky.sentinel"), "soc2")
    assert result["adapter"] == "sentinel"
    assert result["artifact_type"] == "policy"
    assert result["decision"] == "block"


def test_agent_gate_sops_supports_framework_checks_and_redacts_plaintext() -> None:
    result = agent_gate_sops(str(FIXTURES / "secret.sops.yaml"), "soc2")
    assert result["adapter"] == "sops"
    assert result["decision"] == "block"
    assert "literal-token-must-not-leak" not in json.dumps(result)


def test_agent_gate_matches_cli_json(capsys) -> None:
    plan = FIXTURES / "valid_plan.json"
    exit_code = main(["agent-gate", str(plan)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert agent_gate(str(plan)) == json.loads(captured.out)


def test_agent_gate_pulumi_supports_framework_checks() -> None:
    result = agent_gate_pulumi(str(FIXTURES / "pulumi_preview_mixed.json"), "soc2")
    assert result["adapter"] == "pulumi"
    assert result["decision"] == "block"
    assert any(str(check).startswith("rtp.control.soc2.") for check in result["required_checks"])


def test_agent_gate_pulumi_project_supports_framework_checks() -> None:
    result = agent_gate_pulumi_project(
        str(FIXTURES / "pulumi_project_risky.yaml"),
        "soc2",
    )
    assert result["adapter"] == "pulumi-project"
    assert result["artifact"] == "project"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_bicep_supports_source_and_framework_checks() -> None:
    result = agent_gate_bicep(str(FIXTURES / "bicep_source_risky.bicep"), "soc2")
    assert result["adapter"] == "bicep"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_pulumi_unknown_provider_gets_framework_baseline(
    tmp_path: Path,
) -> None:
    preview = tmp_path / "pulumi-gcp.json"
    preview.write_text(
        json.dumps(
            {
                "events": [
                    {
                        "sequence": 1,
                        "resourcePreEvent": {
                            "metadata": {
                                "op": "update",
                                "urn": "urn:pulumi:dev::app::gcp:storage/bucket:Bucket::assets",
                                "type": "gcp:storage/bucket:Bucket",
                                "old": {"inputs": {"location": "US"}},
                                "new": {"inputs": {"location": "EU"}},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = agent_gate_pulumi(str(preview), "soc2")

    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_cloudformation_and_kubernetes_mcp_tools_accept_frameworks(
    tmp_path: Path,
) -> None:
    cloudformation = agent_gate_cloudformation(str(FIXTURES / "cfn_change_set_mixed.json"), "soc2")
    cdk = agent_gate_cdk(str(FIXTURES / "cdk_assembly_risky.json"), "soc2")
    manifest = tmp_path / "deployment.yaml"
    manifest.write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
        encoding="utf-8",
    )
    kubernetes = agent_gate_kubernetes(str(manifest), "soc2")

    assert "rtp.control.soc2.CC8.1" in cloudformation["required_checks"]
    assert "rtp.control.soc2.CC8.1" in cdk["required_checks"]
    assert "rtp.control.soc2.CC8.1" in kubernetes["required_checks"]


def test_kubernetes_mcp_applies_flux_gitops_rules() -> None:
    result = agent_gate_kubernetes(str(FIXTURES / "flux_gitops_risky.yml"), "soc2")
    assert result["adapter"] == "kubernetes"
    assert result["decision"] == "block"
    assert result["risk_counts"] == {
        "safe": 0,
        "review": 0,
        "dangerous": 5,
        "irreversible": 0,
    }
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_pulumi_rejects_invalid_preview(tmp_path: Path) -> None:
    invalid = tmp_path / "preview.json"
    invalid.write_text("not-json", encoding="utf-8")
    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_pulumi(str(invalid))
    assert exc_info.value.code == "INVALID_JSON"


def test_agent_gate_pipeline_supports_framework_checks() -> None:
    result = agent_gate_pipeline(
        str(FIXTURES / "github_actions_deploy.yml"),
        "github-actions",
        "soc2",
    )

    assert result["adapter"] == "github-actions"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_pipeline_supports_azure_pipelines() -> None:
    result = agent_gate_pipeline(
        str(FIXTURES / "azure_pipelines_deploy.yml"),
        "azure-pipelines",
        "soc2",
    )
    assert result["adapter"] == "azure-pipelines"
    assert result["decision"] == "block"
    assert result["total_changes"] == 21
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_pipeline_supports_bitbucket_pipelines() -> None:
    result = agent_gate_pipeline(
        str(FIXTURES / "bitbucket_pipelines_deploy.yml"),
        "bitbucket-pipelines",
        "soc2",
    )
    assert result["adapter"] == "bitbucket-pipelines"
    assert result["decision"] == "block"
    assert result["total_changes"] == 27
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_pipeline_supports_buildkite() -> None:
    result = agent_gate_pipeline(
        str(FIXTURES / "buildkite_deploy.yml"),
        "buildkite",
        "soc2",
    )
    assert result["adapter"] == "buildkite"
    assert result["decision"] == "block"
    assert result["total_changes"] == 18
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


@pytest.mark.parametrize(
    ("fixture", "total"),
    [("atlantis_risky.yaml", 18), ("atlantis_server_risky.yaml", 11)],
)
def test_agent_gate_atlantis_supports_repo_and_server_config(fixture: str, total: int) -> None:
    result = agent_gate_atlantis(str(FIXTURES / fixture), "soc2")
    assert result["adapter"] == "atlantis"
    assert result["decision"] == "block"
    assert result["total_changes"] == total
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


@pytest.mark.parametrize(
    ("fixture", "total", "decision"),
    [("envoy_risky.yaml", 20, "block"), ("envoy_config_dump.json", 4, "warn")],
)
def test_agent_gate_envoy_supports_bootstrap_and_config_dump(
    fixture: str, total: int, decision: str
) -> None:
    result = agent_gate_envoy(str(FIXTURES / fixture), "soc2")
    assert result["adapter"] == "envoy"
    assert result["decision"] == decision
    assert result["total_changes"] == total
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


@pytest.mark.parametrize(
    ("ecosystem", "fixture", "total"),
    [
        ("prometheus", "prometheus_risky.yml", 16),
        ("alertmanager", "alertmanager_risky.yml", 17),
    ],
)
def test_agent_gate_monitoring_supports_both_ecosystems(
    ecosystem: str, fixture: str, total: int
) -> None:
    result = agent_gate_monitoring(str(FIXTURES / fixture), ecosystem, "soc2")
    assert result["adapter"] == ecosystem
    assert result["decision"] == "block"
    assert result["total_changes"] == total
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_otel_collector_supports_framework_checks() -> None:
    result = agent_gate_otel_collector(str(FIXTURES / "otel_collector_risky.yml"), "soc2")
    assert result["adapter"] == "otel-collector"
    assert result["decision"] == "block"
    assert result["total_changes"] == 26
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_traefik_supports_yaml_and_toml() -> None:
    risky = agent_gate_traefik(str(FIXTURES / "traefik_risky.yml"), "soc2")
    static = agent_gate_traefik(str(FIXTURES / "traefik_static.toml"), "soc2")
    assert risky["adapter"] == "traefik"
    assert risky["decision"] == "block"
    assert risky["total_changes"] == 23
    assert static["adapter"] == "traefik"
    assert "rtp.control.soc2.CC8.1" in risky["required_checks"]


@pytest.mark.parametrize("fixture", ["grafana_risky.ini", "grafana_provisioning_risky.yml"])
def test_agent_gate_grafana_supports_ini_and_provisioning(fixture: str) -> None:
    result = agent_gate_grafana(str(FIXTURES / fixture), "soc2")
    assert result["adapter"] == "grafana"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


@pytest.mark.parametrize(
    ("handler", "fixture", "adapter"),
    [
        (agent_gate_vault, "vault_risky.hcl", "vault"),
        (agent_gate_consul, "consul_risky.hcl", "consul"),
    ],
)
def test_agent_gate_hashicorp_supports_vault_and_consul(
    handler, fixture: str, adapter: str
) -> None:
    result = handler(str(FIXTURES / fixture), "soc2")
    assert result["adapter"] == adapter
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_loki_supports_framework_checks() -> None:
    result = agent_gate_loki(str(FIXTURES / "loki_risky.yml"), "soc2")
    assert result["adapter"] == "loki"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


@pytest.mark.parametrize("fixture", ["Caddyfile.risky", "caddy_risky.json"])
def test_agent_gate_caddy_supports_caddyfile_and_json(fixture: str) -> None:
    result = agent_gate_caddy(str(FIXTURES / fixture), "soc2")
    assert result["adapter"] == "caddy"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


@pytest.mark.parametrize(
    ("handler", "fixture", "adapter"),
    [
        (agent_gate_terraform_config, "terraform_config_risky.tf", "terraform-config"),
        (agent_gate_terragrunt, "terragrunt_risky.hcl", "terragrunt"),
    ],
)
def test_agent_gate_terraform_source_supports_config_and_terragrunt(
    handler, fixture: str, adapter: str
) -> None:
    result = handler(str(FIXTURES / fixture), "soc2")
    assert result["adapter"] == adapter
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


@pytest.mark.parametrize(
    ("handler", "fixture", "adapter"),
    [
        (agent_gate_helm, "helm_template_risky.yaml", "helm"),
        (agent_gate_kustomize, "kustomization_risky.yml", "kustomize"),
        (agent_gate_crossplane, "crossplane_risky.yml", "crossplane"),
        (agent_gate_serverless, "serverless_framework_risky.yml", "serverless"),
        (agent_gate_sam, "sam_template_risky.yml", "sam"),
    ],
)
def test_agent_gate_cloud_native_source(handler, fixture: str, adapter: str) -> None:
    result = handler(str(FIXTURES / fixture), "soc2")
    assert result["adapter"] == adapter
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_pipeline_rejects_unknown_ecosystem() -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_pipeline("pipeline.yml", "unknown")

    assert exc_info.value.code == "INVALID_INPUT"


@pytest.mark.parametrize(
    ("ecosystem", "fixture"),
    [
        ("travis-ci", "travis_ci_risky.yml"),
        ("drone-ci", "drone_ci_risky.yml"),
        ("woodpecker-ci", "woodpecker_ci_risky.yml"),
        ("concourse", "concourse_risky.yml"),
        ("bamboo", "bamboo_risky.yml"),
        ("codebuild", "codebuild_risky.yml"),
        ("cloud-build", "google_cloud_build_risky.yml"),
        ("codepipeline", "codepipeline_risky.json"),
    ],
)
def test_agent_gate_pipeline_supports_additional_ci_ecosystems(
    ecosystem: str, fixture: str
) -> None:
    result = agent_gate_pipeline(str(FIXTURES / fixture), ecosystem, "soc2")
    assert result["adapter"] == ecosystem
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


@pytest.mark.parametrize(
    ("ecosystem", "fixture", "adapter"),
    [
        ("docker-compose", "docker_compose_risky.yml", "docker-compose"),
        ("nomad", "nomad_plan_risky.json", "nomad"),
        ("nomad", "nomad_job_risky.nomad.hcl", "nomad"),
    ],
)
def test_agent_gate_workload_supports_framework_checks(
    ecosystem: str,
    fixture: str,
    adapter: str,
) -> None:
    result = agent_gate_workload(str(FIXTURES / fixture), ecosystem, "soc2")
    assert result["adapter"] == adapter
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_workload_rejects_unknown_ecosystem() -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_workload("workload.yml", "unknown")
    assert exc_info.value.code == "INVALID_INPUT"


def test_agent_gate_packer_supports_framework_checks() -> None:
    result = agent_gate_packer(str(FIXTURES / "packer_inspect_risky.txt"), "soc2")
    assert result["adapter"] == "packer"
    assert result["decision"] == "block"
    assert result["total_changes"] == 11
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_packer_supports_native_template() -> None:
    result = agent_gate_packer(str(FIXTURES / "packer_template_risky.pkr.hcl"), "soc2")
    assert result["adapter"] == "packer"
    assert result["artifact_type"] == "template"
    assert result["decision"] == "block"
    assert result["total_changes"] == 29


def test_agent_gate_skaffold_supports_framework_checks() -> None:
    result = agent_gate_skaffold(str(FIXTURES / "skaffold_risky.yaml"), "soc2")
    assert result["adapter"] == "skaffold"
    assert result["config_count"] == 2
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_devspace_supports_framework_checks() -> None:
    result = agent_gate_devspace(str(FIXTURES / "devspace_risky.yaml"), "soc2")
    assert result["adapter"] == "devspace"
    assert result["project_name"] == "platform"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_tilt_supports_framework_checks() -> None:
    result = agent_gate_tilt(str(FIXTURES / "Tiltfile.risky"), "soc2")
    assert result["adapter"] == "tilt"
    assert result["syntax_mode"] == "ast"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_cue_supports_framework_checks() -> None:
    result = agent_gate_cue(str(FIXTURES / "deploy_risky_tool.cue"), "soc2")
    assert result["adapter"] == "cue"
    assert result["artifact_type"] == "tool"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_jsonnet_supports_framework_checks() -> None:
    result = agent_gate_jsonnet(str(FIXTURES / "tanka_main_risky.jsonnet"), "soc2")
    assert result["adapter"] == "jsonnet"
    assert result["artifact_type"] == "source"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_helmfile_supports_framework_checks() -> None:
    result = agent_gate_helmfile(str(FIXTURES / "helmfile_risky.yaml.gotmpl"), "soc2")
    assert result["adapter"] == "helmfile"
    assert result["artifact_type"] == "state"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_terramate_supports_framework_checks() -> None:
    result = agent_gate_terramate(str(FIXTURES / "terramate_risky.tm.hcl"), "soc2")
    assert result["adapter"] == "terramate"
    assert result["artifact_type"] == "configuration"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_spacelift_supports_framework_checks() -> None:
    result = agent_gate_spacelift(str(FIXTURES / "spacelift_runtime_risky.yml"), "soc2")
    assert result["adapter"] == "spacelift"
    assert result["stack_count"] == 2
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_carvel_supports_framework_checks() -> None:
    result = agent_gate_carvel(str(FIXTURES / "vendir_risky.yml"), "soc2")
    assert result["adapter"] == "carvel"
    assert result["artifact_type"] == "vendir"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_salt_supports_framework_checks() -> None:
    result = agent_gate_salt(str(FIXTURES / "salt_states_risky.sls"), "soc2")
    assert result["adapter"] == "salt"
    assert result["decision"] == "block"
    assert result["total_changes"] == 6
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_nix_supports_framework_checks() -> None:
    result = agent_gate_nix(str(FIXTURES / "nixos_module_risky.nix"), "soc2")
    assert result["adapter"] == "nix"
    assert result["artifact_type"] == "module"
    assert result["decision"] == "block"
    assert result["total_changes"] == 33
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_dsc_supports_framework_checks() -> None:
    result = agent_gate_dsc(str(FIXTURES / "powershell_dsc_risky.ps1"), "soc2")
    assert result["adapter"] == "dsc"
    assert result["artifact_type"] == "powershell"
    assert result["decision"] == "block"
    assert result["total_changes"] == 18
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_cfengine_supports_framework_checks() -> None:
    result = agent_gate_cfengine(str(FIXTURES / "cfengine_policy_risky.cf"), "soc2")
    assert result["adapter"] == "cfengine"
    assert result["artifact_type"] == "policy"
    assert result["decision"] == "block"
    assert result["total_changes"] == 30
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_terraform_lock_supports_framework_checks() -> None:
    result = agent_gate_terraform_lock(
        str(FIXTURES / "terraform_lock_risky.hcl"),
        "soc2",
    )
    assert result["adapter"] == "terraform-lock"
    assert result["provider_count"] == 3
    assert result["decision"] == "block"
    assert result["total_changes"] == 14
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_terraform_state_supports_framework_checks() -> None:
    result = agent_gate_terraform_state(
        str(FIXTURES / "terraform_state_show_risky.json"),
        "soc2",
    )
    assert result["adapter"] == "terraform-state"
    assert result["artifact"] == "show-json"
    assert result["resource_count"] == 3
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_configuration_management_supports_salt_project() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "salt_master_project_risky.yaml"),
        "salt-project",
        "soc2",
    )
    assert result["adapter"] == "salt-project"
    assert result["artifact_type"] == "config"
    assert result["decision"] == "block"
    assert result["total_changes"] == 25
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_configuration_management_supports_ansible_inventory() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "ansible_inventory_plugin_risky.aws_ec2.yml"),
        "ansible-project",
        "soc2",
    )
    assert result["adapter"] == "ansible-project"
    assert result["artifact_type"] == "inventory_plugin"
    assert result["decision"] == "block"
    assert result["total_changes"] == 12
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_configuration_management_supports_execution_environments() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "ansible_execution_environment" / "execution-environment.yml"),
        "ansible-project",
        "soc2",
    )
    assert result["adapter"] == "ansible-project"
    assert result["artifact_type"] == "execution_environment"
    assert result["decision"] == "block"
    assert "fixture-registry-password-do-not-leak" not in json.dumps(result)
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_configuration_management_supports_puppet_runtime_config() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "puppet_conf_risky.conf"),
        "puppet-project",
        "soc2",
    )
    assert result["adapter"] == "puppet-project"
    assert result["artifact_type"] == "config"
    assert result["decision"] == "block"
    assert result["total_changes"] == 34
    assert "fixture-puppet-proxy-password-do-not-leak" not in json.dumps(result)
    assert "fixture-puppet-header-token-do-not-leak" not in json.dumps(result)
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_configuration_management_supports_bolt_inventory() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "bolt_inventory" / "inventory.yaml"),
        "puppet-project",
        "soc2",
    )
    assert result["adapter"] == "puppet-project"
    assert result["artifact_type"] == "bolt_inventory"
    assert result["decision"] == "block"
    assert "fixture-ssh-password-do-not-leak" not in json.dumps(result)


def test_agent_gate_configuration_management_supports_r10k_configuration() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "puppet_r10k_risky" / "r10k.yaml"),
        "puppet-project",
        "soc2",
    )
    encoded = json.dumps(result)

    assert result["adapter"] == "puppet-project"
    assert result["artifact_type"] == "r10k"
    assert result["source_count"] == 2
    assert result["decision"] == "block"
    assert result["total_changes"] == 40
    assert "fixture-proxy-password" not in encoded
    assert "fixture-forge-token-do-not-leak" not in encoded
    assert "fixture-private-key-do-not-leak" not in json.dumps(result)
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_configuration_management_supports_jenkins_plugin_catalog() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "jenkins_plugins_risky.txt"),
        "jenkins-project",
        "soc2",
    )
    encoded = json.dumps(result)
    assert result["adapter"] == "jenkins-project"
    assert result["artifact_type"] == "plugins_txt"
    assert result["plugin_count"] == 7
    assert result["decision"] == "block"
    assert result["total_changes"] == 8
    assert "fixture-user" not in encoded
    assert "fixture-password" not in encoded


def test_agent_gate_configuration_management_supports_jenkins_job_builder() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "jenkins_job_builder_risky" / "jenkins-jobs.yaml"),
        "jenkins-project",
        "soc2",
    )
    encoded = json.dumps(result)

    assert result["adapter"] == "jenkins-project"
    assert result["artifact_type"] == "job_builder_yaml"
    assert result["definition_count"] == 3
    assert result["job_count"] == 1
    assert result["decision"] == "block"
    assert result["total_changes"] == 13
    assert "fixture-password" not in encoded
    assert "fixture-parameter-secret-do-not-leak" not in encoded
    assert "plugins.example.invalid" not in encoded
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_configuration_management_supports_chef_runtime_config() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "chef_runtime" / "client.rb"),
        "chef-project",
        "soc2",
    )
    encoded = json.dumps(result)
    assert result["adapter"] == "chef-project"
    assert result["artifact_type"] == "client_config"
    assert result["setting_count"] == 16
    assert result["decision"] == "block"
    assert result["total_changes"] == 18
    assert "fixture-chef" not in encoded
    assert "example.invalid" not in encoded
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_configuration_management_supports_berksfile_lock() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "chef_berkshelf_risky" / "Berksfile.lock"),
        "chef-project",
        "soc2",
    )
    encoded = json.dumps(result)
    assert result["adapter"] == "chef-project"
    assert result["artifact_type"] == "berks_lock"
    assert result["dependency_count"] == 5
    assert result["decision"] == "block"
    assert "fixture-user" not in encoded
    assert "fixture-password" not in encoded
    assert "example.invalid" not in encoded
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_configuration_management_supports_dsc() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "powershell_dsc_risky.ps1"),
        "dsc",
        "soc2",
    )
    assert result["adapter"] == "dsc"
    assert result["artifact_type"] == "powershell"
    assert result["decision"] == "block"


def test_agent_gate_configuration_management_supports_cfengine() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "cfengine_augments_risky.json"),
        "cfengine",
        "soc2",
    )
    assert result["adapter"] == "cfengine"
    assert result["artifact_type"] == "augments"
    assert result["decision"] == "block"


def test_agent_gate_configuration_management_supports_teamcity() -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / "teamcity_risky.kts"),
        "teamcity",
        "soc2",
    )
    assert result["adapter"] == "teamcity"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_configuration_management_rejects_unknown_ecosystem() -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_configuration_management("source.yml", "unknown")
    assert exc_info.value.code == "INVALID_INPUT"


def test_agent_gate_vagrant_supports_framework_checks() -> None:
    result = agent_gate_vagrant(str(FIXTURES / "Vagrantfile.risky"), "soc2")
    assert result["adapter"] == "vagrant"
    assert result["decision"] == "block"
    assert result["total_changes"] == 17
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_cloud_init_supports_framework_checks() -> None:
    result = agent_gate_cloud_init(str(FIXTURES / "cloud_init_risky.yml"), "soc2")
    assert result["adapter"] == "cloud-init"
    assert result["decision"] == "block"
    assert result["total_changes"] == 20
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_systemd_supports_framework_checks() -> None:
    result = agent_gate_systemd(str(FIXTURES / "systemd_risky.service"), "soc2")
    assert result["adapter"] == "systemd"
    assert result["decision"] == "block"
    assert result["total_changes"] == 30
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


@pytest.mark.parametrize(
    ("ecosystem", "fixture"),
    [("nginx", "nginx_risky.conf"), ("haproxy", "haproxy_risky.cfg")],
)
def test_agent_gate_proxy_config_supports_framework_checks(ecosystem: str, fixture: str) -> None:
    result = agent_gate_proxy_config(str(FIXTURES / fixture), ecosystem, "soc2")
    assert result["adapter"] == ecosystem
    assert result["decision"] == "block"
    assert result["total_changes"] == 19
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_dockerfile_supports_framework_checks() -> None:
    result = agent_gate_dockerfile(str(FIXTURES / "Dockerfile.risky"), "soc2")
    assert result["adapter"] == "dockerfile"
    assert result["decision"] == "block"
    assert result["total_changes"] == 20
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_docker_bake_supports_framework_checks_and_redacts_values() -> None:
    result = agent_gate_docker_bake(
        str(FIXTURES / "docker-bake.risky.hcl"), "soc2"
    )
    assert result["adapter"] == "docker-bake"
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]
    assert "literal-build-token-must-not-leak" not in json.dumps(result)


@pytest.mark.parametrize(
    ("plan_path", "expected"),
    [
        ("", "INVALID_INPUT"),
        ("missing.json", "PLAN_ERROR"),
    ],
)
def test_analyze_plan_rejects_missing_or_invalid_inputs(
    plan_path: str,
    expected: str,
) -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(plan_path)

    assert exc_info.value.code == expected
    assert exc_info.value.to_dict()["code"] == expected


def test_analyze_plan_rejects_invalid_json() -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(str(FIXTURES / "invalid_plan.json"))

    assert exc_info.value.code == "PLAN_ERROR"
    assert "invalid JSON" in exc_info.value.message


def test_analyze_plan_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(str(tmp_path))

    assert exc_info.value.code == "PLAN_ERROR"
    assert "directory" in exc_info.value.message


def test_analyze_plan_rejects_unsupported_plan_shape(tmp_path: Path) -> None:
    plan = tmp_path / "unsupported.json"
    plan.write_text(json.dumps({"resource_changes": {}}), encoding="utf-8")

    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(str(plan))

    assert exc_info.value.code == "PLAN_ERROR"
    assert "resource_changes" in exc_info.value.message


def test_create_server_registers_analyze_plan_tool(monkeypatch) -> None:
    registered: dict[str, object] = {}

    class FakeFastMCP:
        def __init__(self, name: str) -> None:
            self.name = name

        def tool(self, *, name: str):
            def decorator(func):
                registered[name] = func
                return func

            return decorator

    monkeypatch.setattr("readtheplan.mcp_server._load_fastmcp", lambda: FakeFastMCP)

    server = create_server()

    assert isinstance(server, FakeFastMCP)
    assert server.name == "readtheplan"
    assert "analyze_plan" in registered
    assert "agent_gate" in registered


def test_cli_parser_has_mcp_subcommand() -> None:
    parser = _build_parser()
    args = parser.parse_args(["mcp"])

    assert isinstance(args, argparse.Namespace)
    assert args.command == "mcp"


def test_cli_mcp_subcommand_runs_mcp_main(monkeypatch, capsys) -> None:
    called = False

    def fake_main() -> None:
        nonlocal called
        called = True

    monkeypatch.setattr("readtheplan.mcp_server.main", fake_main)

    assert main(["mcp"]) == 0
    assert called
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_cli_mcp_subcommand_reports_missing_extra(monkeypatch, capsys) -> None:
    def fake_main() -> None:
        raise MissingMCPDependencyError(
            'MCP preview requires the optional dependency. Install it with: pip install "readtheplan[mcp]"'  # noqa: E501
        )

    monkeypatch.setattr("readtheplan.mcp_server.main", fake_main)

    assert main(["mcp"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "readtheplan[mcp]" in captured.err


# ── framework parameter ───────────────────────────────────────────────


def test_analyze_plan_with_framework_returns_controls() -> None:
    plan = FIXTURES / "soc2_plan.json"
    result = analyze_plan(str(plan), framework="soc2")

    assert "framework" in result
    assert result["framework"]["name"] == "soc2"
    assert "version" in result["framework"]
    assert "schema_version" in result["framework"]

    for change in result["changes"]:
        assert "controls" in change
        assert isinstance(change["controls"], list)
        for control in change["controls"]:
            assert "id" in control
            assert "title" in control
            assert "rationale" in control


def test_analyze_plan_framework_matches_cli(capsys) -> None:
    """Framework-enriched MCP output must match the CLI --framework JSON."""
    plan = FIXTURES / "soc2_plan.json"
    exit_code = main(["analyze", "--format", "json", "--framework", "soc2", str(plan)])
    captured = capsys.readouterr()

    assert exit_code == 0
    cli_result = json.loads(captured.out)
    mcp_result = analyze_plan(str(plan), framework="soc2")

    assert mcp_result == cli_result
    assert "framework" in mcp_result
    assert mcp_result["framework"]["name"] == "soc2"


def test_analyze_plan_rejects_unknown_framework() -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(str(FIXTURES / "valid_plan.json"), framework="nonexistent")

    assert exc_info.value.code == "FRAMEWORK_NOT_FOUND"
    assert "nonexistent" in exc_info.value.message


def test_analyze_plan_without_framework_has_no_controls() -> None:
    result = analyze_plan(str(FIXTURES / "valid_plan.json"))

    assert "framework" not in result
    for change in result["changes"]:
        assert "controls" not in change


def test_agent_gate_with_framework_adds_control_checks() -> None:
    result = agent_gate(str(FIXTURES / "soc2_plan.json"), framework="soc2")

    control_checks = [c for c in result["required_checks"] if c.startswith("rtp.control.soc2.")]
    assert len(control_checks) > 0


# ── path traversal protection ─────────────────────────────────────────


def test_working_root_returns_none_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("MCP_ROOT", raising=False)
    assert _working_root() is None


def test_working_root_returns_path_when_set(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    assert _working_root() == tmp_path.resolve()


def test_validate_path_allows_inside_root(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    allowed = tmp_path / "foo.json"
    allowed.write_text("{}")
    result = _validate_path(str(allowed))
    assert result == allowed.resolve()


def test_validate_path_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    outside = tmp_path.parent / "outside.json"

    with pytest.raises(MCPToolInputError) as exc_info:
        _validate_path(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"
    assert "outside the allowed working root" in exc_info.value.message


def test_validate_path_allows_path_when_mcp_root_unset(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("MCP_ROOT", raising=False)
    f = tmp_path / "any.json"
    f.write_text("{}")
    result = _validate_path(str(f))
    assert result == f.resolve()


def test_analyze_plan_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    """End-to-end: analyze_plan with MCP_ROOT set rejects traversal."""
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    outside = tmp_path.parent / "plan.json"
    # copy a valid plan fixture outside the root
    outside.write_text((FIXTURES / "valid_plan.json").read_text())

    with pytest.raises(MCPToolInputError) as exc_info:
        analyze_plan(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    """agent_gate also validates paths when MCP_ROOT is set."""
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    outside = tmp_path.parent / "plan.json"
    outside.write_text((FIXTURES / "valid_plan.json").read_text())

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_cloudformation_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    """CloudFormation MCP tool must enforce the same MCP_ROOT boundary."""
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    outside = tmp_path.parent / "cfn.json"
    outside.write_text((FIXTURES / "cfn_change_set_mixed.json").read_text())

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_cloudformation(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_project_scans_mixed_infrastructure_snapshot(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    project = root / "project"
    shutil.copytree(FIXTURES / "project_scan", project)
    monkeypatch.setenv("MCP_ROOT", str(root))

    result = agent_gate_project(str(project), framework="soc2")

    assert result["adapter"] == "project-scan"
    assert result["decision"] == "block"
    assert result["discovered_file_count"] == 4
    assert result["scanned_file_count"] == 4
    assert result["total_changes"] == 17
    assert {item["tool"] for item in result["files"]} == {
        "docker-compose",
        "jenkins",
        "spacelift",
        "terraform-config",
    }
    assert "project-scan-secret" not in json.dumps(result)
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_agent_gate_project_analyzes_only_isolated_snapshot_paths(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    project = root / "project"
    project.mkdir(parents=True)
    original = project / "Dockerfile"
    original.write_text("FROM scratch\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))
    analyzed_paths: list[Path] = []

    def fake_analyze(item, *, framework):
        analyzed_paths.append(item.path)
        return {
            "adapter": "dockerfile",
            "decision": "proceed",
            "risk": "safe",
            "risk_counts": {"safe": 1, "review": 0, "dangerous": 0, "irreversible": 0},
            "total_changes": 1,
            "required_checks": [],
            "reason": "Snapshot analyzed.",
        }

    monkeypatch.setattr("readtheplan.project_scan._analyze_input", fake_analyze)

    result = agent_gate_project(str(project))

    assert result["decision"] == "proceed"
    assert len(analyzed_paths) == 1
    assert analyzed_paths[0] != original
    assert not analyzed_paths[0].is_relative_to(root)
    assert not analyzed_paths[0].exists()


def test_agent_gate_project_honors_excludes_and_default_dependency_skips(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    project = root / "project"
    (project / "infra").mkdir(parents=True)
    (project / "infra" / "main.tf").write_text("resource {}\n", encoding="utf-8")
    (project / "generated").mkdir()
    (project / "generated" / "skip.tf").write_text("resource {}\n", encoding="utf-8")
    (project / "node_modules").mkdir()
    (project / "node_modules" / "skip.tf").write_text("resource {}\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    result = agent_gate_project(str(project), excludes=["generated/**"])

    assert result["discovered_file_count"] == 1
    assert result["files"][0]["path"] == "infra/main.tf"


def test_agent_gate_project_detects_content_sniffed_manifest(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    project = root / "project"
    project.mkdir(parents=True)
    manifest = project / "deployment.yaml"
    manifest.write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MCP_ROOT", str(root))

    result = agent_gate_project(str(project))

    assert result["discovered_file_count"] == 1
    assert result["files"][0]["tool"] == "kubernetes"


def test_agent_gate_project_reports_oversized_supported_input_without_reading_it(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    project = root / "project"
    project.mkdir(parents=True)
    (project / "Dockerfile").write_text(
        "FROM scratch\n# project-scan-large-secret\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MCP_ROOT", str(root))

    result = agent_gate_project(str(project), max_file_bytes=16)

    assert result["discovered_file_count"] == 1
    assert result["scanned_file_count"] == 0
    assert result["errors"] == [
        {"path": "Dockerfile", "tool": "dockerfile", "code": "file-too-large"}
    ]
    assert "project-scan-large-secret" not in json.dumps(result)


def test_agent_gate_project_rejects_path_outside_root(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_project(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_project_skips_static_symlink_outside_root(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    project = root / "project"
    project.mkdir(parents=True)
    outside = tmp_path / "outside.tf"
    outside.write_text("resource {}\n", encoding="utf-8")
    linked = project / "linked.tf"
    try:
        linked.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")
    monkeypatch.setenv("MCP_ROOT", str(root))

    result = agent_gate_project(str(project))

    assert result["discovered_file_count"] == 0


def test_agent_gate_project_rejects_validate_open_swap(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    project = root / "project"
    project.mkdir(parents=True)
    inside = project / "Dockerfile"
    inside.write_text("FROM scratch\n", encoding="utf-8")
    outside = tmp_path / "outside.Dockerfile"
    outside.write_text("FROM evil.example/image\n", encoding="utf-8")
    inside_path = str(inside.resolve())
    monkeypatch.setenv("MCP_ROOT", str(root))
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and os.fspath(path) == inside_path:
            inside.unlink()
            try:
                inside.symlink_to(outside)
            except OSError as exc:
                pytest.skip(f"file symlinks unavailable: {exc}")
            swapped = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("readtheplan.mcp_server.os.open", swapping_open)

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_project(str(project))

    assert swapped is True
    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_project_rejects_swap_to_different_target_inside_root(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    project = root / "project"
    project.mkdir(parents=True)
    inside = project / "Dockerfile"
    inside.write_text("FROM scratch\n", encoding="utf-8")
    sibling = project / "other.txt"
    sibling.write_text("FROM evil.example/image\n", encoding="utf-8")
    inside_path = str(inside.resolve())
    monkeypatch.setenv("MCP_ROOT", str(root))
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and os.fspath(path) == inside_path:
            inside.unlink()
            try:
                inside.symlink_to(sibling)
            except OSError as exc:
                pytest.skip(f"file symlinks unavailable: {exc}")
            swapped = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("readtheplan.mcp_server.os.open", swapping_open)

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_project(str(project))

    assert swapped is True
    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_project_revalidates_every_walked_directory(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    project = root / "project"
    project.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    def escaped_walk(*args, **kwargs):
        yield str(outside), [], ["Dockerfile"]

    monkeypatch.setattr("readtheplan.mcp_server.os.walk", escaped_walk)

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_project(str(project))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_project_fails_closed_on_supported_file_limit(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    project = root / "project"
    project.mkdir(parents=True)
    (project / "a.tf").write_text("resource {}\n", encoding="utf-8")
    (project / "b.tf").write_text("resource {}\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_project(str(project), max_files=1)

    assert exc_info.value.code == "LIMIT_EXCEEDED"


def test_agent_gate_project_fails_closed_on_candidate_limit(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    project = root / "project"
    project.mkdir(parents=True)
    (project / "a.txt").write_text("a\n", encoding="utf-8")
    (project / "b.txt").write_text("b\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))
    monkeypatch.setattr("readtheplan.mcp_server._MCP_PROJECT_SCAN_MAX_CANDIDATES", 1)

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_project(str(project))

    assert exc_info.value.code == "LIMIT_EXCEEDED"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"project_path": ""},
        {"project_path": ".", "excludes": [""]},
        {"project_path": ".", "max_files": 0},
        {"project_path": ".", "max_files": 5001},
        {"project_path": ".", "max_file_bytes": 0},
        {"project_path": ".", "max_file_bytes": 100 * 1024 * 1024 + 1},
    ],
)
def test_agent_gate_project_rejects_invalid_limits_and_patterns(kwargs) -> None:
    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_project(**kwargs)

    assert exc_info.value.code == "INVALID_INPUT"


@pytest.mark.parametrize(
    ("handler", "fixture_name", "result_key", "expected_value"),
    [
        (analyze_plan, "valid_plan.json", "resource_change_count", 3),
        (agent_gate, "valid_plan.json", "schema", "rtp-agent-gate-v1"),
        (
            agent_gate_cloudformation,
            "cfn_change_set_mixed.json",
            "adapter",
            "cloudformation",
        ),
        (agent_gate_azure, "azure_whatif_mixed.json", "adapter", "azure"),
        (agent_gate_pulumi, "pulumi_preview_mixed.json", "adapter", "pulumi"),
        (
            agent_gate_pulumi_project,
            "pulumi_project_risky.yaml",
            "adapter",
            "pulumi-project",
        ),
        (agent_gate_helm, "helm_template_risky.yaml", "adapter", "helm"),
        (agent_gate_kustomize, "kustomization_risky.yml", "adapter", "kustomize"),
        (agent_gate_crossplane, "crossplane_risky.yml", "adapter", "crossplane"),
        (agent_gate_serverless, "serverless_framework_risky.yml", "adapter", "serverless"),
        (agent_gate_sam, "sam_template_risky.yml", "adapter", "sam"),
    ],
)
def test_non_kubernetes_handlers_use_confined_read_boundary(
    monkeypatch,
    tmp_path,
    handler,
    fixture_name,
    result_key,
    expected_value,
) -> None:
    """Each file-backed MCP handler consumes bytes from the confined reader."""
    root = tmp_path / "root"
    root.mkdir()
    input_file = root / "input.json"
    input_file.write_text("not valid JSON", encoding="utf-8")
    fixture_bytes = (FIXTURES / fixture_name).read_bytes()
    calls: list[str] = []
    monkeypatch.setenv("MCP_ROOT", str(root))

    def fake_read_confined_bytes(path: str) -> bytes:
        calls.append(path)
        return fixture_bytes

    monkeypatch.setattr(
        "readtheplan.mcp_server._read_confined_bytes",
        fake_read_confined_bytes,
    )

    result = handler(str(input_file))

    assert calls == [str(input_file.resolve())]
    assert result[result_key] == expected_value


@pytest.mark.parametrize(
    ("handler", "fixture_name", "result_key", "expected_value"),
    [
        (analyze_plan, "valid_plan.json", "resource_change_count", 3),
        (agent_gate, "valid_plan.json", "schema", "rtp-agent-gate-v1"),
        (
            agent_gate_cloudformation,
            "cfn_change_set_mixed.json",
            "adapter",
            "cloudformation",
        ),
        (agent_gate_azure, "azure_whatif_mixed.json", "adapter", "azure"),
        (agent_gate_pulumi, "pulumi_preview_mixed.json", "adapter", "pulumi"),
        (
            agent_gate_pulumi_project,
            "pulumi_project_risky.yaml",
            "adapter",
            "pulumi-project",
        ),
        (agent_gate_helm, "helm_template_risky.yaml", "adapter", "helm"),
        (agent_gate_kustomize, "kustomization_risky.yml", "adapter", "kustomize"),
        (agent_gate_crossplane, "crossplane_risky.yml", "adapter", "crossplane"),
        (agent_gate_serverless, "serverless_framework_risky.yml", "adapter", "serverless"),
        (agent_gate_sam, "sam_template_risky.yml", "adapter", "sam"),
    ],
)
def test_non_kubernetes_handlers_allow_path_inside_root(
    monkeypatch,
    tmp_path,
    handler,
    fixture_name,
    result_key,
    expected_value,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    input_file = root / "input.json"
    input_file.write_bytes((FIXTURES / fixture_name).read_bytes())
    monkeypatch.setenv("MCP_ROOT", str(root))

    result = handler(str(input_file))

    assert result[result_key] == expected_value


@pytest.mark.parametrize(
    ("handler", "fixture_name"),
    [
        (analyze_plan, "valid_plan.json"),
        (agent_gate, "valid_plan.json"),
        (agent_gate_cloudformation, "cfn_change_set_mixed.json"),
        (agent_gate_azure, "azure_whatif_mixed.json"),
        (agent_gate_pulumi, "pulumi_preview_mixed.json"),
        (agent_gate_pulumi_project, "pulumi_project_risky.yaml"),
        (agent_gate_helm, "helm_template_risky.yaml"),
        (agent_gate_kustomize, "kustomization_risky.yml"),
        (agent_gate_crossplane, "crossplane_risky.yml"),
        (agent_gate_serverless, "serverless_framework_risky.yml"),
        (agent_gate_sam, "sam_template_risky.yml"),
    ],
)
def test_non_kubernetes_handlers_reject_validate_open_swap(
    monkeypatch,
    tmp_path,
    handler,
    fixture_name,
) -> None:
    """Swapping an authorized input cannot redirect any sibling handler."""
    root = tmp_path / "root"
    root.mkdir()
    fixture_bytes = (FIXTURES / fixture_name).read_bytes()
    inside = root / "input.json"
    inside.write_bytes(fixture_bytes)
    outside = tmp_path / "outside.json"
    outside.write_bytes(fixture_bytes)
    inside_path = str(inside.resolve())
    monkeypatch.setenv("MCP_ROOT", str(root))

    real_open = os.open
    swapped = False

    def swapping_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and os.fspath(path) == inside_path:
            inside.unlink()
            try:
                inside.symlink_to(outside)
            except OSError as exc:
                pytest.skip(f"file symlinks unavailable: {exc}")
            swapped = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("readtheplan.mcp_server.os.open", swapping_open)

    with pytest.raises(MCPToolInputError) as exc_info:
        handler(str(inside))

    assert swapped is True
    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_kubernetes_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    """Kubernetes inputs are confined to MCP_ROOT like the other MCP tools."""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "k8s.json"
    outside.write_text(json.dumps({"resources": []}), encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_kubernetes(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_pipeline_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "workflow.yml"
    outside.write_text("permissions: {}\njobs: {}\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_pipeline(str(outside), "github-actions")

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_workload_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "compose.yml"
    outside.write_text("services:\n  api:\n    image: api:latest\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_workload(str(outside), "docker-compose")

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_packer_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "packer.txt"
    outside.write_text("Packer Inspect: HCL2 mode\n> builds:\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_packer(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_skaffold_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "skaffold.yaml"
    outside.write_text("apiVersion: skaffold/v4beta13\nkind: Config\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_skaffold(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_devspace_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "devspace.yaml"
    outside.write_text("version: v2beta1\nname: example\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_devspace(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_tilt_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "Tiltfile"
    outside.write_text("docker_build('api', '.')\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_tilt(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_cue_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "config.cue"
    outside.write_text("package example\nvalue: true\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_cue(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_jsonnet_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "main.jsonnet"
    outside.write_text("{ apiVersion: 'v1', kind: 'ConfigMap' }", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))
    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_jsonnet(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_helmfile_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "helmfile.yaml"
    outside.write_text("releases: []\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))
    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_helmfile(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_terramate_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "stack.tm.hcl"
    outside.write_text('stack { name = "app" }\n', encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))
    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_terramate(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_carvel_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "vendir.yml"
    outside.write_text(
        "apiVersion: vendir.k14s.io/v1alpha1\nkind: Config\ndirectories: []\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MCP_ROOT", str(root))
    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_carvel(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_spacelift_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "config.yml"
    outside.write_text('version: "2"\nstacks: {}\n', encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))
    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_spacelift(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_salt_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "state.sls"
    outside.write_text("example:\n  pkg.installed: []\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_salt(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_nix_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "configuration.nix"
    outside.write_text("{ ... }: { services.openssh.enable = true; }\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_nix(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_dsc_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "configuration.ps1"
    outside.write_text("Configuration Example { Node localhost {} }\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_dsc(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_cfengine_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "promises.cf"
    outside.write_text('bundle agent main { reports: "hello"; }\n', encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_cfengine(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_opa_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "policy.rego"
    outside.write_text("package example\ndefault allow := false\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_opa(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_sentinel_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "policy.sentinel"
    outside.write_text("main = rule { false }\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_sentinel(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_sops_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "secret.sops.yaml"
    outside.write_text(
        "value: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops: {}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_sops(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_terraform_lock_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / ".terraform.lock.hcl"
    outside.write_text(
        'provider "registry.terraform.io/hashicorp/aws" { version="1.0.0" hashes=[] }\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_terraform_lock(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_terraform_state_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "state.json"
    outside.write_bytes((FIXTURES / "terraform_state_show_review.json").read_bytes())
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_terraform_state(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_vagrant_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "Vagrantfile"
    outside.write_text('Vagrant.configure("2") do |config|\nend\n', encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_vagrant(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_cloud_init_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "user-data.yml"
    outside.write_text("#cloud-config\npackages: [curl]\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_cloud_init(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_systemd_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "example.service"
    outside.write_text("[Service]\nExecStart=/usr/bin/true\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_systemd(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_proxy_config_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "nginx.conf"
    outside.write_text("events {}\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_proxy_config(str(outside), "nginx")

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_dockerfile_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "Dockerfile"
    outside.write_text("FROM scratch\n", encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_dockerfile(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_docker_bake_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "docker-bake.hcl"
    outside.write_text('target "default" { context = "." }\n', encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_docker_bake(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_kubernetes_allows_path_inside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    manifest = root / "k8s.json"
    manifest.write_text(json.dumps({"resources": []}), encoding="utf-8")
    monkeypatch.setenv("MCP_ROOT", str(root))

    result = agent_gate_kubernetes(str(manifest))

    assert result["adapter"] == "kubernetes"


def test_agent_gate_kubernetes_rejects_symlink_outside_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "k8s.json"
    outside.write_text(json.dumps({"resources": []}), encoding="utf-8")
    linked = root / "linked.json"
    try:
        linked.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_kubernetes(str(linked))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_kubernetes_rejects_validate_open_swap(monkeypatch, tmp_path) -> None:
    """Swapping an authorized file to an outside symlink cannot win a TOCTOU race."""
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "k8s.json"
    inside.write_text(json.dumps({"resources": []}), encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"resources": []}), encoding="utf-8")
    inside_path = str(inside.resolve())
    monkeypatch.setenv("MCP_ROOT", str(root))

    real_open = os.open
    swapped = False

    def swapping_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and os.fspath(path) == inside_path:
            inside.unlink()
            try:
                inside.symlink_to(outside)
            except OSError as exc:
                pytest.skip(f"file symlinks unavailable: {exc}")
            swapped = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("readtheplan.mcp_server.os.open", swapping_open)

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_kubernetes(str(inside))

    assert swapped is True
    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_analyze_plan_allows_path_inside_root(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    plan = tmp_path / "plan.json"
    plan.write_text((FIXTURES / "valid_plan.json").read_text())

    result = analyze_plan(str(plan))
    assert result["resource_change_count"] == 3


# ── stdio integration test ────────────────────────────────────────────


def _importable(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ModuleNotFoundError:
        return False


def _cli_on_path() -> bool:
    import shutil

    return shutil.which("readtheplan") is not None


pytestmark_stdio = pytest.mark.skipif(
    not (_importable("mcp.server.fastmcp") and _cli_on_path()),
    reason="mcp optional dep or readtheplan CLI not on PATH (pip install -e .[mcp])",
)


def _send_jsonrpc(proc: subprocess.Popen, payload: dict) -> dict:
    """Write a single JSON-RPC line to the server and read the response."""
    line = json.dumps(payload) + "\n"
    proc.stdin.write(line.encode("utf-8"))  # type: ignore[union-attr]
    proc.stdin.flush()  # type: ignore[union-attr]

    # read lines until we get a non-empty response
    for _ in range(20):
        raw = proc.stdout.readline()  # type: ignore[union-attr]
        if not raw:
            raise RuntimeError("Server closed stdout unexpectedly")
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            continue

    raise RuntimeError("No valid JSON-RPC response received")


def _mcp_initialize(proc: subprocess.Popen) -> dict:
    """Perform the MCP initialize handshake."""
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1.0"},
        },
    }
    response = _send_jsonrpc(proc, init_req)
    assert "result" in response, f"Initialize failed: {response}"
    # send initialized notification
    notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    proc.stdin.write((json.dumps(notif) + "\n").encode("utf-8"))  # type: ignore[union-attr]
    proc.stdin.flush()  # type: ignore[union-attr]
    return response["result"]


@pytestmark_stdio
def test_stdio_server_tools_list() -> None:
    """Start the real MCP stdio server, list tools, and call analyze_plan."""
    plan = FIXTURES / "valid_plan.json"

    # start the server subprocess via the CLI entry point
    proc = subprocess.Popen(
        ["readtheplan", "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        env={
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "MCP_ROOT": str(FIXTURES.resolve()),
        },
    )

    try:
        # --- initialize ---
        _mcp_initialize(proc)

        # --- tools/list ---
        tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        tools_resp = _send_jsonrpc(proc, tools_req)
        assert "result" in tools_resp, f"tools/list failed: {tools_resp}"
        tools_by_name = {tool["name"]: tool for tool in tools_resp["result"]["tools"]}
        tool_names = set(tools_by_name)
        assert "analyze_plan" in tool_names
        assert "agent_gate_project" in tool_names
        assert "agent_gate" in tool_names
        assert "agent_gate_cloudformation" in tool_names
        assert "agent_gate_cdk" in tool_names
        assert "agent_gate_azure" in tool_names
        assert "agent_gate_bicep" in tool_names
        assert "agent_gate_kubernetes" in tool_names
        assert "agent_gate_pulumi" in tool_names
        assert "agent_gate_pulumi_project" in tool_names
        assert "agent_gate_pipeline" in tool_names
        assert "agent_gate_workload" in tool_names
        assert "agent_gate_packer" in tool_names
        assert "agent_gate_skaffold" in tool_names
        assert "agent_gate_devspace" in tool_names
        assert "agent_gate_tilt" in tool_names
        assert "agent_gate_cue" in tool_names
        assert "agent_gate_jsonnet" in tool_names
        assert "agent_gate_helmfile" in tool_names
        assert "agent_gate_terramate" in tool_names
        assert "agent_gate_spacelift" in tool_names
        assert "agent_gate_carvel" in tool_names
        assert "agent_gate_salt" in tool_names
        assert "agent_gate_nix" in tool_names
        assert "agent_gate_dsc" in tool_names
        assert "agent_gate_cfengine" in tool_names
        assert "agent_gate_opa" in tool_names
        assert "agent_gate_sentinel" in tool_names
        assert "agent_gate_sops" in tool_names
        assert "agent_gate_docker_bake" in tool_names
        assert "agent_gate_vagrant" in tool_names
        assert "agent_gate_cloud_init" in tool_names
        assert "agent_gate_systemd" in tool_names
        assert "agent_gate_proxy_config" in tool_names
        assert "agent_gate_atlantis" in tool_names
        assert "agent_gate_envoy" in tool_names
        assert "agent_gate_monitoring" in tool_names
        assert "agent_gate_otel_collector" in tool_names
        assert "agent_gate_traefik" in tool_names
        assert "agent_gate_grafana" in tool_names
        assert "agent_gate_vault" in tool_names
        assert "agent_gate_consul" in tool_names
        assert "agent_gate_loki" in tool_names
        assert "agent_gate_caddy" in tool_names
        assert "agent_gate_terraform_config" in tool_names
        assert "agent_gate_terraform_lock" in tool_names
        assert "agent_gate_terraform_state" in tool_names
        assert "agent_gate_terraform_stack" in tool_names
        assert "agent_gate_terragrunt" in tool_names
        assert "agent_gate_helm" in tool_names
        assert "agent_gate_kustomize" in tool_names
        assert "agent_gate_crossplane" in tool_names
        assert "agent_gate_serverless" in tool_names
        assert "agent_gate_sam" in tool_names
        assert "agent_gate_dockerfile" in tool_names
        assert "agent_gate_configuration_management" in tool_names
        for tool_name in (
            "agent_gate_cloudformation",
            "agent_gate_cdk",
            "agent_gate_azure",
            "agent_gate_bicep",
            "agent_gate_kubernetes",
            "agent_gate_pulumi",
            "agent_gate_pulumi_project",
        ):
            assert "framework" in tools_by_name[tool_name]["inputSchema"]["properties"]
        project_schema = tools_by_name["agent_gate_project"]["inputSchema"]
        assert {
            "project_path",
            "framework",
            "excludes",
            "max_files",
            "max_file_bytes",
        } <= set(project_schema["properties"])
        pipeline_schema = tools_by_name["agent_gate_pipeline"]["inputSchema"]
        assert {"input_path", "ecosystem", "framework"} <= set(pipeline_schema["properties"])
        workload_schema = tools_by_name["agent_gate_workload"]["inputSchema"]
        assert {"input_path", "ecosystem", "framework"} <= set(workload_schema["properties"])
        packer_schema = tools_by_name["agent_gate_packer"]["inputSchema"]
        assert {"input_path", "framework"} <= set(packer_schema["properties"])
        skaffold_schema = tools_by_name["agent_gate_skaffold"]["inputSchema"]
        assert {"input_path", "framework"} <= set(skaffold_schema["properties"])
        devspace_schema = tools_by_name["agent_gate_devspace"]["inputSchema"]
        assert {"input_path", "framework"} <= set(devspace_schema["properties"])
        tilt_schema = tools_by_name["agent_gate_tilt"]["inputSchema"]
        assert {"input_path", "framework"} <= set(tilt_schema["properties"])
        cue_schema = tools_by_name["agent_gate_cue"]["inputSchema"]
        assert {"input_path", "framework"} <= set(cue_schema["properties"])
        jsonnet_schema = tools_by_name["agent_gate_jsonnet"]["inputSchema"]
        assert {"input_path", "framework"} <= set(jsonnet_schema["properties"])
        helmfile_schema = tools_by_name["agent_gate_helmfile"]["inputSchema"]
        assert {"input_path", "framework"} <= set(helmfile_schema["properties"])
        terramate_schema = tools_by_name["agent_gate_terramate"]["inputSchema"]
        assert {"input_path", "framework"} <= set(terramate_schema["properties"])
        spacelift_schema = tools_by_name["agent_gate_spacelift"]["inputSchema"]
        assert {"input_path", "framework"} <= set(spacelift_schema["properties"])
        carvel_schema = tools_by_name["agent_gate_carvel"]["inputSchema"]
        assert {"input_path", "framework"} <= set(carvel_schema["properties"])
        salt_schema = tools_by_name["agent_gate_salt"]["inputSchema"]
        assert {"input_path", "framework"} <= set(salt_schema["properties"])
        nix_schema = tools_by_name["agent_gate_nix"]["inputSchema"]
        assert {"input_path", "framework"} <= set(nix_schema["properties"])
        dsc_schema = tools_by_name["agent_gate_dsc"]["inputSchema"]
        assert {"input_path", "framework"} <= set(dsc_schema["properties"])
        cfengine_schema = tools_by_name["agent_gate_cfengine"]["inputSchema"]
        assert {"input_path", "framework"} <= set(cfengine_schema["properties"])
        opa_schema = tools_by_name["agent_gate_opa"]["inputSchema"]
        assert {"input_path", "framework"} <= set(opa_schema["properties"])
        sentinel_schema = tools_by_name["agent_gate_sentinel"]["inputSchema"]
        assert {"input_path", "framework"} <= set(sentinel_schema["properties"])
        sops_schema = tools_by_name["agent_gate_sops"]["inputSchema"]
        assert {"input_path", "framework"} <= set(sops_schema["properties"])
        docker_bake_schema = tools_by_name["agent_gate_docker_bake"]["inputSchema"]
        assert {"input_path", "framework"} <= set(docker_bake_schema["properties"])
        vagrant_schema = tools_by_name["agent_gate_vagrant"]["inputSchema"]
        assert {"input_path", "framework"} <= set(vagrant_schema["properties"])
        cloud_init_schema = tools_by_name["agent_gate_cloud_init"]["inputSchema"]
        assert {"input_path", "framework"} <= set(cloud_init_schema["properties"])
        systemd_schema = tools_by_name["agent_gate_systemd"]["inputSchema"]
        assert {"input_path", "framework"} <= set(systemd_schema["properties"])
        proxy_schema = tools_by_name["agent_gate_proxy_config"]["inputSchema"]
        assert {"input_path", "ecosystem", "framework"} <= set(proxy_schema["properties"])
        atlantis_schema = tools_by_name["agent_gate_atlantis"]["inputSchema"]
        assert {"input_path", "framework"} <= set(atlantis_schema["properties"])
        envoy_schema = tools_by_name["agent_gate_envoy"]["inputSchema"]
        assert {"input_path", "framework"} <= set(envoy_schema["properties"])
        monitoring_schema = tools_by_name["agent_gate_monitoring"]["inputSchema"]
        assert {"input_path", "ecosystem", "framework"} <= set(monitoring_schema["properties"])
        collector_schema = tools_by_name["agent_gate_otel_collector"]["inputSchema"]
        assert {"input_path", "framework"} <= set(collector_schema["properties"])
        traefik_schema = tools_by_name["agent_gate_traefik"]["inputSchema"]
        assert {"input_path", "framework"} <= set(traefik_schema["properties"])
        grafana_schema = tools_by_name["agent_gate_grafana"]["inputSchema"]
        assert {"input_path", "framework"} <= set(grafana_schema["properties"])
        vault_schema = tools_by_name["agent_gate_vault"]["inputSchema"]
        assert {"input_path", "framework"} <= set(vault_schema["properties"])
        consul_schema = tools_by_name["agent_gate_consul"]["inputSchema"]
        assert {"input_path", "framework"} <= set(consul_schema["properties"])
        loki_schema = tools_by_name["agent_gate_loki"]["inputSchema"]
        assert {"input_path", "framework"} <= set(loki_schema["properties"])
        caddy_schema = tools_by_name["agent_gate_caddy"]["inputSchema"]
        assert {"input_path", "framework"} <= set(caddy_schema["properties"])
        tf_config_schema = tools_by_name["agent_gate_terraform_config"]["inputSchema"]
        assert {"input_path", "framework"} <= set(tf_config_schema["properties"])
        tf_lock_schema = tools_by_name["agent_gate_terraform_lock"]["inputSchema"]
        assert {"input_path", "framework"} <= set(tf_lock_schema["properties"])
        tf_state_schema = tools_by_name["agent_gate_terraform_state"]["inputSchema"]
        assert {"input_path", "framework"} <= set(tf_state_schema["properties"])
        tf_stack_schema = tools_by_name["agent_gate_terraform_stack"]["inputSchema"]
        assert {"input_path", "framework"} <= set(tf_stack_schema["properties"])
        terragrunt_schema = tools_by_name["agent_gate_terragrunt"]["inputSchema"]
        assert {"input_path", "framework"} <= set(terragrunt_schema["properties"])
        helm_schema = tools_by_name["agent_gate_helm"]["inputSchema"]
        assert {"input_path", "framework"} <= set(helm_schema["properties"])
        kustomize_schema = tools_by_name["agent_gate_kustomize"]["inputSchema"]
        assert {"input_path", "framework"} <= set(kustomize_schema["properties"])
        crossplane_schema = tools_by_name["agent_gate_crossplane"]["inputSchema"]
        assert {"input_path", "framework"} <= set(crossplane_schema["properties"])
        serverless_schema = tools_by_name["agent_gate_serverless"]["inputSchema"]
        assert {"input_path", "framework"} <= set(serverless_schema["properties"])
        sam_schema = tools_by_name["agent_gate_sam"]["inputSchema"]
        assert {"input_path", "framework"} <= set(sam_schema["properties"])
        dockerfile_schema = tools_by_name["agent_gate_dockerfile"]["inputSchema"]
        assert {"input_path", "framework"} <= set(dockerfile_schema["properties"])
        config_management_schema = tools_by_name["agent_gate_configuration_management"][
            "inputSchema"
        ]
        assert {"input_path", "ecosystem", "framework"} <= set(
            config_management_schema["properties"]
        )

        # --- tools/call: analyze_plan ---
        call_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "analyze_plan",
                "arguments": {"plan_path": str(plan.resolve())},
            },
        }
        call_resp = _send_jsonrpc(proc, call_req)
        assert "result" in call_resp, f"tools/call failed: {call_resp}"

        # MCP wraps tool results as content items
        content = call_resp["result"]["content"]
        assert len(content) == 1
        assert content[0]["type"] == "text"
        mcp_summary = json.loads(content[0]["text"])

        # compare with CLI JSON output
        import subprocess as sp

        cli_out = sp.check_output(
            [
                "readtheplan",
                "analyze",
                "--format",
                "json",
                str(plan),
            ],
            text=True,
        )
        cli_summary = json.loads(cli_out)

        assert mcp_summary == cli_summary

        # --- tools/call: agent_gate_project ---
        project_req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "agent_gate_project",
                "arguments": {
                    "project_path": str((FIXTURES / "project_scan").resolve()),
                    "framework": "soc2",
                },
            },
        }
        project_resp = _send_jsonrpc(proc, project_req)
        assert "result" in project_resp, f"project tools/call failed: {project_resp}"
        project_content = project_resp["result"]["content"]
        assert len(project_content) == 1
        project_summary = json.loads(project_content[0]["text"])
        assert project_summary["adapter"] == "project-scan"
        assert project_summary["discovered_file_count"] == 4
        assert project_summary["scanned_file_count"] == 4
        assert "project-scan-secret" not in project_content[0]["text"]

        # --- tools/call: agent_gate_configuration_management (puppet.conf) ---
        puppet_req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "agent_gate_configuration_management",
                "arguments": {
                    "input_path": str((FIXTURES / "puppet_conf_risky.conf").resolve()),
                    "ecosystem": "puppet-project",
                    "framework": "soc2",
                },
            },
        }
        puppet_resp = _send_jsonrpc(proc, puppet_req)
        assert "result" in puppet_resp, f"puppet.conf tools/call failed: {puppet_resp}"
        puppet_content = puppet_resp["result"]["content"]
        assert len(puppet_content) == 1
        puppet_summary = json.loads(puppet_content[0]["text"])
        assert puppet_summary["adapter"] == "puppet-project"
        assert puppet_summary["artifact_type"] == "config"
        assert puppet_summary["total_changes"] == 34
        assert "fixture-puppet-proxy-password-do-not-leak" not in puppet_content[0]["text"]
        assert "fixture-puppet-header-token-do-not-leak" not in puppet_content[0]["text"]

        # --- tools/call: agent_gate_configuration_management (Jenkins plugins) ---
        jenkins_project_req = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "agent_gate_configuration_management",
                "arguments": {
                    "input_path": str(
                        (FIXTURES / "jenkins_plugins_risky.txt").resolve()
                    ),
                    "ecosystem": "jenkins-project",
                    "framework": "soc2",
                },
            },
        }
        jenkins_project_resp = _send_jsonrpc(proc, jenkins_project_req)
        assert "result" in jenkins_project_resp, (
            f"Jenkins plugin tools/call failed: {jenkins_project_resp}"
        )
        jenkins_project_content = jenkins_project_resp["result"]["content"]
        assert len(jenkins_project_content) == 1
        jenkins_project_summary = json.loads(jenkins_project_content[0]["text"])
        assert jenkins_project_summary["adapter"] == "jenkins-project"
        assert jenkins_project_summary["artifact_type"] == "plugins_txt"
        assert jenkins_project_summary["plugin_count"] == 7
        assert jenkins_project_summary["total_changes"] == 8
        assert "fixture-user" not in jenkins_project_content[0]["text"]
        assert "fixture-password" not in jenkins_project_content[0]["text"]
        assert "plugins.example.invalid" not in jenkins_project_content[0]["text"]

        # --- tools/call: agent_gate_configuration_management (Chef client.rb) ---
        chef_runtime_req = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "agent_gate_configuration_management",
                "arguments": {
                    "input_path": str(
                        (FIXTURES / "chef_runtime" / "client.rb").resolve()
                    ),
                    "ecosystem": "chef-project",
                    "framework": "soc2",
                },
            },
        }
        chef_runtime_resp = _send_jsonrpc(proc, chef_runtime_req)
        assert "result" in chef_runtime_resp, (
            f"Chef runtime tools/call failed: {chef_runtime_resp}"
        )
        chef_runtime_content = chef_runtime_resp["result"]["content"]
        assert len(chef_runtime_content) == 1
        chef_runtime_summary = json.loads(chef_runtime_content[0]["text"])
        assert chef_runtime_summary["adapter"] == "chef-project"
        assert chef_runtime_summary["artifact_type"] == "client_config"
        assert chef_runtime_summary["setting_count"] == 16
        assert chef_runtime_summary["total_changes"] == 18
        assert "fixture-chef" not in chef_runtime_content[0]["text"]
        assert "example.invalid" not in chef_runtime_content[0]["text"]

    finally:
        proc.stdin.close()  # type: ignore[union-attr]
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        # stderr should not contain raw plan JSON
        stderr_text = proc.stderr.read().decode("utf-8", errors="replace")  # type: ignore[union-attr]
        # The valid_plan.json contains "resource_changes" — stderr should
        # NOT leak the raw plan payload (only file paths, error messages).
        assert "resource_changes" not in stderr_text, (
            "MCP server stderr must not include raw plan JSON"
        )


@pytestmark_stdio
def test_stdio_server_analyze_plan_with_framework() -> None:
    """Stdio integration: analyze_plan with framework parameter."""
    plan = FIXTURES / "soc2_plan.json"

    proc = subprocess.Popen(
        ["readtheplan", "mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    try:
        _mcp_initialize(proc)

        call_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "analyze_plan",
                "arguments": {
                    "plan_path": str(plan.resolve()),
                    "framework": "soc2",
                },
            },
        }
        call_resp = _send_jsonrpc(proc, call_req)
        assert "result" in call_resp, f"tools/call failed: {call_resp}"

        content = call_resp["result"]["content"]
        mcp_summary = json.loads(content[0]["text"])

        assert "framework" in mcp_summary
        assert mcp_summary["framework"]["name"] == "soc2"
        for change in mcp_summary["changes"]:
            assert "controls" in change

    finally:
        proc.stdin.close()  # type: ignore[union-attr]
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
