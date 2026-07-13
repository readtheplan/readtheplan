from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable, Sequence
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, TextIO, cast

from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.controls import (
    CatalogSchemaError,
    ControlCatalog,
    FrameworkNotFoundError,
    available_frameworks,
    load_catalog,
)
from readtheplan.evidence import EvidenceError, Reviewer, build_evidence
from readtheplan.evolution import get_engine
from readtheplan.overlays import (
    Overlay,
    OverlayError,
    apply_overlay_to_catalog,
    apply_overlay_to_change,
    load_overlay,
)
from readtheplan.plan import PlanError, PlanSummary, analyze_plan_file, load_plan
from readtheplan.rules import RISK_ORDER
from readtheplan.signing import (
    SigningError,
    VerificationError,
    sign_envelope,
    verify_envelope,
)
from readtheplan.summary import summary_to_dict


def main(
    argv: Sequence[str] | None = None,
    *,
    include_git_version: bool = True,
) -> int:
    parser = _build_parser(include_git_version=include_git_version)
    args = parser.parse_args(argv)
    func = getattr(args, "evolution_func", None) or cast(
        "Callable[[argparse.Namespace], int]", args.func
    )
    return func(args)


def _build_parser(*, include_git_version: bool = True) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="readtheplan",
        description=(
            "Review infrastructure changes across plans, manifests, playbooks, and pipelines."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_package_version(include_git=include_git_version)}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a Terraform plan JSON file.",
    )
    analyze.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format. Defaults to text.",
    )
    analyze.add_argument(
        "--no-rules",
        action="store_true",
        help="Disable resource-aware rules and use the action-only classifier.",
    )
    analyze.add_argument(
        "--fail-on",
        choices=tuple(RISK_ORDER),
        help=(
            "After printing the normal report, exit 2 if any change is at or "
            "above this risk tier. Independent of output format."
        ),
    )
    analyze.add_argument(
        "--rules-file",
        action="append",
        default=[],
        metavar="PATH",
        help="Apply overlay YAML on top of built-in rules. Repeatable.",
    )
    analyze.add_argument(
        "--framework",
        help=(
            "Annotate each change with control IDs from the named framework "
            f"catalog. Currently available: {_framework_help_list()}."
        ),
    )
    analyze.add_argument(
        "--evidence",
        metavar="PATH",
        help="Write rtp-evidence-v1 JSON envelope to PATH. Use - for stdout.",
    )
    analyze.add_argument(
        "--agent-id",
        default=_default_agent_id(),
        help="Agent ID for evidence attestation.",
    )
    analyze.add_argument(
        "--reviewer-id",
        help="Optional reviewer identifier for evidence output.",
    )
    analyze.add_argument(
        "--reviewer-kind",
        choices=("human", "agent"),
        default="human",
        help="Reviewer kind for evidence output. Defaults to human.",
    )
    analyze.add_argument(
        "--run-id",
        help="Optional CI run identifier for evidence attestation.",
    )
    analyze.add_argument(
        "--sign",
        action="store_true",
        help="Sign the evidence envelope using sigstore keyless signing.",
    )
    analyze.add_argument(
        "--oidc-issuer",
        help="OIDC issuer for sigstore signing. Defaults to sigstore public.",
    )
    analyze.add_argument(
        "--rekor-url",
        help="Rekor transparency log URL. Defaults to sigstore public.",
    )
    analyze.add_argument(
        "--mode",
        choices=("kernel", "self-improving"),
        default="kernel",
        help='Gate mode. "kernel": basic gate. '
        '"self-improving": gate + evolution recording + rule suggestion.',
    )
    analyze.add_argument("plan_file", help="Path to Terraform plan JSON.")
    analyze.set_defaults(func=_analyze)

    scan = subparsers.add_parser(
        "scan",
        help="Discover and gate supported infrastructure files across a project.",
    )
    scan.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog in every file gate. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude a repository-relative glob. Repeatable.",
    )
    scan.add_argument(
        "--max-files",
        type=int,
        default=500,
        help="Maximum supported inputs to analyze. Defaults to 500.",
    )
    scan.add_argument(
        "--max-file-bytes",
        type=int,
        default=10 * 1024 * 1024,
        help="Maximum size of one discovered input. Defaults to 10 MiB.",
    )
    scan.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project directory or supported input file. Defaults to the current directory.",
    )
    scan.set_defaults(func=_scan_project)

    agent_gate = subparsers.add_parser(
        "agent-gate",
        help="Emit the local coding-agent gate decision for a Terraform plan JSON file.",
    )
    agent_gate.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    agent_gate.add_argument(
        "--mode",
        choices=("kernel", "self-improving"),
        default="kernel",
        help='Gate mode. "kernel": basic gate. '
        '"self-improving": gate + evolution recording + rule suggestion.',
    )
    agent_gate.add_argument("plan_file", help="Path to Terraform plan JSON.")
    agent_gate.set_defaults(func=_agent_gate)

    cloudformation = subparsers.add_parser(
        "cloudformation",
        help="Emit the agent-gate decision for a CloudFormation Change Set or template diff.",
    )
    cloudformation.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    cloudformation.add_argument(
        "input_file", help="Path to CloudFormation Change Set JSON or template diff."
    )
    cloudformation.set_defaults(func=_cloudformation_gate)

    cdk = subparsers.add_parser(
        "cdk",
        help="Emit the agent-gate decision for an AWS CDK Cloud Assembly or asset manifest.",
    )
    cdk.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    cdk.add_argument(
        "input_file", help="Path to cdk.out/manifest.json or a CDK asset manifest JSON file."
    )
    cdk.set_defaults(func=_cdk_gate)

    azure = subparsers.add_parser(
        "azure",
        help="Emit the agent-gate decision for Azure Bicep/ARM What-If JSON.",
    )
    azure.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    azure.add_argument(
        "input_file",
        help="Path to Azure deployment What-If JSON.",
    )
    azure.set_defaults(func=_azure_gate)

    bicep = subparsers.add_parser(
        "bicep",
        help="Emit the agent-gate decision for Azure Bicep source.",
    )
    bicep.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    bicep.add_argument("input_file", help="Path to an Azure Bicep source file.")
    bicep.set_defaults(func=_bicep_gate)

    kubernetes = subparsers.add_parser(
        "kubernetes",
        help="Emit the agent-gate decision for a Kubernetes manifest diff.",
    )
    kubernetes.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    kubernetes.add_argument(
        "input_file",
        help=("Path to Kubernetes JSON/YAML, multi-document YAML, or a manifest diff wrapper."),
    )
    kubernetes.set_defaults(func=_kubernetes_gate)

    pulumi = subparsers.add_parser(
        "pulumi",
        help="Emit the agent-gate decision for Pulumi preview JSON.",
    )
    pulumi.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    pulumi.add_argument(
        "input_file",
        help="Path to Pulumi preview digest JSON or streaming JSON events.",
    )
    pulumi.set_defaults(func=_pulumi_gate)

    pulumi_project = subparsers.add_parser(
        "pulumi-project",
        help="Emit the agent-gate decision for Pulumi project, stack, or policy YAML.",
    )
    pulumi_project.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    pulumi_project.add_argument(
        "input_file",
        help="Path to Pulumi.yaml, Pulumi.<stack>.yaml, or PulumiPolicy.yaml.",
    )
    pulumi_project.set_defaults(func=_pulumi_project_gate)

    ansible = subparsers.add_parser(
        "ansible",
        help="Emit the agent-gate decision for an Ansible playbook.",
    )
    ansible.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    ansible.add_argument("input_file", help="Path to an Ansible playbook YAML file.")
    ansible.set_defaults(func=_ansible_gate)

    ansible_project = subparsers.add_parser(
        "ansible-project",
        help="Analyze Ansible configuration, dependencies, or inventory.",
    )
    ansible_project.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    ansible_project.add_argument(
        "input_file",
        help="Path to ansible.cfg, Galaxy requirements, or YAML/INI/plugin inventory.",
    )
    ansible_project.set_defaults(func=_ansible_project_gate)

    jenkins = subparsers.add_parser(
        "jenkins",
        help="Emit the agent-gate decision for a declarative or scripted Jenkinsfile.",
    )
    jenkins.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    jenkins.add_argument("input_file", help="Path to a Jenkinsfile.")
    jenkins.set_defaults(func=_jenkins_gate)

    teamcity = subparsers.add_parser(
        "teamcity",
        help="Emit the agent-gate decision for TeamCity Kotlin DSL settings.",
    )
    teamcity.add_argument("--framework", help="Include checks from a compliance framework.")
    teamcity.add_argument("input_file", help="Path to a TeamCity .kts or .kt settings file.")
    teamcity.set_defaults(func=_teamcity_gate)

    jenkins_jcasc = subparsers.add_parser(
        "jenkins-jcasc",
        help="Emit the agent-gate decision for Jenkins Configuration as Code YAML.",
    )
    jenkins_jcasc.add_argument("--framework", help="Include checks from a compliance framework.")
    jenkins_jcasc.add_argument("input_file", help="Path to a JCasC YAML file.")
    jenkins_jcasc.set_defaults(func=_jenkins_jcasc_gate)

    chef = subparsers.add_parser(
        "chef",
        help="Emit the agent-gate decision for a Chef recipe.",
    )
    chef.add_argument("--framework", help="Include checks from a compliance framework.")
    chef.add_argument("input_file", help="Path to a Chef recipe (.rb).")
    chef.set_defaults(func=_chef_gate)

    chef_project = subparsers.add_parser(
        "chef-project",
        help="Emit the agent-gate decision for Chef policy or cookbook project files.",
    )
    chef_project.add_argument("--framework", help="Include checks from a compliance framework.")
    chef_project.add_argument(
        "input_file",
        help="Path to Policyfile.rb, Policyfile.lock.json, or cookbook metadata.rb.",
    )
    chef_project.set_defaults(func=_chef_project_gate)

    puppet = subparsers.add_parser(
        "puppet",
        help="Emit the agent-gate decision for a Puppet manifest.",
    )
    puppet.add_argument("--framework", help="Include checks from a compliance framework.")
    puppet.add_argument("input_file", help="Path to a Puppet manifest (.pp).")
    puppet.set_defaults(func=_puppet_gate)

    puppet_project = subparsers.add_parser(
        "puppet-project",
        help="Emit the agent-gate decision for Puppet project and runtime configuration.",
    )
    puppet_project.add_argument("--framework", help="Include checks from a compliance framework.")
    puppet_project.add_argument(
        "input_file", help="Path to Puppetfile, metadata.json, hiera.yaml, or puppet.conf."
    )
    puppet_project.set_defaults(func=_puppet_project_gate)

    github_actions = subparsers.add_parser(
        "github-actions",
        help="Emit the agent-gate decision for a GitHub Actions workflow YAML file.",
    )
    github_actions.add_argument("--framework", help="Include checks from a compliance framework.")
    github_actions.add_argument("input_file", help="Path to a workflow YAML file.")
    github_actions.set_defaults(func=_pipeline_gate)

    gitlab_ci = subparsers.add_parser(
        "gitlab-ci",
        help="Emit the agent-gate decision for a GitLab CI configuration.",
    )
    gitlab_ci.add_argument("--framework", help="Include checks from a compliance framework.")
    gitlab_ci.add_argument("input_file", help="Path to .gitlab-ci.yml.")
    gitlab_ci.set_defaults(func=_pipeline_gate)

    circleci = subparsers.add_parser(
        "circleci",
        help="Emit the agent-gate decision for a CircleCI configuration.",
    )
    circleci.add_argument("--framework", help="Include checks from a compliance framework.")
    circleci.add_argument("input_file", help="Path to .circleci/config.yml.")
    circleci.set_defaults(func=_pipeline_gate)

    azure_pipelines = subparsers.add_parser(
        "azure-pipelines",
        help="Emit the agent-gate decision for an Azure Pipelines YAML configuration.",
    )
    azure_pipelines.add_argument("--framework", help="Include checks from a compliance framework.")
    azure_pipelines.add_argument("input_file", help="Path to azure-pipelines.yml.")
    azure_pipelines.set_defaults(func=_pipeline_gate)

    bitbucket_pipelines = subparsers.add_parser(
        "bitbucket-pipelines",
        help="Emit the agent-gate decision for bitbucket-pipelines.yml.",
    )
    bitbucket_pipelines.add_argument(
        "--framework", help="Include checks from a compliance framework."
    )
    bitbucket_pipelines.add_argument("input_file", help="Path to bitbucket-pipelines.yml.")
    bitbucket_pipelines.set_defaults(func=_pipeline_gate)

    buildkite = subparsers.add_parser(
        "buildkite",
        help="Emit the agent-gate decision for a Buildkite pipeline YAML file.",
    )
    buildkite.add_argument("--framework", help="Include checks from a compliance framework.")
    buildkite.add_argument("input_file", help="Path to a Buildkite pipeline YAML file.")
    buildkite.set_defaults(func=_pipeline_gate)

    travis_ci = subparsers.add_parser(
        "travis-ci",
        help="Emit the agent-gate decision for a Travis CI configuration.",
    )
    travis_ci.add_argument("--framework", help="Include checks from a compliance framework.")
    travis_ci.add_argument("input_file", help="Path to .travis.yml.")
    travis_ci.set_defaults(func=_pipeline_gate)

    drone_ci = subparsers.add_parser(
        "drone-ci",
        help="Emit the agent-gate decision for a Drone CI pipeline.",
    )
    drone_ci.add_argument("--framework", help="Include checks from a compliance framework.")
    drone_ci.add_argument("input_file", help="Path to .drone.yml.")
    drone_ci.set_defaults(func=_pipeline_gate)

    woodpecker_ci = subparsers.add_parser(
        "woodpecker-ci",
        help="Emit the agent-gate decision for a Woodpecker CI workflow.",
    )
    woodpecker_ci.add_argument(
        "--framework", help="Include checks from a compliance framework."
    )
    woodpecker_ci.add_argument("input_file", help="Path to a Woodpecker workflow YAML file.")
    woodpecker_ci.set_defaults(func=_pipeline_gate)

    concourse = subparsers.add_parser(
        "concourse",
        help="Emit the agent-gate decision for a Concourse pipeline YAML file.",
    )
    concourse.add_argument("--framework", help="Include checks from a compliance framework.")
    concourse.add_argument("input_file", help="Path to a Concourse pipeline YAML file.")
    concourse.set_defaults(func=_pipeline_gate)

    bamboo = subparsers.add_parser(
        "bamboo",
        help="Emit the agent-gate decision for Bamboo YAML Specs.",
    )
    bamboo.add_argument("--framework", help="Include checks from a compliance framework.")
    bamboo.add_argument("input_file", help="Path to bamboo-specs/bamboo.yml.")
    bamboo.set_defaults(func=_pipeline_gate)

    codebuild = subparsers.add_parser(
        "codebuild",
        help="Emit the agent-gate decision for an AWS CodeBuild buildspec.",
    )
    codebuild.add_argument("--framework", help="Include checks from a compliance framework.")
    codebuild.add_argument("input_file", help="Path to buildspec.yml.")
    codebuild.set_defaults(func=_cloud_ci_gate)

    cloud_build = subparsers.add_parser(
        "cloud-build",
        help="Emit the agent-gate decision for a Google Cloud Build configuration.",
    )
    cloud_build.add_argument("--framework", help="Include checks from a compliance framework.")
    cloud_build.add_argument("input_file", help="Path to cloudbuild.yaml or cloudbuild.json.")
    cloud_build.set_defaults(func=_cloud_ci_gate)

    codepipeline = subparsers.add_parser(
        "codepipeline",
        help="Emit the agent-gate decision for an AWS CodePipeline definition.",
    )
    codepipeline.add_argument("--framework", help="Include checks from a compliance framework.")
    codepipeline.add_argument("input_file", help="Path to a CodePipeline JSON or YAML file.")
    codepipeline.set_defaults(func=_cloud_ci_gate)

    atlantis = subparsers.add_parser(
        "atlantis",
        help="Emit the agent-gate decision for Atlantis repo or server configuration.",
    )
    atlantis.add_argument("--framework", help="Include checks from a compliance framework.")
    atlantis.add_argument("input_file", help="Path to atlantis.yaml or server repos.yaml.")
    atlantis.set_defaults(func=_atlantis_gate)

    docker_compose = subparsers.add_parser(
        "docker-compose",
        help="Emit the agent-gate decision for a Docker Compose configuration.",
    )
    docker_compose.add_argument("--framework", help="Include checks from a compliance framework.")
    docker_compose.add_argument("input_file", help="Path to a Compose YAML file.")
    docker_compose.set_defaults(func=_workload_gate)

    nomad = subparsers.add_parser(
        "nomad",
        help="Emit the agent-gate decision for a Nomad plan response or jobspec source.",
    )
    nomad.add_argument("--framework", help="Include checks from a compliance framework.")
    nomad.add_argument("input_file", help="Path to a Nomad plan JSON or HCL/JSON jobspec.")
    nomad.set_defaults(func=_workload_gate)

    packer = subparsers.add_parser(
        "packer",
        help="Emit the agent-gate decision for Packer template source or inspect output.",
    )
    packer.add_argument("--framework", help="Include checks from a compliance framework.")
    packer.add_argument(
        "input_file",
        help="Path to .pkr.hcl/.pkr.json template or human/machine-readable inspect output.",
    )
    packer.set_defaults(func=_packer_gate)

    skaffold = subparsers.add_parser(
        "skaffold",
        help="Emit the agent-gate decision for Skaffold pipeline configuration.",
    )
    skaffold.add_argument("--framework", help="Include checks from a compliance framework.")
    skaffold.add_argument("input_file", help="Path to skaffold.yaml or another Skaffold Config.")
    skaffold.set_defaults(func=_skaffold_gate)

    devspace = subparsers.add_parser(
        "devspace",
        help="Emit the agent-gate decision for DevSpace project configuration.",
    )
    devspace.add_argument("--framework", help="Include checks from a compliance framework.")
    devspace.add_argument("input_file", help="Path to devspace.yaml.")
    devspace.set_defaults(func=_devspace_gate)

    tilt = subparsers.add_parser(
        "tilt",
        help="Emit the agent-gate decision for a Tiltfile.",
    )
    tilt.add_argument("--framework", help="Include checks from a compliance framework.")
    tilt.add_argument("input_file", help="Path to a Tiltfile.")
    tilt.set_defaults(func=_tiltfile_gate)

    cue = subparsers.add_parser(
        "cue",
        help="Emit the agent-gate decision for CUE source, module, or workflow configuration.",
    )
    cue.add_argument("--framework", help="Include checks from a compliance framework.")
    cue.add_argument("input_file", help="Path to a .cue source file.")
    cue.set_defaults(func=_cue_gate)

    jsonnet = subparsers.add_parser(
        "jsonnet",
        help="Emit the agent-gate decision for Jsonnet source or jsonnet-bundler metadata.",
    )
    jsonnet.add_argument("--framework", help="Include checks from a compliance framework.")
    jsonnet.add_argument(
        "input_file", help="Path to Jsonnet source, spec.json, or jsonnetfile metadata."
    )
    jsonnet.set_defaults(func=_jsonnet_gate)

    tanka = subparsers.add_parser(
        "tanka",
        help="Emit the agent-gate decision for a Grafana Tanka environment or Jsonnet source.",
    )
    tanka.add_argument("--framework", help="Include checks from a compliance framework.")
    tanka.add_argument(
        "input_file", help="Path to Tanka main.jsonnet, spec.json, or dependency metadata."
    )
    tanka.set_defaults(func=_jsonnet_gate)

    helmfile = subparsers.add_parser(
        "helmfile",
        help="Emit the agent-gate decision for Helmfile state or lock configuration.",
    )
    helmfile.add_argument("--framework", help="Include checks from a compliance framework.")
    helmfile.add_argument("input_file", help="Path to helmfile YAML/Go-template state or lock.")
    helmfile.set_defaults(func=_helmfile_gate)

    terramate = subparsers.add_parser(
        "terramate",
        help="Emit the agent-gate decision for Terramate configuration or .tmgen source.",
    )
    terramate.add_argument("--framework", help="Include checks from a compliance framework.")
    terramate.add_argument("input_file", help="Path to a .tm.hcl, .tm, .tm.json, or .tmgen file.")
    terramate.set_defaults(func=_terramate_gate)

    spacelift = subparsers.add_parser(
        "spacelift",
        help="Emit the agent-gate decision for Spacelift runtime configuration.",
    )
    spacelift.add_argument("--framework", help="Include checks from a compliance framework.")
    spacelift.add_argument(
        "input_file",
        help="Path to .spacelift/config.yml or a single-stack runtime configuration.",
    )
    spacelift.set_defaults(func=_spacelift_gate)

    for command, help_text in (
        ("ytt", "ytt templates and data-value/overlay source"),
        ("vendir", "vendir desired or locked directory content"),
        ("kbld", "kbld image search/build/override/publish configuration"),
        ("imgpkg", "imgpkg image or bundle lock configuration"),
        ("kapp", "kapp deploy configuration or annotated manifests"),
    ):
        carvel = subparsers.add_parser(
            command,
            help=f"Emit the agent-gate decision for {help_text}.",
        )
        carvel.add_argument("--framework", help="Include checks from a compliance framework.")
        carvel.add_argument("input_file", help=f"Path to {help_text}.")
        carvel.set_defaults(func=_carvel_gate)

    salt = subparsers.add_parser(
        "salt",
        help="Emit the agent-gate decision for a Salt SLS state file.",
    )
    salt.add_argument("--framework", help="Include checks from a compliance framework.")
    salt.add_argument("input_file", help="Path to a Salt SLS YAML/Jinja state file.")
    salt.set_defaults(func=_salt_gate)

    salt_project = subparsers.add_parser(
        "salt-project",
        help="Emit the agent-gate decision for Salt project configuration.",
    )
    salt_project.add_argument("--framework", help="Include checks from a compliance framework.")
    salt_project.add_argument(
        "input_file",
        help="Path to Salt master/minion config, a top file, or a salt-ssh roster.",
    )
    salt_project.set_defaults(func=_salt_project_gate)

    nix = subparsers.add_parser(
        "nix",
        help="Emit the agent-gate decision for Nix flakes, locks, or NixOS modules.",
    )
    nix.add_argument("--framework", help="Include checks from a compliance framework.")
    nix.add_argument("input_file", help="Path to flake.nix, flake.lock, or a NixOS module.")
    nix.set_defaults(func=_nix_gate)

    dsc = subparsers.add_parser(
        "dsc",
        help="Emit the agent-gate decision for DSC configuration.",
    )
    dsc.add_argument("--framework", help="Include checks from a compliance framework.")
    dsc.add_argument(
        "input_file",
        help="Path to a DSC JSON/YAML document or PowerShell DSC configuration.",
    )
    dsc.set_defaults(func=_dsc_gate)

    cfengine = subparsers.add_parser(
        "cfengine",
        help="Emit the agent-gate decision for CFEngine policy or Augments data.",
    )
    cfengine.add_argument("--framework", help="Include checks from a compliance framework.")
    cfengine.add_argument(
        "input_file",
        help="Path to a CFEngine .cf policy or Augments JSON file.",
    )
    cfengine.set_defaults(func=_cfengine_gate)

    opa = subparsers.add_parser(
        "opa",
        help="Emit the agent-gate decision for Rego, OPA bundle metadata, or Conftest config.",
    )
    opa.add_argument("--framework", help="Include checks from a compliance framework.")
    opa.add_argument(
        "input_file",
        help="Path to .rego, .manifest, .signatures.json, or conftest.toml.",
    )
    opa.set_defaults(func=_opa_gate)

    sentinel = subparsers.add_parser(
        "sentinel",
        help="Emit the agent-gate decision for Sentinel policy or CLI configuration.",
    )
    sentinel.add_argument("--framework", help="Include checks from a compliance framework.")
    sentinel.add_argument(
        "input_file",
        help="Path to a .sentinel policy or sentinel.hcl/sentinel.json configuration.",
    )
    sentinel.set_defaults(func=_sentinel_gate)

    sops = subparsers.add_parser(
        "sops",
        help="Emit the agent-gate decision for SOPS policy or encrypted data.",
    )
    sops.add_argument("--framework", help="Include checks from a compliance framework.")
    sops.add_argument(
        "input_file",
        help="Path to .sops.yaml or an encrypted SOPS YAML, JSON, dotenv, or INI file.",
    )
    sops.set_defaults(func=_sops_gate)

    vagrant = subparsers.add_parser(
        "vagrant",
        help="Emit the agent-gate decision for a Vagrantfile.",
    )
    vagrant.add_argument("--framework", help="Include checks from a compliance framework.")
    vagrant.add_argument("input_file", help="Path to a Vagrantfile.")
    vagrant.set_defaults(func=_vagrant_gate)

    systemd = subparsers.add_parser(
        "systemd",
        help="Emit the agent-gate decision for a systemd unit file.",
    )
    systemd.add_argument("--framework", help="Include checks from a compliance framework.")
    systemd.add_argument("input_file", help="Path to a systemd unit file.")
    systemd.set_defaults(func=_systemd_gate)

    nginx = subparsers.add_parser(
        "nginx",
        help="Emit the agent-gate decision for an NGINX configuration file.",
    )
    nginx.add_argument("--framework", help="Include checks from a compliance framework.")
    nginx.add_argument("input_file", help="Path to an NGINX configuration file.")
    nginx.set_defaults(func=_proxy_config_gate)

    haproxy = subparsers.add_parser(
        "haproxy",
        help="Emit the agent-gate decision for an HAProxy configuration file.",
    )
    haproxy.add_argument("--framework", help="Include checks from a compliance framework.")
    haproxy.add_argument("input_file", help="Path to an HAProxy configuration file.")
    haproxy.set_defaults(func=_proxy_config_gate)

    envoy = subparsers.add_parser(
        "envoy",
        help="Emit the agent-gate decision for Envoy bootstrap or config_dump data.",
    )
    envoy.add_argument("--framework", help="Include checks from a compliance framework.")
    envoy.add_argument("input_file", help="Path to Envoy YAML/JSON or config_dump JSON.")
    envoy.set_defaults(func=_envoy_gate)

    traefik = subparsers.add_parser(
        "traefik",
        help="Emit the agent-gate decision for Traefik YAML/JSON/TOML configuration.",
    )
    traefik.add_argument("--framework", help="Include checks from a compliance framework.")
    traefik.add_argument("input_file", help="Path to Traefik static or dynamic configuration.")
    traefik.set_defaults(func=_traefik_gate)

    grafana = subparsers.add_parser(
        "grafana",
        help="Emit the agent-gate decision for Grafana INI or provisioning config.",
    )
    grafana.add_argument("--framework", help="Include checks from a compliance framework.")
    grafana.add_argument("input_file", help="Path to grafana.ini or provisioning YAML/JSON.")
    grafana.set_defaults(func=_grafana_gate)

    vault = subparsers.add_parser(
        "vault",
        help="Emit the agent-gate decision for Vault server HCL/JSON configuration.",
    )
    vault.add_argument("--framework", help="Include checks from a compliance framework.")
    vault.add_argument("input_file", help="Path to Vault server HCL or JSON configuration.")
    vault.set_defaults(func=_hashicorp_gate)

    consul = subparsers.add_parser(
        "consul",
        help="Emit the agent-gate decision for Consul agent HCL/JSON configuration.",
    )
    consul.add_argument("--framework", help="Include checks from a compliance framework.")
    consul.add_argument("input_file", help="Path to Consul agent HCL or JSON configuration.")
    consul.set_defaults(func=_hashicorp_gate)

    loki = subparsers.add_parser(
        "loki",
        help="Emit the agent-gate decision for Grafana Loki configuration YAML.",
    )
    loki.add_argument("--framework", help="Include checks from a compliance framework.")
    loki.add_argument("input_file", help="Path to loki.yaml.")
    loki.set_defaults(func=_loki_gate)

    caddy = subparsers.add_parser(
        "caddy",
        help="Emit the agent-gate decision for Caddyfile or native Caddy JSON.",
    )
    caddy.add_argument("--framework", help="Include checks from a compliance framework.")
    caddy.add_argument("input_file", help="Path to a Caddyfile or native Caddy JSON.")
    caddy.set_defaults(func=_caddy_gate)

    terraform_config = subparsers.add_parser(
        "terraform-config",
        help="Emit the agent-gate decision for Terraform configuration HCL/JSON.",
    )
    terraform_config.add_argument("--framework", help="Include checks from a compliance framework.")
    terraform_config.add_argument("input_file", help="Path to a .tf or .tf.json file.")
    terraform_config.set_defaults(func=_terraform_config_gate)

    terraform_stack = subparsers.add_parser(
        "terraform-stack",
        help="Emit the agent-gate decision for Terraform Stack component or deployment HCL.",
    )
    terraform_stack.add_argument(
        "--framework", help="Include checks from a compliance framework."
    )
    terraform_stack.add_argument(
        "input_file", help="Path to a .tfcomponent.hcl or .tfdeploy.hcl file."
    )
    terraform_stack.set_defaults(func=_terraform_stack_gate)

    terraform_lock = subparsers.add_parser(
        "terraform-lock",
        help="Emit the agent-gate decision for a Terraform/OpenTofu dependency lock.",
    )
    terraform_lock.add_argument("--framework", help="Include checks from a compliance framework.")
    terraform_lock.add_argument(
        "input_file",
        help="Path to .terraform.lock.hcl.",
    )
    terraform_lock.set_defaults(func=_terraform_lock_gate)

    terraform_state = subparsers.add_parser(
        "terraform-state",
        help="Emit the agent-gate decision for Terraform/OpenTofu state JSON.",
    )
    terraform_state.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    terraform_state.add_argument(
        "input_file",
        help="Path to terraform/tofu show -json output or a raw v4 state snapshot.",
    )
    terraform_state.set_defaults(func=_terraform_state_gate)

    terragrunt = subparsers.add_parser(
        "terragrunt",
        help="Emit the agent-gate decision for Terragrunt configuration HCL/JSON.",
    )
    terragrunt.add_argument("--framework", help="Include checks from a compliance framework.")
    terragrunt.add_argument("input_file", help="Path to terragrunt.hcl or JSON configuration.")
    terragrunt.set_defaults(func=_terraform_config_gate)

    helm = subparsers.add_parser(
        "helm",
        help="Emit the agent-gate decision for Helm Chart.yaml, values YAML, or template source.",
    )
    helm.add_argument("--framework", help="Include checks from a compliance framework.")
    helm.add_argument("input_file", help="Path to Chart.yaml, values YAML, or a Helm template.")
    helm.set_defaults(func=_helm_gate)

    kustomize = subparsers.add_parser(
        "kustomize",
        help="Emit the agent-gate decision for a kustomization YAML file.",
    )
    kustomize.add_argument("--framework", help="Include checks from a compliance framework.")
    kustomize.add_argument("input_file", help="Path to kustomization.yaml.")
    kustomize.set_defaults(func=_kustomize_gate)

    crossplane = subparsers.add_parser(
        "crossplane",
        help="Emit the agent-gate decision for Crossplane package and resource YAML.",
    )
    crossplane.add_argument("--framework", help="Include checks from a compliance framework.")
    crossplane.add_argument("input_file", help="Path to Crossplane YAML or JSON resources.")
    crossplane.set_defaults(func=_crossplane_gate)

    serverless = subparsers.add_parser(
        "serverless",
        help="Emit the agent-gate decision for Serverless Framework service YAML.",
    )
    serverless.add_argument("--framework", help="Include checks from a compliance framework.")
    serverless.add_argument("input_file", help="Path to serverless.yml.")
    serverless.set_defaults(func=_serverless_source_gate)

    sam = subparsers.add_parser(
        "sam",
        help="Emit the agent-gate decision for an AWS SAM template.",
    )
    sam.add_argument("--framework", help="Include checks from a compliance framework.")
    sam.add_argument("input_file", help="Path to an AWS SAM template YAML or JSON file.")
    sam.set_defaults(func=_serverless_source_gate)

    prometheus = subparsers.add_parser(
        "prometheus",
        help="Emit the agent-gate decision for Prometheus configuration YAML.",
    )
    prometheus.add_argument("--framework", help="Include checks from a compliance framework.")
    prometheus.add_argument("input_file", help="Path to prometheus.yml.")
    prometheus.set_defaults(func=_monitoring_gate)

    alertmanager = subparsers.add_parser(
        "alertmanager",
        help="Emit the agent-gate decision for Alertmanager configuration YAML.",
    )
    alertmanager.add_argument("--framework", help="Include checks from a compliance framework.")
    alertmanager.add_argument("input_file", help="Path to alertmanager.yml.")
    alertmanager.set_defaults(func=_monitoring_gate)

    otel_collector = subparsers.add_parser(
        "otel-collector",
        help="Emit the agent-gate decision for OpenTelemetry Collector YAML.",
    )
    otel_collector.add_argument("--framework", help="Include checks from a compliance framework.")
    otel_collector.add_argument("input_file", help="Path to Collector configuration YAML.")
    otel_collector.set_defaults(func=_otel_collector_gate)

    cloud_init = subparsers.add_parser(
        "cloud-init",
        help="Emit the agent-gate decision for cloud-init user-data.",
    )
    cloud_init.add_argument("--framework", help="Include checks from a compliance framework.")
    cloud_init.add_argument("input_file", help="Path to cloud-init user-data.")
    cloud_init.set_defaults(func=_cloud_init_gate)

    docker_bake = subparsers.add_parser(
        "docker-bake",
        help="Emit the agent-gate decision for a Docker Buildx Bake definition.",
    )
    docker_bake.add_argument(
        "--framework", help="Include checks from a compliance framework."
    )
    docker_bake.add_argument(
        "input_file",
        help="Path to docker-bake.hcl, docker-bake.json, or a Compose build file.",
    )
    docker_bake.set_defaults(func=_docker_bake_gate)

    dockerfile = subparsers.add_parser(
        "dockerfile",
        help="Emit the agent-gate decision for a Dockerfile or Containerfile.",
    )
    dockerfile.add_argument("--framework", help="Include checks from a compliance framework.")
    dockerfile.add_argument("input_file", help="Path to a Dockerfile or Containerfile.")
    dockerfile.set_defaults(func=_dockerfile_gate)

    verify = subparsers.add_parser(
        "verify",
        help="Verify a signed rtp-evidence-v1 envelope.",
    )
    verify.add_argument(
        "--rekor-url",
        help="Rekor transparency log URL. Defaults to sigstore public.",
    )
    verify.add_argument(
        "--certificate-identity",
        help="Expected certificate identity (e.g., https://github.com/readtheplan/readtheplan/.github/workflows/release.yml@refs/tags/v0.3.0). When set, verification fails if the signer does not match.",  # noqa: E501
    )
    verify.add_argument(
        "--certificate-oidc-issuer",
        help="Expected OIDC issuer (e.g., https://token.actions.githubusercontent.com). Required when --certificate-identity is set.",  # noqa: E501
    )
    verify.add_argument("envelope", help="Path to evidence envelope JSON.")
    verify.set_defaults(func=_verify)

    mcp = subparsers.add_parser(
        "mcp",
        help="Start the experimental local MCP stdio server.",
    )
    mcp.set_defaults(func=_mcp)

    evolution_parser = subparsers.add_parser(
        "evolution",
        help="Manage the self-improving evolution engine.",
    )
    evolution_sub = evolution_parser.add_subparsers(dest="evolution_action", required=True)

    evolution_sub.add_parser(
        "status",
        help="Show evolution engine statistics and recent runs.",
    ).set_defaults(evolution_func=_evolution_status)

    evolution_sub.add_parser(
        "dashboard",
        help="Generate and open the HTML evolution dashboard.",
    ).set_defaults(evolution_func=_evolution_dashboard)

    evolution_sub.add_parser(
        "voice",
        help="Generate a voice brief summary of evolution status.",
    ).set_defaults(evolution_func=_evolution_voice)

    evolution_sub.add_parser(
        "patterns",
        help="List all detected patterns and their status.",
    ).set_defaults(evolution_func=_evolution_patterns)

    evolution_sub.add_parser(
        "runs",
        help="Show recent evolution run history.",
    ).set_defaults(evolution_func=_evolution_runs)

    evolution_sub.add_parser(
        "dispatch",
        help="Dispatch pending handoffs to the shared handoff directory.",
    ).set_defaults(evolution_func=_evolution_dispatch)

    evolution_sub.add_parser(
        "console",
        help="Display a terminal-based console dashboard.",
    ).set_defaults(evolution_func=_evolution_console)

    evolve_parser = subparsers.add_parser(
        "evolve",
        help="Review and explicitly approve generated evolution candidates.",
    )
    evolve_sub = evolve_parser.add_subparsers(dest="evolve_action", required=True)
    evolve_approve = evolve_sub.add_parser(
        "approve",
        help="Approve a verified candidate rule for loading on the next run.",
    )
    evolve_approve.add_argument("rule_id", help="Candidate rule ID shown by evolution output.")
    evolve_approve.set_defaults(evolution_func=_evolution_approve)

    return parser


def _framework_help_list() -> str:
    frameworks = available_frameworks()
    if not frameworks:
        return "none packaged"
    return ", ".join(frameworks)


def _default_agent_id() -> str:
    try:
        package_version = version("readtheplan")
    except PackageNotFoundError:
        package_version = "unknown"
    return f"readtheplan@{package_version}"


def _package_version(*, include_git: bool = True) -> str:
    try:
        pkg_version = version("readtheplan")
    except PackageNotFoundError:
        pkg_version = "unknown"

    if not include_git:
        return pkg_version

    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short=7", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=Path(__file__).resolve().parent.parent,
        )
        if commit.returncode == 0 and commit.stdout.strip():
            return f"{pkg_version} (git:{commit.stdout.strip()})"
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return pkg_version


def _analyze(args: argparse.Namespace) -> int:
    if args.sign and not args.evidence:
        print("Error: --sign requires --evidence", file=sys.stderr)
        return 1
    if args.evidence and not args.framework:
        print("Error: --evidence requires --framework", file=sys.stderr)
        return 1

    try:
        overlay_items = tuple(load_overlay(path) for path in args.rules_file)
    except OverlayError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    catalog: ControlCatalog | None = None
    if args.framework:
        try:
            catalog = load_catalog(args.framework)
            for overlay in overlay_items:
                catalog = apply_overlay_to_catalog(catalog, overlay)
        except (CatalogSchemaError, FrameworkNotFoundError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    try:
        plan_bytes = Path(args.plan_file).read_bytes()
        plan_data = json.loads(plan_bytes)
    except UnicodeDecodeError:
        print(
            f"Error: {args.plan_file} is not UTF-8 JSON. If this is a binary plan, "
            "run: terraform show -json tfplan > plan.json",
            file=sys.stderr,
        )
        return 1
    except json.JSONDecodeError as exc:
        print(
            f"Error: invalid JSON in {args.plan_file}:"
            f" line {exc.lineno}, column {exc.colno}: {exc.msg}",
            file=sys.stderr,
        )
        return 1
    except RecursionError:
        print(
            f"Error: {args.plan_file} contains deeply nested JSON that cannot be parsed. "
            "If this is a valid Terraform plan, consider reporting the issue.",
            file=sys.stderr,
        )
        return 1
    except FileNotFoundError:
        print(f"Error: plan file does not exist: {args.plan_file}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: cannot read plan file {args.plan_file}: {exc}", file=sys.stderr)
        return 1

    if not isinstance(plan_data, dict):
        print(
            f"Error: Terraform plan JSON must be an object (top-level dict), "
            f"got {type(plan_data).__name__}: {args.plan_file}",
            file=sys.stderr,
        )
        return 1

    try:
        summary = analyze_plan_file(
            plan_data,
            use_rules=not args.no_rules,
            _original_path=Path(args.plan_file),
        )
    except PlanError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        if overlay_items:
            summary = _apply_overlays_to_summary(
                summary,
                overlay_items,
                plan_account_id=_plan_account_id(args.plan_file, plan_data=plan_data),
            )
    except PlanError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.mode == "self-improving":
        gate = _agent_gate_payload(summary, catalog, mode=args.mode)
        suggested_rules = gate.get("evolution", {}).get("suggested_rules", [])
        if suggested_rules:
            print(
                f"Evolution suggested {len(suggested_rules)} candidate rule(s); "
                "run `readtheplan evolution patterns` for details.",
                file=sys.stderr,
            )

    if args.evidence:
        assert catalog is not None
        try:
            evidence = build_evidence(
                plan_summary=summary,
                plan_json=plan_bytes,
                catalog=catalog,
                agent_id=args.agent_id,
                reviewer=(
                    Reviewer(id=args.reviewer_id, kind=args.reviewer_kind)
                    if args.reviewer_id
                    else None
                ),
                run_id=args.run_id,
            )
            evidence_payload = (
                sign_envelope(
                    evidence,
                    oidc_issuer=args.oidc_issuer,
                    rekor_url=args.rekor_url,
                )
                if args.sign
                else evidence.to_dict()
            )
        except SigningError as exc:
            print(f"Error: sign failed: {exc}", file=sys.stderr)
            return 1
        except (EvidenceError, OSError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        if args.evidence == "-":
            json.dump(evidence_payload, sys.stdout, indent=2)
            print()
            return _fail_on_exit_code(summary, args.fail_on)

        try:
            Path(args.evidence).write_text(
                json.dumps(evidence_payload, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            print(
                f"Error: cannot write evidence file {args.evidence}: {exc}",
                file=sys.stderr,
            )
            return 1

    if args.format == "json":
        json.dump(_summary_to_dict(summary, catalog), sys.stdout, indent=2)
        print()
    else:
        _print_summary(summary, sys.stdout, catalog=catalog)
    return _fail_on_exit_code(summary, args.fail_on)


def _scan_project(args: argparse.Namespace) -> int:
    """Discover and aggregate infrastructure gates across one project tree."""
    from readtheplan.project_scan import ProjectScanError, scan_project

    if args.framework and _adapter_catalog(args.framework) is None:
        return 1
    try:
        gate = scan_project(
            Path(args.path),
            display_root=str(args.path),
            framework=args.framework,
            excludes=tuple(args.exclude),
            max_files=args.max_files,
            max_file_bytes=args.max_file_bytes,
        )
    except ProjectScanError as exc:
        print(f"Error: cannot scan project: {exc}", file=sys.stderr)
        return 1
    return _write_adapter_gate(gate)


def _fail_on_exit_code(summary: PlanSummary, threshold: str | None) -> int:
    if threshold is None:
        return 0

    threshold_rank = RISK_ORDER[threshold]
    count = sum(RISK_ORDER[change.risk] >= threshold_rank for change in summary.resource_changes)
    if count == 0:
        return 0

    print(
        f"fail-on: {count} change(s) at or above {threshold}",
        file=sys.stderr,
    )
    return 2


def _agent_gate(args: argparse.Namespace) -> int:
    catalog: ControlCatalog | None = None
    if args.framework:
        try:
            catalog = load_catalog(args.framework)
        except (CatalogSchemaError, FrameworkNotFoundError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    try:
        summary = analyze_plan_file(args.plan_file, use_rules=True)
    except PlanError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    gate = _agent_gate_payload(summary, catalog, mode=args.mode)
    json.dump(gate, sys.stdout, indent=2)
    print()
    decision = gate.get("decision", "warn")
    if decision == "block":
        return 2
    if decision == "warn":
        return 1
    return 0


def _agent_gate_payload(
    summary: PlanSummary,
    catalog: ControlCatalog | None,
    *,
    mode: str,
) -> dict[str, object]:
    """Build a gate payload, constructing evolution state only when requested."""
    evolution_engine = get_engine() if mode == "self-improving" else None
    return agent_gate_to_dict(
        summary,
        catalog,
        mode=mode,
        evolution_engine=evolution_engine,
    )


def _cloudformation_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for a CloudFormation Change Set / template diff."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.cloudformation import analyze_cloudformation

    try:
        data = json.loads(Path(args.input_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1

    if not isinstance(data, dict):
        print("Error: input must be a JSON object", file=sys.stderr)
        return 1

    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "cloudformation":
        detected = adapter.adapter_name if adapter else "none"
        print(
            f"Error: input not recognized as a supported IaC format (detected: {detected})",
            file=sys.stderr,
        )
        return 1

    catalog: ControlCatalog | None = None
    if args.framework:
        try:
            catalog = load_catalog(args.framework)
        except (CatalogSchemaError, FrameworkNotFoundError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    gate = analyze_cloudformation(data, catalog=catalog)
    json.dump(gate, sys.stdout, indent=2)
    print()
    decision = gate.get("decision", "warn")
    if decision == "block":
        return 2
    if decision == "warn":
        return 1
    return 0


def _cdk_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for AWS CDK synthesized manifests."""
    from readtheplan.adapters.cdk import (
        CdkAdapter,
        CdkInputError,
        analyze_cdk,
        parse_cdk_manifest,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_cdk_manifest(source)
    except CdkInputError as exc:
        print(f"Error: invalid AWS CDK manifest: {exc}", file=sys.stderr)
        return 1
    if not CdkAdapter().can_handle(data):
        print("Error: input not recognized as an AWS CDK manifest", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_cdk(data, catalog=catalog))


def _kubernetes_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for a Kubernetes manifest diff."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.kubernetes import (
        KubernetesInputError,
        analyze_kubernetes,
        parse_kubernetes_input,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_kubernetes_input(source)
    except KubernetesInputError as exc:
        print(f"Error: invalid Kubernetes input: {exc}", file=sys.stderr)
        return 1

    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "kubernetes":
        detected = adapter.adapter_name if adapter else "none"
        print(
            f"Error: input not recognized as a supported IaC format (detected: {detected})",
            file=sys.stderr,
        )
        return 1

    catalog: ControlCatalog | None = None
    if args.framework:
        try:
            catalog = load_catalog(args.framework)
        except (CatalogSchemaError, FrameworkNotFoundError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    gate = analyze_kubernetes(data, catalog=catalog)
    json.dump(gate, sys.stdout, indent=2)
    print()
    decision = gate.get("decision", "warn")
    if decision == "block":
        return 2
    if decision == "warn":
        return 1
    return 0


def _azure_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for Azure Bicep/ARM What-If JSON."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.azure import analyze_azure_whatif

    try:
        data = json.loads(Path(args.input_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print("Error: Azure What-If input must be a JSON object", file=sys.stderr)
        return 1

    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "azure":
        print("Error: input not recognized as Azure deployment What-If output", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_azure_whatif(data, catalog=catalog))


def _bicep_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for Azure Bicep source."""
    from readtheplan.adapters.bicep import (
        BicepAdapter,
        BicepInputError,
        analyze_bicep,
        parse_bicep_source,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_bicep_source(source)
    except BicepInputError as exc:
        print(f"Error: invalid Bicep source: {exc}", file=sys.stderr)
        return 1
    if not BicepAdapter().can_handle(data):
        print("Error: input not recognized as Azure Bicep source", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_bicep(data, catalog=catalog))


def _ansible_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for an Ansible playbook."""
    import yaml

    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.ansible import analyze_ansible

    try:
        documents = list(yaml.safe_load_all(Path(args.input_file).read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1

    plays: list[object] = []
    for document in documents:
        if isinstance(document, list):
            plays.extend(document)
        elif isinstance(document, dict):
            plays.append(document)
    data = {"plays": plays}
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "ansible":
        print("Error: input not recognized as an Ansible playbook", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_ansible(data, catalog=catalog))


def _ansible_project_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for Ansible project configuration."""
    from readtheplan.adapters.ansible_project import (
        AnsibleProjectAdapter,
        AnsibleProjectInputError,
        analyze_ansible_project,
        parse_ansible_project,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_ansible_project(source, filename=args.input_file)
    except AnsibleProjectInputError as exc:
        print(f"Error: invalid Ansible project input: {exc}", file=sys.stderr)
        return 1
    if not AnsibleProjectAdapter().can_handle(data):
        print("Error: input not recognized as Ansible project configuration", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_ansible_project(data, catalog=catalog))


def _pulumi_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for Pulumi preview output."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.pulumi import (
        PulumiPreviewError,
        analyze_pulumi,
        parse_pulumi_preview,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1

    try:
        data = parse_pulumi_preview(source)
    except PulumiPreviewError as exc:
        print(f"Error: invalid Pulumi preview JSON: {exc}", file=sys.stderr)
        return 1

    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "pulumi":
        print("Error: input not recognized as Pulumi preview output", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_pulumi(data, catalog=catalog))


def _pulumi_project_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for Pulumi project-side configuration."""
    from readtheplan.adapters.pulumi_project import (
        PulumiProjectAdapter,
        PulumiProjectInputError,
        analyze_pulumi_project,
        parse_pulumi_project,
    )

    path = Path(args.input_file)
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_pulumi_project(source, filename=path.name)
    except PulumiProjectInputError as exc:
        print(f"Error: invalid Pulumi project input: {exc}", file=sys.stderr)
        return 1
    if not PulumiProjectAdapter().can_handle(data):
        print("Error: input not recognized as Pulumi project configuration", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_pulumi_project(data, catalog=catalog))


def _jenkins_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for a Jenkinsfile."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.jenkins import analyze_jenkins

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1

    data = {"jenkinsfile": source}
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "jenkins":
        print("Error: input not recognized as a Jenkins pipeline", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_jenkins(data, catalog=catalog))


def _teamcity_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for TeamCity Kotlin DSL."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.teamcity import analyze_teamcity

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1

    data = {"teamcity": source}
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "teamcity":
        print("Error: input not recognized as TeamCity Kotlin DSL", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_teamcity(data, catalog=catalog))


def _jenkins_jcasc_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for Jenkins Configuration as Code YAML."""
    from readtheplan.adapters.jenkins_jcasc import (
        JenkinsJCasCAdapter,
        JenkinsJCasCInputError,
        analyze_jenkins_jcasc,
        parse_jenkins_jcasc,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_jenkins_jcasc(source)
    except JenkinsJCasCInputError as exc:
        print(f"Error: invalid Jenkins JCasC YAML: {exc}", file=sys.stderr)
        return 1
    if not JenkinsJCasCAdapter().can_handle(data):
        print("Error: input not recognized as Jenkins JCasC YAML", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_jenkins_jcasc(data, catalog=catalog))


def _chef_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for a Chef recipe."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.chef import analyze_chef

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    data = {"chef_recipe": source}
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "chef":
        print("Error: input not recognized as a Chef recipe", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_chef(data, catalog=catalog))


def _chef_project_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for Chef project policy and metadata."""
    from readtheplan.adapters.chef_project import (
        ChefProjectAdapter,
        ChefProjectInputError,
        analyze_chef_project,
        parse_chef_project,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_chef_project(source)
    except ChefProjectInputError as exc:
        print(f"Error: invalid Chef project input: {exc}", file=sys.stderr)
        return 1
    if not ChefProjectAdapter().can_handle(data):
        print("Error: input not recognized as Chef project configuration", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_chef_project(data, catalog=catalog))


def _puppet_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for a Puppet manifest."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.puppet import analyze_puppet

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    data = {"puppet_manifest": source}
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "puppet":
        print("Error: input not recognized as a Puppet manifest", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_puppet(data, catalog=catalog))


def _puppet_project_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for Puppet project and runtime configuration."""
    from readtheplan.adapters.puppet_project import (
        PuppetProjectAdapter,
        PuppetProjectInputError,
        analyze_puppet_project,
        parse_puppet_project,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_puppet_project(source, filename=args.input_file)
    except PuppetProjectInputError as exc:
        print(f"Error: invalid Puppet project input: {exc}", file=sys.stderr)
        return 1
    if not PuppetProjectAdapter().can_handle(data):
        print("Error: input not recognized as Puppet project configuration", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_puppet_project(data, catalog=catalog))


def _pipeline_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for supported CI workflow YAML."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.pipelines import (
        AzurePipelinesAdapter,
        BambooAdapter,
        BitbucketPipelinesAdapter,
        BuildkiteAdapter,
        CircleCIAdapter,
        ConcourseAdapter,
        DroneCIAdapter,
        GitHubActionsAdapter,
        GitLabCIAdapter,
        PipelineInputError,
        TravisCIAdapter,
        WoodpeckerCIAdapter,
        analyze_pipeline,
        parse_pipeline_yaml,
    )

    adapters = {
        "github-actions": GitHubActionsAdapter,
        "gitlab-ci": GitLabCIAdapter,
        "circleci": CircleCIAdapter,
        "azure-pipelines": AzurePipelinesAdapter,
        "bitbucket-pipelines": BitbucketPipelinesAdapter,
        "buildkite": BuildkiteAdapter,
        "travis-ci": TravisCIAdapter,
        "drone-ci": DroneCIAdapter,
        "woodpecker-ci": WoodpeckerCIAdapter,
        "concourse": ConcourseAdapter,
        "bamboo": BambooAdapter,
    }
    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_pipeline_yaml(source, args.command)
    except PipelineInputError as exc:
        print(f"Error: invalid {args.command} pipeline YAML: {exc}", file=sys.stderr)
        return 1

    adapter = detect_adapter(data)
    expected = adapters[args.command]
    if adapter is None or not isinstance(adapter, expected):
        print(f"Error: input not recognized as {args.command} configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_pipeline(adapter, data, catalog=catalog))


def _cloud_ci_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for cloud-native CI/CD configuration."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.cloud_ci import (
        CloudCIInputError,
        CodeBuildAdapter,
        CodePipelineAdapter,
        GoogleCloudBuildAdapter,
        analyze_cloud_ci,
        parse_cloud_ci,
    )

    adapters = {
        "codebuild": CodeBuildAdapter,
        "cloud-build": GoogleCloudBuildAdapter,
        "codepipeline": CodePipelineAdapter,
    }
    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_cloud_ci(source, args.command)
    except CloudCIInputError as exc:
        print(f"Error: invalid {args.command} configuration: {exc}", file=sys.stderr)
        return 1

    adapter = detect_adapter(data)
    expected = adapters[args.command]
    if adapter is None or not isinstance(adapter, expected):
        print(f"Error: input not recognized as {args.command} configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_cloud_ci(adapter, data, catalog=catalog))


def _atlantis_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Atlantis repo-level or server-side YAML."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.atlantis import (
        AtlantisInputError,
        analyze_atlantis,
        parse_atlantis_config,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_atlantis_config(source)
    except AtlantisInputError as exc:
        print(f"Error: invalid Atlantis configuration: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "atlantis":
        print("Error: input not recognized as Atlantis configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_atlantis(data, catalog=catalog))


def _workload_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for Compose and Nomad artifacts."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.workloads import (
        DockerComposeAdapter,
        NomadPlanAdapter,
        WorkloadInputError,
        analyze_workload,
        parse_docker_compose,
        parse_nomad,
    )

    adapters = {
        "docker-compose": (DockerComposeAdapter, parse_docker_compose),
        "nomad": (NomadPlanAdapter, parse_nomad),
    }
    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    expected, parser = adapters[args.command]
    try:
        data = parser(source)
    except WorkloadInputError as exc:
        print(f"Error: invalid {args.command} input: {exc}", file=sys.stderr)
        return 1

    adapter = detect_adapter(data)
    if adapter is None or not isinstance(adapter, expected):
        print(f"Error: input not recognized as {args.command} configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_workload(adapter, data, catalog=catalog))


def _packer_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for Packer template or inspect output."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.packer import (
        PackerInspectError,
        analyze_packer,
        parse_packer,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_packer(source)
    except PackerInspectError as exc:
        print(f"Error: invalid Packer input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "packer":
        print("Error: input not recognized as Packer template or inspect output", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_packer(data, catalog=catalog))


def _skaffold_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for Skaffold configuration."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.skaffold import SkaffoldInputError, analyze_skaffold, parse_skaffold

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_skaffold(source)
    except SkaffoldInputError as exc:
        print(f"Error: invalid Skaffold input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "skaffold":
        print("Error: input not recognized as Skaffold configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_skaffold(data, catalog=catalog))


def _devspace_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for DevSpace configuration."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.devspace import (
        DevSpaceInputError,
        analyze_devspace,
        parse_devspace,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_devspace(source)
    except DevSpaceInputError as exc:
        print(f"Error: invalid DevSpace input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "devspace":
        print("Error: input not recognized as DevSpace configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_devspace(data, catalog=catalog))


def _tiltfile_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for Tiltfile source."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.tiltfile import (
        TiltfileInputError,
        analyze_tiltfile,
        parse_tiltfile,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_tiltfile(source)
    except TiltfileInputError as exc:
        print(f"Error: invalid Tiltfile input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "tilt":
        print("Error: input not recognized as Tiltfile configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_tiltfile(data, catalog=catalog))


def _cue_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for CUE source."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.cue import CueInputError, analyze_cue, parse_cue

    path = Path(args.input_file)
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_cue(source, path.name)
    except CueInputError as exc:
        print(f"Error: invalid CUE input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "cue":
        print("Error: input not recognized as CUE configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_cue(data, catalog=catalog))


def _jsonnet_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for Jsonnet and Tanka artifacts."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.jsonnet import JsonnetInputError, analyze_jsonnet, parse_jsonnet

    path = Path(args.input_file)
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_jsonnet(source, path.name)
    except JsonnetInputError as exc:
        print(f"Error: invalid Jsonnet/Tanka input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "jsonnet":
        print("Error: input not recognized as Jsonnet/Tanka configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_jsonnet(data, catalog=catalog))


def _helmfile_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for Helmfile state and lock files."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.helmfile import (
        HelmfileInputError,
        analyze_helmfile,
        parse_helmfile,
    )

    path = Path(args.input_file)
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_helmfile(source, path.name)
    except HelmfileInputError as exc:
        print(f"Error: invalid Helmfile input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "helmfile":
        print("Error: input not recognized as Helmfile configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_helmfile(data, catalog=catalog))


def _terramate_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for Terramate configuration."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.terramate import (
        TerramateInputError,
        analyze_terramate,
        parse_terramate,
    )

    path = Path(args.input_file)
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_terramate(source, path.name)
    except TerramateInputError as exc:
        print(f"Error: invalid Terramate input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "terramate":
        print("Error: input not recognized as Terramate configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_terramate(data, catalog=catalog))


def _carvel_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for the Carvel tool family."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.carvel import CarvelInputError, analyze_carvel, parse_carvel

    path = Path(args.input_file)
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_carvel(source, path.name)
    except CarvelInputError as exc:
        print(f"Error: invalid Carvel input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "carvel":
        print("Error: input not recognized as Carvel configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_carvel(data, catalog=catalog))


def _spacelift_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for Spacelift runtime configuration."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.spacelift import (
        SpaceliftInputError,
        analyze_spacelift,
        parse_spacelift,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_spacelift(source)
    except SpaceliftInputError as exc:
        print(f"Error: invalid Spacelift input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "spacelift":
        print("Error: input not recognized as Spacelift runtime configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_spacelift(data, catalog=catalog))


def _salt_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for a Salt SLS state file."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.salt import SaltInputError, analyze_salt, parse_salt_sls

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_salt_sls(source)
    except SaltInputError as exc:
        print(f"Error: invalid Salt SLS input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "salt":
        print("Error: input not recognized as a Salt SLS state", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_salt(data, catalog=catalog))


def _salt_project_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for Salt project configuration."""
    from readtheplan.adapters.salt_project import (
        SaltProjectAdapter,
        SaltProjectInputError,
        analyze_salt_project,
        parse_salt_project,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_salt_project(source)
    except SaltProjectInputError as exc:
        print(f"Error: invalid Salt project input: {exc}", file=sys.stderr)
        return 1
    if not SaltProjectAdapter().can_handle(data):
        print("Error: input not recognized as Salt project configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_salt_project(data, catalog=catalog))


def _nix_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for Nix flakes, locks, and NixOS modules."""
    from readtheplan.adapters.nix import (
        NixInputError,
        NixProjectAdapter,
        analyze_nix_project,
        parse_nix_project,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_nix_project(source)
    except NixInputError as exc:
        print(f"Error: invalid Nix input: {exc}", file=sys.stderr)
        return 1
    if not NixProjectAdapter().can_handle(data):
        print("Error: input not recognized as Nix project data", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_nix_project(data, catalog=catalog))


def _dsc_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for DSC configuration."""
    from readtheplan.adapters.dsc import (
        DscAdapter,
        DscInputError,
        analyze_dsc,
        parse_dsc,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_dsc(source)
    except DscInputError as exc:
        print(f"Error: invalid DSC input: {exc}", file=sys.stderr)
        return 1
    if not DscAdapter().can_handle(data):
        print("Error: input not recognized as DSC configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_dsc(data, catalog=catalog))


def _cfengine_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for CFEngine policy or Augments data."""
    from readtheplan.adapters.cfengine import (
        CFEngineAdapter,
        CFEngineInputError,
        analyze_cfengine,
        parse_cfengine,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_cfengine(source)
    except CFEngineInputError as exc:
        print(f"Error: invalid CFEngine input: {exc}", file=sys.stderr)
        return 1
    if not CFEngineAdapter().can_handle(data):
        print("Error: input not recognized as CFEngine configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_cfengine(data, catalog=catalog))


def _opa_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for standalone OPA/Rego configuration."""
    from readtheplan.adapters.opa import OPAAdapter, OPAInputError, analyze_opa, parse_opa

    path = Path(args.input_file)
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_opa(source, path.name)
    except OPAInputError as exc:
        print(f"Error: invalid OPA/Rego input: {exc}", file=sys.stderr)
        return 1
    if not OPAAdapter().can_handle(data):
        print("Error: input not recognized as OPA/Rego configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_opa(data, catalog=catalog))


def _sentinel_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for Sentinel policy or configuration."""
    from readtheplan.adapters.sentinel import (
        SentinelAdapter,
        SentinelInputError,
        analyze_sentinel,
        parse_sentinel,
    )

    path = Path(args.input_file)
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_sentinel(source, path.name)
    except SentinelInputError as exc:
        print(f"Error: invalid Sentinel input: {exc}", file=sys.stderr)
        return 1
    if not SentinelAdapter().can_handle(data):
        print("Error: input not recognized as Sentinel policy or configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_sentinel(data, catalog=catalog))


def _sops_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for SOPS policy or encrypted data."""
    from readtheplan.adapters.sops import SOPSAdapter, SOPSInputError, analyze_sops, parse_sops

    path = Path(args.input_file)
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_sops(source, path.name)
    except SOPSInputError as exc:
        print(f"Error: invalid SOPS input: {exc}", file=sys.stderr)
        return 1
    if not SOPSAdapter().can_handle(data):
        print("Error: input not recognized as SOPS policy or encrypted data", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_sops(data, catalog=catalog))


def _vagrant_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for a Vagrantfile."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.vagrant import (
        VagrantInputError,
        analyze_vagrant,
        parse_vagrantfile,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_vagrantfile(source)
    except VagrantInputError as exc:
        print(f"Error: invalid Vagrantfile input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "vagrant":
        print("Error: input not recognized as a Vagrantfile", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_vagrant(data, catalog=catalog))


def _cloud_init_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for cloud-init user-data."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.cloud_init import (
        CloudInitInputError,
        analyze_cloud_init,
        parse_cloud_init,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_cloud_init(source)
    except CloudInitInputError as exc:
        print(f"Error: invalid cloud-init input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "cloud-init":
        print("Error: input not recognized as cloud-init user-data", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_cloud_init(data, catalog=catalog))


def _systemd_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for a systemd unit file."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.systemd import (
        SystemdUnitInputError,
        analyze_systemd,
        parse_systemd_unit,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_systemd_unit(source)
    except SystemdUnitInputError as exc:
        print(f"Error: invalid systemd unit input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "systemd":
        print("Error: input not recognized as a systemd unit", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_systemd(data, catalog=catalog))


def _traefik_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Traefik YAML, JSON, or TOML."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.traefik import (
        TraefikInputError,
        analyze_traefik,
        parse_traefik_config,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_traefik_config(source)
    except TraefikInputError as exc:
        print(f"Error: invalid Traefik configuration: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "traefik":
        print("Error: input not recognized as Traefik configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_traefik(data, catalog=catalog))


def _grafana_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Grafana INI or provisioning YAML/JSON."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.grafana import (
        GrafanaInputError,
        analyze_grafana,
        parse_grafana_config,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_grafana_config(source)
    except GrafanaInputError as exc:
        print(f"Error: invalid Grafana configuration: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "grafana":
        print("Error: input not recognized as Grafana configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_grafana(data, catalog=catalog))


def _hashicorp_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Vault or Consul HCL/JSON configuration."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.hashicorp import (
        HashiCorpInputError,
        analyze_hashicorp,
        parse_hashicorp_config,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_hashicorp_config(source, args.command)
    except HashiCorpInputError as exc:
        print(f"Error: invalid {args.command} configuration: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != args.command:
        print(f"Error: input not recognized as {args.command} configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_hashicorp(data, catalog=catalog))


def _loki_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Grafana Loki YAML configuration."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.loki import LokiInputError, analyze_loki, parse_loki_config

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_loki_config(source)
    except LokiInputError as exc:
        print(f"Error: invalid Loki configuration: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "loki":
        print("Error: input not recognized as Loki configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_loki(data, catalog=catalog))


def _caddy_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Caddyfile or native Caddy JSON."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.caddy import CaddyInputError, analyze_caddy, parse_caddy_config

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_caddy_config(source)
    except CaddyInputError as exc:
        print(f"Error: invalid Caddy configuration: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "caddy":
        print("Error: input not recognized as Caddy configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_caddy(data, catalog=catalog))


def _terraform_config_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Terraform config or Terragrunt HCL/JSON."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.terraform_config import (
        TerraformConfigInputError,
        analyze_terraform_config,
        parse_terraform_config,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_terraform_config(source, args.command)
    except TerraformConfigInputError as exc:
        print(f"Error: invalid {args.command} configuration: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != args.command:
        print(f"Error: input not recognized as {args.command} configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_terraform_config(data, catalog=catalog))


def _terraform_lock_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for a Terraform/OpenTofu lock file."""
    from readtheplan.adapters.terraform_lock import (
        TerraformLockAdapter,
        TerraformLockInputError,
        analyze_terraform_lock,
        parse_terraform_lock,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_terraform_lock(source)
    except TerraformLockInputError as exc:
        print(f"Error: invalid Terraform/OpenTofu lock input: {exc}", file=sys.stderr)
        return 1
    if not TerraformLockAdapter().can_handle(data):
        print("Error: input not recognized as a dependency lock file", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_terraform_lock(data, catalog=catalog))


def _terraform_state_gate(args: argparse.Namespace) -> int:
    """Emit the gate contract for saved Terraform/OpenTofu state JSON."""
    from readtheplan.adapters.terraform_state import (
        TerraformStateAdapter,
        TerraformStateInputError,
        analyze_terraform_state,
        parse_terraform_state,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_terraform_state(source)
    except TerraformStateInputError as exc:
        print(f"Error: invalid Terraform/OpenTofu state: {exc}", file=sys.stderr)
        return 1
    if not TerraformStateAdapter().can_handle(data):
        print("Error: input not recognized as Terraform/OpenTofu state", file=sys.stderr)
        return 1

    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_terraform_state(data, catalog=catalog))


def _helm_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Helm chart metadata, values, or template source."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.helm import HelmInputError, analyze_helm, parse_helm_source

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_helm_source(source)
    except HelmInputError as exc:
        print(f"Error: invalid Helm source: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "helm":
        print("Error: input not recognized as Helm source", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_helm(data, catalog=catalog))


def _kustomize_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Kustomize source configuration."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.kustomize import (
        KustomizeInputError,
        analyze_kustomize,
        parse_kustomization,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_kustomization(source)
    except KustomizeInputError as exc:
        print(f"Error: invalid Kustomize source: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "kustomize":
        print("Error: input not recognized as Kustomize source", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_kustomize(data, catalog=catalog))


def _crossplane_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Crossplane package and resource source."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.crossplane import (
        CrossplaneInputError,
        analyze_crossplane,
        parse_crossplane_input,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_crossplane_input(source)
    except CrossplaneInputError as exc:
        print(f"Error: invalid Crossplane source: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "crossplane":
        print("Error: input not recognized as Crossplane source", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_crossplane(data, catalog=catalog))


def _serverless_source_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Serverless Framework or AWS SAM source."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.serverless import (
        ServerlessInputError,
        analyze_sam,
        analyze_serverless,
        parse_sam_template,
        parse_serverless_source,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    parser = parse_serverless_source if args.command == "serverless" else parse_sam_template
    try:
        data = parser(source)
    except ServerlessInputError as exc:
        print(f"Error: invalid {args.command} source: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != args.command:
        print(f"Error: input not recognized as {args.command} source", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    analyze = analyze_serverless if args.command == "serverless" else analyze_sam
    return _write_adapter_gate(analyze(data, catalog=catalog))


def _otel_collector_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for OpenTelemetry Collector YAML."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.otel_collector import (
        OTelCollectorInputError,
        analyze_otel_collector,
        parse_otel_collector_config,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_otel_collector_config(source)
    except OTelCollectorInputError as exc:
        print(f"Error: invalid OpenTelemetry Collector configuration: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "otel-collector":
        print("Error: input not recognized as Collector configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_otel_collector(data, catalog=catalog))


def _monitoring_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Prometheus or Alertmanager YAML."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.monitoring import (
        MonitoringInputError,
        analyze_monitoring,
        parse_monitoring_config,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_monitoring_config(source, args.command)
    except MonitoringInputError as exc:
        print(f"Error: invalid {args.command} configuration: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != args.command:
        print(f"Error: input not recognized as {args.command} configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_monitoring(data, catalog=catalog))


def _envoy_gate(args: argparse.Namespace) -> int:
    """Emit the shared gate for Envoy bootstrap or config_dump data."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.envoy import EnvoyInputError, analyze_envoy, parse_envoy_config

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_envoy_config(source)
    except EnvoyInputError as exc:
        print(f"Error: invalid Envoy configuration: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "envoy":
        print("Error: input not recognized as Envoy configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_envoy(data, catalog=catalog))


def _proxy_config_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for NGINX or HAProxy configuration."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.proxy_configs import (
        ProxyConfigInputError,
        analyze_proxy_config,
        parse_haproxy_config,
        parse_nginx_config,
    )

    ecosystem = args.command
    parser = parse_nginx_config if ecosystem == "nginx" else parse_haproxy_config
    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parser(source)
    except ProxyConfigInputError as exc:
        print(f"Error: invalid {ecosystem} configuration: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != ecosystem:
        print(f"Error: input not recognized as {ecosystem} configuration", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_proxy_config(data, catalog=catalog))


def _docker_bake_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for Docker Buildx Bake."""
    from readtheplan.adapters.docker_bake import (
        DockerBakeAdapter,
        DockerBakeInputError,
        analyze_docker_bake,
        parse_docker_bake,
    )

    path = Path(args.input_file)
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_docker_bake(source, path.name)
    except DockerBakeInputError as exc:
        print(f"Error: invalid Docker Bake input: {exc}", file=sys.stderr)
        return 1
    if not DockerBakeAdapter().can_handle(data):
        print("Error: input not recognized as Docker Buildx Bake", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_docker_bake(data, catalog=catalog))


def _terraform_stack_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for Terraform Stacks."""
    from readtheplan.adapters.terraform_stack import (
        TerraformStackAdapter,
        TerraformStackInputError,
        analyze_terraform_stack,
        parse_terraform_stack,
    )

    path = Path(args.input_file)
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_terraform_stack(source, path.name)
    except TerraformStackInputError as exc:
        print(f"Error: invalid Terraform Stack input: {exc}", file=sys.stderr)
        return 1
    if not TerraformStackAdapter().can_handle(data):
        print("Error: input not recognized as Terraform Stacks", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_terraform_stack(data, catalog=catalog))


def _dockerfile_gate(args: argparse.Namespace) -> int:
    """Emit the shared agent-gate contract for a Dockerfile/Containerfile."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.dockerfile import (
        DockerfileInputError,
        analyze_dockerfile,
        parse_dockerfile,
    )

    try:
        source = Path(args.input_file).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1
    try:
        data = parse_dockerfile(source)
    except DockerfileInputError as exc:
        print(f"Error: invalid Dockerfile input: {exc}", file=sys.stderr)
        return 1
    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "dockerfile":
        print("Error: input not recognized as a Dockerfile", file=sys.stderr)
        return 1
    catalog = _adapter_catalog(args.framework)
    if args.framework and catalog is None:
        return 1
    return _write_adapter_gate(analyze_dockerfile(data, catalog=catalog))


def _adapter_catalog(framework: str | None) -> ControlCatalog | None:
    if not framework:
        return None
    try:
        return load_catalog(framework)
    except (CatalogSchemaError, FrameworkNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return None


def _write_adapter_gate(gate: dict[str, Any]) -> int:
    json.dump(gate, sys.stdout, indent=2)
    print()
    decision = gate.get("decision", "warn")
    if decision == "block":
        return 2
    if decision == "warn":
        return 1
    return 0


def _verify(args: argparse.Namespace) -> int:
    try:
        envelope_bytes = Path(args.envelope).read_bytes()
    except OSError as exc:
        print(f"Error: cannot read envelope file {args.envelope}: {exc}", file=sys.stderr)
        return 1

    if not args.certificate_identity or not args.certificate_oidc_issuer:
        print(
            "Error: --certificate-identity and --certificate-oidc-issuer are both required "
            "for identity verification.",
            file=sys.stderr,
        )
        return 1

    try:
        result = verify_envelope(
            envelope_bytes,
            rekor_url=args.rekor_url,
            certificate_identity=args.certificate_identity,
            certificate_oidc_issuer=args.certificate_oidc_issuer,
        )
    except VerificationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if result.ok:
        print(
            "OK "
            f"identity={result.identity} "
            f"issuer={result.oidc_issuer} "
            f"rekor_uuid={result.rekor_uuid}"
        )
        return 0

    print(f"FAIL {result.reason}", file=sys.stderr)
    return 1


def _mcp(args: argparse.Namespace) -> int:
    try:
        from readtheplan.mcp_server import MissingMCPDependencyError
        from readtheplan.mcp_server import main as mcp_main

        mcp_main()
    except MissingMCPDependencyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


def _apply_overlays_to_summary(
    summary: PlanSummary,
    overlays: Sequence[Overlay],
    *,
    plan_account_id: str | None,
) -> PlanSummary:
    changes = []
    for change in summary.resource_changes:
        out = change
        for overlay in overlays:
            out = apply_overlay_to_change(
                out,
                overlay,
                plan_account_id=plan_account_id,
            )
        changes.append(out)

    return PlanSummary(
        path=summary.path,
        terraform_version=summary.terraform_version,
        resource_changes=tuple(changes),
    )


def _plan_account_id(plan_file: str | Path, plan_data: dict | None = None) -> str | None:
    data = plan_data if plan_data is not None else load_plan(plan_file)
    for key in ("account_id", "aws_account_id"):
        value = data.get(key)
        if value is not None:
            return str(value)

    variables = data.get("variables")
    if isinstance(variables, dict):
        for key in ("account_id", "aws_account_id"):
            raw = variables.get(key)
            if isinstance(raw, dict) and raw.get("value") is not None:
                return str(raw["value"])
    return None


def _summary_to_dict(
    summary: PlanSummary,
    catalog: ControlCatalog | None,
) -> dict[str, object]:
    return summary_to_dict(summary, catalog)


def _print_summary(
    summary: PlanSummary,
    stream: TextIO,
    *,
    catalog: ControlCatalog | None = None,
) -> None:
    print(f"# readtheplan summary: {summary.path}", file=stream)
    if summary.terraform_version:
        print(f"Terraform version: {summary.terraform_version}", file=stream)

    print(f"Resource changes: {len(summary.resource_changes)}", file=stream)
    if not summary.resource_changes:
        print("No resource changes found.", file=stream)
        return

    print("", file=stream)
    print("## Actions", file=stream)
    for action, count in sorted(summary.action_counts.items()):
        print(f"- {action}: {count}", file=stream)

    print("", file=stream)
    print("## Risk", file=stream)
    for risk, count in sorted(summary.risk_counts.items()):
        print(f"- {risk}: {count}", file=stream)

    print("", file=stream)
    print("## Changes", file=stream)
    if catalog is None:
        print("| Risk | Actions | Resource | Type | Explanation |", file=stream)
        print("| --- | --- | --- | --- | --- |", file=stream)
    else:
        print("| Risk | Actions | Resource | Type | Explanation | Controls |", file=stream)
        print("| --- | --- | --- | --- | --- | --- |", file=stream)
    for change in summary.resource_changes:
        actions = "/".join(change.actions)
        row = (
            f"| {change.risk} | {actions} | {change.address} | "
            f"{change.resource_type} | {change.explanation}"
        )
        if catalog is not None:
            controls = catalog.controls_for(
                resource_type=change.resource_type,
                actions=change.actions,
            )
            row = f"{row} | {', '.join(control.id for control in controls)}"
        print(f"{row} |", file=stream)


# ── Evolution handlers ────────────────────────────────────────────


def _evolution_status(args: argparse.Namespace) -> int:
    """Show evolution engine statistics."""
    engine = get_engine()
    stats = engine.get_stats()
    print(json.dumps(stats, indent=2))
    return 0


def _evolution_dashboard(args: argparse.Namespace) -> int:
    """Generate and report the dashboard path."""
    engine = get_engine()
    path = engine.generate_html_dashboard()
    print(f"Dashboard generated: {path}")
    return 0


def _evolution_voice(args: argparse.Namespace) -> int:
    """Generate a voice brief (text output)."""
    engine = get_engine()
    brief = engine.generate_voice_brief(style="concise")
    print(brief)
    return 0


def _evolution_patterns(args: argparse.Namespace) -> int:
    """List all detected patterns."""
    engine = get_engine()
    patterns = engine.get_all_patterns()
    if not patterns:
        print("No patterns yet. Run the gate with --mode self-improving on some plans first.")
        return 0
    print(json.dumps(patterns, indent=2))
    return 0


def _evolution_runs(args: argparse.Namespace) -> int:
    """Show recent runs."""
    engine = get_engine()
    runs = engine.get_recent_runs()
    if not runs:
        print("No runs recorded yet.")
        return 0
    print(json.dumps(runs, indent=2))
    return 0


def _evolution_dispatch(args: argparse.Namespace) -> int:
    """Dispatch pending handoffs to the shared handoff directory."""
    engine = get_engine()
    dispatched = engine.dispatch_handoffs()
    if not dispatched:
        print("No pending handoffs to dispatch.")
    else:
        print(f"Successfully dispatched {len(dispatched)} handoff(s):")
        for hid in dispatched:
            print(f"  - {hid}")
    return 0


def _evolution_approve(args: argparse.Namespace) -> int:
    """Explicitly approve a verified evolution candidate."""
    engine = get_engine()
    try:
        approved = engine.approve_rule(args.rule_id)
    except (FileNotFoundError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(
        f"Approved {approved['rule_id']} ({approved['sha256'][:12]}). "
        "It will load on the next readtheplan run."
    )
    return 0


def _evolution_console(args: argparse.Namespace) -> int:
    """Display a terminal-based console dashboard."""
    engine = get_engine()
    stats = engine.get_stats()
    patterns = engine.get_all_patterns()
    runs = engine.get_recent_runs(limit=5)

    print("=" * 60)
    print("      ⚡ READTHEPLAN EVOLUTION CONSOLE DASHBOARD ⚡")
    print("=" * 60)
    avg = stats["avg_compliance_score"]
    print(f" Total Runs: {stats['total_runs']:<8} | Avg Compliance Score: {avg:.1f}%")
    print(f" Blocked:    {stats['blocked']:<8} | Warned:               {stats['warned']}")
    print(f" Incidents:  {stats['total_incidents']:<8} | Patterns: {stats['total_patterns']}")
    print(f" Approved Rules: {stats['approved_rules']}")
    print("-" * 60)
    print(" DETECTED PATTERNS")
    print("-" * 60)
    if not patterns:
        print("  No patterns detected yet.")
    else:
        print(f"  {'Resource Type':<25} {'Risk':<12} {'Count':<8} {'Status':<12}")
        print(f"  {'-' * 25} {'-' * 12} {'-' * 8} {'-' * 12}")
        for p in patterns[:10]:
            print(
                f"  {p['resource_type']:<25} {p['risk']:<12} "
                f"{p['incident_count']:<8} {p['rule_status']:<12}"
            )
        if len(patterns) > 10:
            print(f"  ... and {len(patterns) - 10} more patterns.")
    print("-" * 60)
    print(" RECENT RUNS")
    print("-" * 60)
    if not runs:
        print("  No runs recorded yet.")
    else:
        print(f"  {'Timestamp':<22} {'Decision':<12} {'Score':<8} {'Outcome':<8}")
        print(f"  {'-' * 22} {'-' * 12} {'-' * 8} {'-' * 8}")
        for r in runs:
            ts = r["timestamp"][:19].replace("T", " ")
            print(f"  {ts:<22} {r['decision']:<12} {r['compliance_score']:<8.1f} {r['outcome']:<8}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
