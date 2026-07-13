from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.cli import main
from readtheplan.project_scan import (
    ProjectScanError,
    _looks_like_ansible_inventory_yaml,
    _project_pr_comment,
    discover_project_inputs,
    identify_project_input,
    scan_project,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("relative", "tool"),
    [
        (".terraform.lock.hcl", "terraform-lock"),
        ("live/prod/terragrunt.hcl", "terragrunt"),
        (".spacelift/config.yml", "spacelift"),
        ("cdk.out/manifest.json", "cdk"),
        ("Pulumi.production.yaml", "pulumi-project"),
        ("ansible.cfg", "ansible-project"),
        ("inventory/hosts.ini", "ansible-project"),
        ("inventories/prod/inventory.yml", "ansible-project"),
        ("inventory/prod.aws_ec2.yml", "ansible-project"),
        ("ansible/collections/requirements.yml", "ansible-project"),
        ("execution-environment.yml", "ansible-project"),
        ("ansible-navigator.yml", "ansible-project"),
        (".ansible-navigator.json", "ansible-project"),
        ("molecule/default/molecule.yml", "ansible-project"),
        (".config/molecule/config.yml", "ansible-project"),
        ("galaxy.yml", "ansible-project"),
        ("collections/demo/meta/runtime.yml", "ansible-project"),
        ("roles/demo/meta/main.yml", "ansible-project"),
        ("roles/demo/meta/argument_specs.yml", "ansible-project"),
        (".ansible-lint", "ansible-project"),
        ("Jenkinsfile.deploy", "jenkins"),
        ("plugins.txt", "jenkins-project"),
        ("jenkins/plugins.yaml", "jenkins-project"),
        ("cookbooks/base/recipes/default.rb", "chef"),
        ("client.rb", "chef-project"),
        (".chef/config.rb", "chef-project"),
        ("chef/chef-server.rb", "chef-project"),
        ("cookbooks/base/Berksfile", "chef-project"),
        ("cookbooks/base/Berksfile.lock", "chef-project"),
        ("chef/client.d/security.rb", "chef-project"),
        ("cookbooks/base/.kitchen.yml", "chef-project"),
        ("cookbooks/base/kitchen.local.yaml", "chef-project"),
        ("profiles/linux/inspec.yml", "inspec"),
        ("profiles/linux/inspec.lock", "inspec"),
        ("profiles/linux/waivers.yml", "inspec"),
        ("manifests/site.pp", "puppet"),
        ("puppet/puppet.conf", "puppet-project"),
        ("puppet/r10k.yaml", "puppet-project"),
        ("environments/production/environment.conf", "puppet-project"),
        ("puppet/puppetdb.conf", "puppet-project"),
        ("puppetserver/conf.d/puppetserver.conf", "puppet-project"),
        ("puppetserver/conf.d/auth.conf", "puppet-project"),
        ("puppetserver/conf.d/ca.conf", "puppet-project"),
        ("puppetserver/conf.d/webserver.conf", "puppet-project"),
        ("puppetserver/conf.d/web-routes.conf", "puppet-project"),
        ("bolt-project.yaml", "puppet-project"),
        ("bolt/inventory.yaml", "puppet-project"),
        ("states/web.sls", "salt"),
        ("flake.nix", "nix"),
        ("policy/main.rego", "opa"),
        (".sops.yaml", "sops"),
        ("secrets/production.sops.yaml", "sops"),
        ("secrets/production.sops.json", "sops"),
        ("secrets/production.sops.env", "sops"),
        ("secrets/production.sops.ini", "sops"),
        ("Vagrantfile", "vagrant"),
        ("docker-bake.hcl", "docker-bake"),
        ("docker-bake.override.json", "docker-bake"),
        ("Dockerfile.production", "dockerfile"),
        ("compose.yaml", "docker-compose"),
        (".github/workflows/deploy.yml", "github-actions"),
        (".gitlab-ci.yml", "gitlab-ci"),
        (".travis.yml", "travis-ci"),
        (".drone.yml", "drone-ci"),
        (".woodpecker.yml", "woodpecker-ci"),
        (".woodpecker/deploy.yaml", "woodpecker-ci"),
        ("bamboo-specs/bamboo.yml", "bamboo"),
        (".concourse/pipeline.yml", "concourse"),
        (".teamcity/settings.kts", "teamcity"),
        ("buildspec.yml", "codebuild"),
        ("ci/buildspec-release.yaml", "codebuild"),
        ("cloudbuild.yaml", "cloud-build"),
        ("codepipeline.json", "codepipeline"),
        ("Chart.yaml", "helm"),
        ("kustomization.yaml", "kustomize"),
        ("helmfile.yaml.gotmpl", "helmfile"),
        ("skaffold.yaml", "skaffold"),
        ("devspace.yaml", "devspace"),
        ("Tiltfile", "tilt"),
        ("deploy.cue", "cue"),
        ("main.jsonnet", "jsonnet"),
        ("environments/prod/main.jsonnet", "tanka"),
        ("vendir.yml", "vendir"),
        ("serverless.yml", "serverless"),
        ("service.nomad.hcl", "nomad"),
        ("image.pkr.hcl", "packer"),
        ("main.bicep", "bicep"),
        ("api.service", "systemd"),
        ("nginx.conf", "nginx"),
        ("prometheus.yml", "prometheus"),
        ("infra/main.tf", "terraform-config"),
    ],
)
def test_high_confidence_filename_detection(relative: str, tool: str) -> None:
    assert identify_project_input(Path(relative), relative) == tool


def test_content_detection_for_kubernetes_ansible_and_terraform(tmp_path: Path) -> None:
    kubernetes = tmp_path / "deployment.yml"
    kubernetes.write_text("apiVersion: apps/v1\nkind: Deployment\n", encoding="utf-8")
    ansible = tmp_path / "site.yml"
    ansible.write_text("- hosts: all\n  tasks:\n    - debug: {}\n", encoding="utf-8")
    terraform = tmp_path / "plan.json"
    terraform.write_text(
        json.dumps({"format_version": "1.2", "resource_changes": []}),
        encoding="utf-8",
    )
    assert identify_project_input(kubernetes, kubernetes.name) == "kubernetes"
    assert identify_project_input(ansible, ansible.name) == "ansible"
    assert identify_project_input(terraform, terraform.name) == "terraform"


def test_generic_auth_and_webserver_names_require_puppet_context() -> None:
    assert identify_project_input(Path("auth.conf"), "auth.conf", inspect_content=False) is None
    assert (
        identify_project_input(Path("webserver.conf"), "webserver.conf", inspect_content=False)
        is None
    )


def test_content_detection_for_ansible_static_and_plugin_inventory(tmp_path: Path) -> None:
    static_inventory = tmp_path / "production.yml"
    static_inventory.write_text(
        "all:\n  children:\n    web:\n      hosts:\n        web-1:\n",
        encoding="utf-8",
    )
    plugin_inventory = tmp_path / "cloud.yml"
    plugin_inventory.write_text(
        "plugin: amazon.aws.aws_ec2\nregions:\n  - us-east-1\n",
        encoding="utf-8",
    )

    assert identify_project_input(static_inventory, static_inventory.name) == "ansible-project"
    assert identify_project_input(plugin_inventory, plugin_inventory.name) == "ansible-project"


def test_ansible_inventory_detection_handles_adversarial_whitespace_linearly() -> None:
    source = "all:\n" + (" \n" * 50_000) + "not_inventory: true\n"

    assert _looks_like_ansible_inventory_yaml(source) is False


def test_content_detection_for_concourse_pipeline(tmp_path: Path) -> None:
    pipeline = tmp_path / "pipeline.yml"
    pipeline.write_text(
        "jobs:\n  - name: build\n    plan:\n      - task: test\n        file: ci/test.yml\n",
        encoding="utf-8",
    )
    assert identify_project_input(pipeline, pipeline.name) == "concourse"


def test_content_detection_for_cloud_build_and_codepipeline_json(tmp_path: Path) -> None:
    cloud_build = tmp_path / "generated-build.json"
    cloud_build.write_text(
        json.dumps({"steps": [{"name": "gcr.io/cloud-builders/docker", "args": ["build"]}]}),
        encoding="utf-8",
    )
    codepipeline = tmp_path / "generated-pipeline.json"
    codepipeline.write_text(
        json.dumps({"pipeline": {"name": "deploy", "stages": []}}),
        encoding="utf-8",
    )
    assert identify_project_input(cloud_build, cloud_build.name) == "cloud-build"
    assert identify_project_input(codepipeline, codepipeline.name) == "codepipeline"


def test_content_detection_for_generated_docker_bake_json(tmp_path: Path) -> None:
    bake = tmp_path / "generated-build.json"
    bake.write_text(
        json.dumps(
            {
                "target": {
                    "app": {
                        "context": ".",
                        "dockerfile": "Dockerfile",
                        "output": [{"type": "registry"}],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    assert identify_project_input(bake, bake.name) == "docker-bake"


def test_content_detection_for_sops_structured_dotenv_and_ini(tmp_path: Path) -> None:
    yaml_secret = tmp_path / "generated-secret.yaml"
    yaml_secret.write_text(
        "value: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n"
        "sops:\n  mac: ENC[AES256_GCM,data:m,iv:i,tag:t,type:str]\n",
        encoding="utf-8",
    )
    json_secret = tmp_path / "generated-secret.json"
    json_secret.write_text(json.dumps({"data": "ENC[...]", "sops": {"version": "3.10"}}))
    env_secret = tmp_path / "generated-secret.env"
    env_secret.write_text("KEY=ENC[...]\nsops_mac=ENC[...]\n", encoding="utf-8")
    ini_secret = tmp_path / "generated-secret.ini"
    ini_secret.write_text("[data]\nkey=ENC[...]\n[sops]\nversion=3.10\n", encoding="utf-8")

    assert identify_project_input(yaml_secret, yaml_secret.name) == "sops"
    assert identify_project_input(json_secret, json_secret.name) == "sops"
    assert identify_project_input(env_secret, env_secret.name) == "sops"
    assert identify_project_input(ini_secret, ini_secret.name) == "sops"


def test_sops_encrypted_prefix_detects_large_document_before_truncated_metadata(
    tmp_path: Path,
) -> None:
    secret = tmp_path / "production.enc.yaml"
    secret.write_text(
        "value: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n"
        + "padding: "
        + "x" * (300 * 1024)
        + "\nsops:\n  version: 3.10.2\n",
        encoding="utf-8",
    )

    assert identify_project_input(secret, secret.name) == "sops"


def test_large_terraform_plan_is_detected_from_a_bounded_prefix(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        '{"format_version":"1.2","terraform_version":"1.9.0","padding":"'
        + "x" * (300 * 1024)
        + '","resource_changes":[]}',
        encoding="utf-8",
    )

    assert identify_project_input(plan, plan.name) == "terraform"


def test_pr_comment_sanitizes_untrusted_path_markdown() -> None:
    comment = _project_pr_comment(
        decision="warn",
        risk="review",
        reason="Review the project.",
        results=[
            {
                "path": "infra/evil`\n**spoofed**.tf",
                "tool": "terraform-config",
                "decision": "warn",
                "risk": "review",
            }
        ],
        errors=[],
        required_checks=[],
    )

    assert "\n**spoofed**" not in comment
    assert "evil`" not in comment
    assert "infra/evilˋ **spoofed**.tf" in comment


@pytest.mark.parametrize(
    "relative",
    [
        "src/adapters/dockerfile.py",
        "src/parsers/JenkinsfileParser.py",
        "src/parsers/tiltfile.py",
        "tools/playbook-helper.py",
        "config/repos.yaml",
        "provisioning/application.yaml",
        "src/client.rb",
        "lib/solo.rb",
        "config/config.rb",
    ],
)
def test_similarly_named_source_and_generic_config_files_are_not_infrastructure(
    tmp_path: Path, relative: str
) -> None:
    source = tmp_path / Path(relative).name
    source.write_text("def parse_config(): ...\n", encoding="utf-8")

    assert identify_project_input(source, relative) is None


def test_discovery_is_deterministic_and_honors_default_and_custom_exclusions(
    tmp_path: Path,
) -> None:
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "b.tf").write_text("resource {}", encoding="utf-8")
    (tmp_path / "infra" / "a.tf").write_text("resource {}", encoding="utf-8")
    (tmp_path / "skip").mkdir()
    (tmp_path / "skip" / "ignored.tf").write_text("resource {}", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "vendored.tf").write_text("resource {}", encoding="utf-8")

    found = discover_project_inputs(tmp_path, excludes=("skip/**",))
    assert [item.relative_path for item in found] == ["infra/a.tf", "infra/b.tf"]


def test_project_scan_aggregates_mixed_tools_and_redacts_source_values(capsys) -> None:
    root = FIXTURES / "project_scan"
    exit_code = main(["scan", "--framework", "soc2", str(root)])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 2
    assert payload["schema"] == "rtp-agent-gate-v1"
    assert payload["adapter"] == "project-scan"
    assert payload["decision"] == "block"
    assert payload["discovered_file_count"] == 4
    assert payload["scanned_file_count"] == 4
    assert payload["error_count"] == 0
    assert [item["path"] for item in payload["files"]] == [
        ".spacelift/config.yml",
        "compose.yml",
        "infra/main.tf",
        "Jenkinsfile",
    ]
    assert {item["tool"] for item in payload["files"]} == {
        "spacelift",
        "docker-compose",
        "terraform-config",
        "jenkins",
    }
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
    encoded = json.dumps(payload)
    assert "project-scan-secret" not in encoded
    assert "deploy-production.sh" not in encoded
    assert "kubectl apply" not in encoded


def test_project_scan_analyzes_travis_drone_and_woodpecker(tmp_path: Path) -> None:
    fixture_names = {
        ".travis.yml": "travis_ci_risky.yml",
        ".drone.yml": "drone_ci_risky.yml",
        ".woodpecker.yml": "woodpecker_ci_risky.yml",
    }
    for destination, fixture in fixture_names.items():
        (tmp_path / destination).write_text(
            (FIXTURES / fixture).read_text(encoding="utf-8"), encoding="utf-8"
        )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 3
    assert payload["scanned_file_count"] == 3
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {
        "travis-ci",
        "drone-ci",
        "woodpecker-ci",
    }
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "literal-example-token" not in encoded
    assert "literal-job-token" not in encoded


def test_project_scan_analyzes_concourse_bamboo_and_teamcity(tmp_path: Path) -> None:
    destinations = {
        ".concourse/pipeline.yml": "concourse_risky.yml",
        "bamboo-specs/bamboo.yml": "bamboo_risky.yml",
        ".teamcity/settings.kts": "teamcity_risky.kts",
    }
    for destination, fixture in destinations.items():
        target = tmp_path / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((FIXTURES / fixture).read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 3
    assert payload["scanned_file_count"] == 3
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {
        "concourse",
        "bamboo",
        "teamcity",
    }
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "literal-concourse-token" not in encoded
    assert "literal-bamboo-token" not in encoded
    assert "literal-teamcity-token" not in encoded


def test_project_scan_analyzes_cloud_native_build_and_delivery(tmp_path: Path) -> None:
    destinations = {
        "buildspec.yml": "codebuild_risky.yml",
        "cloudbuild.yaml": "google_cloud_build_risky.yml",
        "codepipeline.json": "codepipeline_risky.json",
    }
    for destination, fixture in destinations.items():
        (tmp_path / destination).write_text(
            (FIXTURES / fixture).read_text(encoding="utf-8"), encoding="utf-8"
        )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 3
    assert payload["scanned_file_count"] == 3
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {
        "codebuild",
        "cloud-build",
        "codepipeline",
    }
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "literal-codebuild-token" not in encoded
    assert "literal-cloud-build-token" not in encoded
    assert "literal-codepipeline-token" not in encoded


def test_project_scan_analyzes_ansible_static_and_dynamic_inventory(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory"
    inventory.mkdir()
    destinations = {
        "inventory.yml": "ansible_inventory_risky.yml",
        "prod.aws_ec2.yml": "ansible_inventory_plugin_risky.aws_ec2.yml",
    }
    for destination, fixture in destinations.items():
        (inventory / destination).write_text(
            (FIXTURES / fixture).read_text(encoding="utf-8"), encoding="utf-8"
        )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 2
    assert payload["scanned_file_count"] == 2
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {"ansible-project"}
    assert {item["adapter"] for item in payload["files"]} == {"ansible-project"}
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-inventory-password-do-not-leak" not in encoded
    assert "fixture-aws-access-key-do-not-leak" not in encoded


def test_project_scan_analyzes_molecule_scenarios(tmp_path: Path) -> None:
    target = tmp_path / "molecule" / "default" / "molecule.yml"
    target.parent.mkdir(parents=True)
    target.write_text(
        (FIXTURES / "ansible_molecule_risky" / "molecule" / "default" / "molecule.yml").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["files"][0]["tool"] == "ansible-project"
    assert payload["files"][0]["artifact_type"] == "molecule"
    assert payload["files"][0]["platform_count"] == 2
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-molecule-registry-password-do-not-leak" not in encoded
    assert "privileged-platform" not in encoded


def test_project_scan_analyzes_ansible_content_metadata_and_lint_policy(
    tmp_path: Path,
) -> None:
    source_root = FIXTURES / "ansible_content_policy_risky"
    relative_paths = (
        "galaxy.yml",
        ".ansible-lint",
        "meta/runtime.yml",
        "roles/risky_role/meta/main.yml",
        "roles/risky_role/meta/argument_specs.yml",
    )
    for relative in relative_paths:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((source_root / relative).read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 5
    assert payload["scanned_file_count"] == 5
    assert payload["error_count"] == 0
    assert {item["artifact_type"] for item in payload["files"]} == {
        "ansible_lint",
        "argument_specs",
        "collection_metadata",
        "role_metadata",
        "runtime_metadata",
    }
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-password-do-not-leak" not in encoded
    assert "fixture-argument-token-do-not-leak" not in encoded
    assert "fixture-lint-password-do-not-leak" not in encoded


def test_project_scan_analyzes_puppet_runtime_configuration(tmp_path: Path) -> None:
    puppet_directory = tmp_path / "puppet"
    puppet_directory.mkdir()
    (puppet_directory / "puppet.conf").write_text(
        (FIXTURES / "puppet_conf_risky.conf").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["files"][0]["tool"] == "puppet-project"
    assert payload["files"][0]["adapter"] == "puppet-project"
    assert payload["files"][0]["total_changes"] == 34
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-puppet-proxy-password-do-not-leak" not in encoded
    assert "fixture-puppet-header-token-do-not-leak" not in encoded


def test_project_scan_analyzes_r10k_deployment_configuration(tmp_path: Path) -> None:
    target = tmp_path / "puppet" / "r10k.yaml"
    target.parent.mkdir()
    target.write_text(
        (FIXTURES / "puppet_r10k_risky" / "r10k.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["files"][0]["tool"] == "puppet-project"
    assert payload["files"][0]["adapter"] == "puppet-project"
    assert payload["files"][0]["total_changes"] == 40
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-proxy-password" not in encoded
    assert "fixture-forge-token-do-not-leak" not in encoded


def test_project_scan_analyzes_puppet_server_and_environment_policy(tmp_path: Path) -> None:
    source_root = FIXTURES / "puppet_server_policy_risky"
    destinations = {
        "environment.conf": "environments/production/environment.conf",
        "puppetdb.conf": "puppet/puppetdb.conf",
        "puppetserver.conf": "puppetserver/conf.d/puppetserver.conf",
        "auth.conf": "puppetserver/conf.d/auth.conf",
        "ca.conf": "puppetserver/conf.d/ca.conf",
        "webserver.conf": "puppetserver/conf.d/webserver.conf",
        "web-routes.conf": "puppetserver/conf.d/web-routes.conf",
    }
    for source_name, destination in destinations.items():
        target = tmp_path / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            (source_root / source_name).read_text(encoding="utf-8"), encoding="utf-8"
        )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 7
    assert payload["scanned_file_count"] == 7
    assert payload["error_count"] == 0
    assert {item["artifact_type"] for item in payload["files"]} == {
        "environment",
        "puppetdb",
        "server_auth",
        "server_ca",
        "server_routes",
        "server_runtime",
        "server_web",
    }
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-puppetdb-password-do-not-leak" not in encoded
    assert "fixture-jruby-token-do-not-leak" not in encoded
    assert "fixture-admin-rule-do-not-leak" not in encoded


def test_project_scan_analyzes_bolt_project_and_inventory(tmp_path: Path) -> None:
    bolt_directory = tmp_path / "bolt"
    bolt_directory.mkdir()
    (bolt_directory / "bolt-project.yaml").write_text(
        (FIXTURES / "bolt_project" / "bolt-project.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (bolt_directory / "inventory.yaml").write_text(
        (FIXTURES / "bolt_inventory" / "inventory.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 2
    assert payload["scanned_file_count"] == 2
    assert payload["error_count"] == 0
    assert {item["path"] for item in payload["files"]} == {
        "bolt/bolt-project.yaml",
        "bolt/inventory.yaml",
    }
    assert {item["adapter"] for item in payload["files"]} == {"puppet-project"}
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-bolt-token-do-not-leak" not in encoded
    assert "fixture-ssh-password-do-not-leak" not in encoded


def test_root_bolt_inventory_wins_over_generic_ansible_inventory(tmp_path: Path) -> None:
    (tmp_path / "bolt-project.yaml").write_text("name: root_project\n", encoding="utf-8")
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text("targets:\n  - target.example.com\n", encoding="utf-8")

    assert identify_project_input(inventory, "inventory.yaml") == "puppet-project"


def test_project_scan_analyzes_jenkins_jcasc_library_trust(tmp_path: Path) -> None:
    target = tmp_path / "jenkins" / "jenkins.yaml"
    target.parent.mkdir()
    target.write_text(
        (FIXTURES / "jenkins_jcasc_risky.yml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["files"][0]["tool"] == "jenkins-jcasc"
    assert payload["files"][0]["total_changes"] == 26
    assert payload["files"][0]["risk_counts"] == {
        "safe": 0,
        "review": 7,
        "dangerous": 19,
        "irreversible": 0,
    }
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-library-credential-do-not-leak" not in encoded
    assert "git.example.test" not in encoded
    assert "shared-deploy" not in encoded


def test_project_scan_analyzes_jenkins_plugin_catalog(tmp_path: Path) -> None:
    jenkins_directory = tmp_path / "jenkins"
    jenkins_directory.mkdir()
    (jenkins_directory / "plugins.txt").write_text(
        (FIXTURES / "jenkins_plugins_risky.txt").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["files"][0]["tool"] == "jenkins-project"
    assert payload["files"][0]["adapter"] == "jenkins-project"
    assert payload["files"][0]["total_changes"] == 8
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-user" not in encoded
    assert "fixture-password" not in encoded
    assert "plugins.example.invalid" not in encoded


def test_project_scan_analyzes_jenkins_job_builder_definitions(tmp_path: Path) -> None:
    fixture = FIXTURES / "jenkins_job_builder_risky" / "jenkins-jobs.yaml"
    target = tmp_path / "jjb" / "jobs.yaml"
    target.parent.mkdir()
    target.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["files"][0]["tool"] == "jenkins-project"
    assert payload["files"][0]["total_changes"] == 13
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-password" not in encoded
    assert "fixture-parameter-secret-do-not-leak" not in encoded


def test_project_scan_analyzes_jenkins_shared_library_without_generic_groovy(
    tmp_path: Path,
) -> None:
    fixture_root = FIXTURES / "jenkins_shared_library_risky"
    targets = (
        "vars/deploy.groovy",
        "src/org/example/Helper.groovy",
    )
    for relative in targets:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((fixture_root / relative).read_text(encoding="utf-8"), encoding="utf-8")
    generic = tmp_path / "application" / "src" / "main" / "groovy" / "App.groovy"
    generic.parent.mkdir(parents=True)
    generic.write_text("class App {}\n", encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 2
    assert payload["scanned_file_count"] == 2
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {"jenkins-project"}
    assert {item["artifact_type"] for item in payload["files"]} == {
        "shared_library_class",
        "shared_library_var",
    }
    assert payload["total_changes"] == 23
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-shared-library-secret-do-not-leak" not in encoded
    assert "fixture-controller-path-do-not-leak" not in encoded


def test_project_scan_analyzes_chef_runtime_configuration(tmp_path: Path) -> None:
    source = FIXTURES / "chef_runtime"
    targets = {
        "client.rb": "client.rb",
        ".chef/config.rb": ".chef/config.rb",
        "solo.rb": "solo.rb",
        "chef-server.rb": "chef-server.rb",
    }
    for destination, fixture in targets.items():
        target = tmp_path / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((source / fixture).read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 4
    assert payload["scanned_file_count"] == 4
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {"chef-project"}
    assert {item["adapter"] for item in payload["files"]} == {"chef-project"}
    assert payload["total_changes"] == 61
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-chef" not in encoded
    assert "example.invalid" not in encoded


def test_project_scan_analyzes_test_kitchen_configuration(tmp_path: Path) -> None:
    fixture = FIXTURES / "chef_test_kitchen_risky" / ".kitchen.yml"
    target = tmp_path / "cookbooks" / "base" / ".kitchen.yml"
    target.parent.mkdir(parents=True)
    target.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["files"][0]["tool"] == "chef-project"
    assert payload["files"][0]["artifact_type"] == "test_kitchen"
    assert payload["files"][0]["platform_count"] == 1
    assert payload["files"][0]["suite_count"] == 1
    assert payload["files"][0]["dynamic_erb"] is True
    assert payload["total_changes"] == 31
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-cloud-secret-do-not-leak" not in encoded
    assert "fixture-local-command-do-not-run" not in encoded
    assert "example.invalid" not in encoded


def test_project_scan_analyzes_inspec_profile_artifacts(tmp_path: Path) -> None:
    source = FIXTURES / "inspec_profile_risky"
    for relative in (
        "inspec.yml",
        "inspec.lock",
        "controls/main.rb",
        "libraries/custom.rb",
        "waivers.yml",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((source / relative).read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 5
    assert payload["scanned_file_count"] == 5
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {"inspec"}
    assert {item["adapter"] for item in payload["files"]} == {"inspec"}
    assert payload["total_changes"] == 30
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-user" not in encoded
    assert "fixture-password" not in encoded
    assert "fixture-secret-value" not in encoded
    assert "fixture-control-id" not in encoded
    assert "example.invalid" not in encoded


def test_project_scan_analyzes_sops_policy_and_encrypted_documents(tmp_path: Path) -> None:
    destinations = {
        ".sops.yaml": "sops_policy_risky.yaml",
        "secret.sops.yaml": "secret.sops.yaml",
        "secret.sops.env": "secret.sops.env",
        "secret.sops.ini": "secret.sops.ini",
    }
    for destination, fixture in destinations.items():
        (tmp_path / destination).write_text(
            (FIXTURES / fixture).read_text(encoding="utf-8"), encoding="utf-8"
        )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 4
    assert payload["scanned_file_count"] == 4
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {"sops"}
    assert payload["decision"] == "block"
    assert "literal-token-must-not-leak" not in json.dumps(payload)


def test_project_scan_analyzes_docker_bake_and_redacts_build_values(tmp_path: Path) -> None:
    (tmp_path / "docker-bake.hcl").write_text(
        (FIXTURES / "docker-bake.risky.hcl").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["files"][0]["tool"] == "docker-bake"
    assert payload["files"][0]["adapter"] == "docker-bake"
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "literal-build-token-must-not-leak" not in encoded
    assert "literal-build-arg-must-not-leak" not in encoded


def test_malformed_discovered_input_becomes_redacted_validation_error(tmp_path: Path) -> None:
    config = tmp_path / ".spacelift" / "config.yml"
    config.parent.mkdir()
    config.write_text("stacks: [\nsuper-secret-value", encoding="utf-8")
    payload = scan_project(tmp_path, display_root=".")
    encoded = json.dumps(payload)
    assert payload["decision"] == "warn"
    assert payload["error_count"] == 1
    assert payload["errors"] == [
        {"path": ".spacelift/config.yml", "tool": "spacelift", "code": "analysis-failed"}
    ]
    assert "super-secret-value" not in encoded


def test_no_supported_inputs_warns_without_inventing_changes(tmp_path: Path, capsys) -> None:
    (tmp_path / "README.md").write_text("hello", encoding="utf-8")
    assert main(["scan", str(tmp_path)]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "warn"
    assert payload["discovered_file_count"] == 0
    assert payload["total_changes"] == 0
    assert payload["risk_counts"] == {
        "safe": 0,
        "review": 0,
        "dangerous": 0,
        "irreversible": 0,
    }


def test_file_size_limit_records_validation_error(tmp_path: Path) -> None:
    config = tmp_path / "compose.yml"
    config.write_text("services: {}\n", encoding="utf-8")
    payload = scan_project(tmp_path, display_root=".", max_file_bytes=1)
    assert payload["errors"][0]["code"] == "file-too-large"
    assert payload["risk_counts"]["review"] == 1


def test_discovery_limit_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "a.tf").write_text("resource {}", encoding="utf-8")
    (tmp_path / "b.tf").write_text("resource {}", encoding="utf-8")
    with pytest.raises(ProjectScanError, match="more than 1"):
        discover_project_inputs(tmp_path, max_files=1)


def test_invalid_limits_and_missing_paths_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ProjectScanError, match="max_files"):
        discover_project_inputs(tmp_path, max_files=0)
    with pytest.raises(ProjectScanError, match="max_file_bytes"):
        scan_project(tmp_path, display_root=".", max_file_bytes=0)
    with pytest.raises(ProjectScanError, match="cannot be resolved"):
        discover_project_inputs(tmp_path / "missing")
