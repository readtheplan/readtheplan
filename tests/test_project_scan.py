from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import readtheplan.project_scan as project_scan_module
from readtheplan.cli import main
from readtheplan.project_scan import (
    DiscoveredInput,
    ProjectScanError,
    _looks_like_ansible_inventory_yaml,
    _project_pr_comment,
    discover_project_inputs,
    identify_project_input,
    scan_discovered_inputs,
    scan_project,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("relative", "tool"),
    [
        (".terraform.lock.hcl", "terraform-lock"),
        ("terraform.tfstate", "terraform-state"),
        ("terraform.tfstate.backup", "terraform-state"),
        ("snapshots/production.tfstate.json", "terraform-state"),
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
        ("controller-export.json", "ansible-project"),
        ("awx/resources.yml", "ansible-project"),
        ("extensions/eda/rulebooks/remediate.yml", "ansible-project"),
        ("rulebook-events.yml", "ansible-project"),
        (".ansible-navigator.json", "ansible-project"),
        ("molecule/default/molecule.yml", "ansible-project"),
        (".config/molecule/config.yml", "ansible-project"),
        ("galaxy.yml", "ansible-project"),
        ("collections/demo/meta/runtime.yml", "ansible-project"),
        ("roles/demo/meta/main.yml", "ansible-project"),
        ("roles/demo/meta/argument_specs.yml", "ansible-project"),
        ("roles/demo/tasks/main.yml", "ansible"),
        ("roles/demo/tasks/platform/redhat.yaml", "ansible"),
        ("collections/acme/demo/roles/service/handlers/main.yml", "ansible"),
        (".ansible-lint", "ansible-project"),
        ("Jenkinsfile.deploy", "jenkins"),
        ("plugins.txt", "jenkins-project"),
        ("jenkins/plugins.yaml", "jenkins-project"),
        ("jenkins_home/init.groovy", "jenkins-project"),
        ("jenkins_home/init.groovy.d/10-security.groovy", "jenkins-project"),
        ("jenkins_home/boot-failure.groovy", "jenkins-project"),
        ("usr/share/jenkins/ref/boot-failure.groovy.d/notify.groovy", "jenkins-project"),
        ("cookbooks/base/recipes/default.rb", "chef"),
        ("cookbooks/base/resources/application.rb", "chef"),
        ("cookbooks/base/attributes/default.rb", "chef"),
        ("cookbooks/base/libraries/helpers.rb", "chef"),
        ("cookbooks/base/providers/legacy.rb", "chef"),
        ("cookbooks/base/definitions/legacy.rb", "chef"),
        ("cookbooks/base/templates/default/application.erb", "chef"),
        ("cookbooks/base/ohai/cloud_inventory.rb", "chef"),
        ("client.rb", "chef-project"),
        (".chef/config.rb", "chef-project"),
        ("chef/chef-server.rb", "chef-project"),
        ("cookbooks/base/Berksfile", "chef-project"),
        ("cookbooks/base/Berksfile.lock", "chef-project"),
        ("chef/client.d/security.rb", "chef-project"),
        ("cookbooks/base/.kitchen.yml", "chef-project"),
        ("cookbooks/base/kitchen.local.yaml", "chef-project"),
        ("habitat/plan.sh", "chef-project"),
        ("habitat/x86_64-windows/plan.ps1", "chef-project"),
        ("habitat/hooks/run", "chef-project"),
        ("habitat/hooks/health_check.ps1", "chef-project"),
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
        ("modules/demo/plans/deploy.yaml", "puppet-project"),
        ("site-modules/demo/tasks/deploy.json", "puppet-project"),
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


@pytest.mark.parametrize(
    ("fixture", "tool"),
    [
        ("ytt_risky.yaml", "ytt"),
        ("vendir_risky.yml", "vendir"),
        ("vendir_risky.lock.yml", "vendir"),
        ("kbld_risky.yml", "kbld"),
        ("imgpkg_risky_locks.yml", "imgpkg"),
        ("kapp_risky.yml", "kapp"),
        ("crossplane_risky.yml", "crossplane"),
        ("sam_template_risky.yml", "sam"),
        ("serverless_framework_risky.yml", "serverless"),
        ("jenkins_jcasc_risky.yml", "jenkins-jcasc"),
        ("pulumi_preview_mixed.json", "pulumi"),
        ("azure_whatif_mixed.json", "azure"),
    ],
)
def test_content_detection_prefers_specialized_infrastructure_adapter(
    fixture: str,
    tool: str,
) -> None:
    source = (FIXTURES / fixture).read_bytes()
    generated = Path(f"generated{Path(fixture).suffix}")

    assert (
        identify_project_input(generated, generated.name, content=source) == tool
    )


def test_project_scan_routes_specialized_kubernetes_shaped_inputs(tmp_path: Path) -> None:
    expected = {
        "crossplane-generated.yaml": ("crossplane_risky.yml", "crossplane"),
        "imgpkg-generated.yaml": ("imgpkg_risky_locks.yml", "imgpkg"),
        "kbld-generated.yaml": ("kbld_risky.yml", "kbld"),
        "kapp-generated.yaml": ("kapp_risky.yml", "kapp"),
        "jenkins-generated.yaml": ("jenkins_jcasc_risky.yml", "jenkins-jcasc"),
        "pulumi-generated.json": ("pulumi_preview_mixed.json", "pulumi"),
        "sam-generated.yaml": ("sam_template_risky.yml", "sam"),
        "serverless-generated.yaml": ("serverless_framework_risky.yml", "serverless"),
        "vendir-generated.yaml": ("vendir_risky.yml", "vendir"),
        "ytt-generated.yaml": ("ytt_risky.yaml", "ytt"),
        "what-if-generated.json": ("azure_whatif_mixed.json", "azure"),
    }
    for target_name, (fixture, _tool) in expected.items():
        (tmp_path / target_name).write_bytes((FIXTURES / fixture).read_bytes())

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == len(expected)
    assert payload["scanned_file_count"] == len(expected)
    assert payload["error_count"] == 0
    assert {item["path"]: item["tool"] for item in payload["files"]} == {
        path: tool for path, (_fixture, tool) in expected.items()
    }


@pytest.mark.parametrize(
    "source",
    [
        '[{"resourcePreEvent":{"metadata":{"op":"create","urn":"urn:pulumi:test"}}}]',
        '{"resourcePreEvent":{"metadata":{"op":"create","urn":"urn:pulumi:test"}}}\n'
        '{"summaryEvent":{"maybeCorrupt":false}}\n',
    ],
)
def test_content_detection_recognizes_pulumi_event_exports(source: str) -> None:
    assert (
        identify_project_input(
            Path("preview.json"),
            "preview.json",
            content=source.encode(),
        )
        == "pulumi"
    )


@pytest.mark.parametrize(
    "fixture",
    ["terraform_state_show_risky.json", "terraform_state_raw_risky.json"],
)
def test_content_detection_recognizes_terraform_state_exports(fixture: str) -> None:
    source = (FIXTURES / fixture).read_bytes()

    assert (
        identify_project_input(
            Path("generated-state.json"),
            "generated-state.json",
            content=source,
        )
        == "terraform-state"
    )


def test_project_scan_routes_and_redacts_terraform_state(tmp_path: Path) -> None:
    fixtures = {
        "generated-state.json": "terraform_state_show_risky.json",
        "terraform.tfstate": "terraform_state_raw_risky.json",
    }
    for target, fixture in fixtures.items():
        (tmp_path / target).write_bytes((FIXTURES / fixture).read_bytes())

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 2
    assert payload["scanned_file_count"] == 2
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {"terraform-state"}
    assert {item["artifact"] for item in payload["files"]} == {
        "raw-v4",
        "show-json",
    }
    assert {item.get("serial") for item in payload["files"]} == {None, 42}
    encoded = json.dumps(payload)
    for secret in (
        "output-secret-value",
        "marked-output-secret",
        "marked-resource-secret",
        "unmarked-resource-secret",
        "raw-output-secret",
        "raw-marked-resource-secret",
        "raw-unmarked-resource-secret",
        "provider-private-blob",
    ):
        assert secret not in encoded


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


def test_ansible_role_content_detection_requires_role_context(tmp_path: Path) -> None:
    generic = tmp_path / "tasks" / "main.yml"
    generic.parent.mkdir()
    generic.write_text("- debug: {}\n", encoding="utf-8")
    assert identify_project_input(generic, "tasks/main.yml", inspect_content=False) is None

    role_root = tmp_path / "standalone-role"
    task_file = role_root / "tasks" / "main.yml"
    handler_file = role_root / "handlers" / "main.yml"
    task_file.parent.mkdir(parents=True)
    handler_file.parent.mkdir(parents=True)
    task_file.write_text("- debug: {}\n", encoding="utf-8")
    handler_file.write_text("- debug: {}\n", encoding="utf-8")
    assert identify_project_input(task_file, "standalone-role/tasks/main.yml") == "ansible"
    assert identify_project_input(handler_file, "standalone-role/handlers/main.yml") == "ansible"

    defaults = role_root / "defaults" / "main.yml"
    defaults.parent.mkdir()
    defaults.write_text("region: us-east-1\n", encoding="utf-8")
    assert (
        identify_project_input(
            defaults,
            "standalone-role/defaults/main.yml",
            inspect_content=False,
        )
        is None
    )


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


def test_project_scan_includes_terraform_plan_integrity_findings(tmp_path: Path) -> None:
    shutil.copy(
        FIXTURES / "terraform_plan_integrity_risky.json",
        tmp_path / "plan.json",
    )

    payload = scan_project(tmp_path, display_root=".", framework="soc2")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["decision"] == "block"
    assert payload["risk_counts"] == {
        "safe": 1,
        "review": 4,
        "dangerous": 9,
        "irreversible": 0,
    }
    assert payload["total_changes"] == 14
    result = payload["files"][0]
    assert result["tool"] == "terraform"
    assert result["resource_change_count"] == 1
    assert result["plan_finding_count"] == 13
    assert result["total_changes"] == 14
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
    encoded = json.dumps(payload)
    assert "fixture-action-payload-secret-do-not-leak" not in encoded
    assert "fixture-ansible-token-do-not-leak" not in encoded


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


def test_project_scan_analyzes_ansible_role_tasks_and_handlers(tmp_path: Path) -> None:
    source_root = FIXTURES / "ansible_role_content_risky" / "roles" / "application"
    for relative in (Path("tasks/main.yml"), Path("handlers/main.yml")):
        target = tmp_path / "roles" / "application" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((source_root / relative).read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")
    encoded = json.dumps(payload)

    assert payload["discovered_file_count"] == 2
    assert payload["scanned_file_count"] == 2
    assert payload["error_count"] == 0
    assert payload["total_changes"] == 16
    assert payload["risk_counts"] == {
        "safe": 0,
        "review": 7,
        "dangerous": 9,
        "irreversible": 0,
    }
    assert {item["artifact_type"] for item in payload["files"]} == {
        "task_file",
        "handler_file",
    }
    task_result = next(item for item in payload["files"] if item["artifact_type"] == "task_file")
    handler_result = next(
        item for item in payload["files"] if item["artifact_type"] == "handler_file"
    )
    assert task_result["task_count"] == 11
    assert task_result["handler_count"] == 0
    assert handler_result["task_count"] == 0
    assert handler_result["handler_count"] == 4
    assert payload["decision"] == "block"
    for secret in (
        "fixture-task-token-do-not-leak",
        "fixture-environment-token-do-not-leak",
        "fixture-handler-name-do-not-leak",
        "fixture-handler-message-do-not-leak",
    ):
        assert secret not in encoded


def test_project_scan_analyzes_ansible_lookup_boundaries(tmp_path: Path) -> None:
    target = tmp_path / "lookup-playbook.yml"
    target.write_text(
        (FIXTURES / "ansible_lookup_risky.yml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    payload = scan_project(tmp_path, display_root=".", framework="soc2")
    encoded = json.dumps(payload)

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["decision"] == "block"
    assert payload["total_changes"] == 9
    assert payload["risk_counts"] == {
        "safe": 0,
        "review": 2,
        "dangerous": 7,
        "irreversible": 0,
    }
    result = payload["files"][0]
    assert result["tool"] == "ansible"
    assert result["adapter"] == "ansible"
    assert result["lookup_count"] == 9
    assert "command" in result["lookup_capabilities"]
    assert "secret" in result["lookup_capabilities"]
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
    assert "fixture-pipe-command-do-not-run" not in encoded
    assert "fixture-vault-secret-do-not-leak" not in encoded


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
        target.write_text((source_root / source_name).read_text(encoding="utf-8"), encoding="utf-8")

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


def test_project_scan_analyzes_bolt_plans_and_task_metadata(tmp_path: Path) -> None:
    for fixture in ("bolt_content_risky", "bolt_content_review"):
        source = FIXTURES / fixture / "modules" / "fixture"
        for kind, name in (("plans", "deploy.yaml"), ("tasks", "deploy.json")):
            if fixture.endswith("review"):
                name = "inspect.yaml" if kind == "plans" else "inspect.json"
            target = tmp_path / "modules" / fixture / kind / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((source / kind / name).read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 4
    assert payload["scanned_file_count"] == 4
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {"puppet-project"}
    assert {item["artifact_type"] for item in payload["files"]} == {
        "bolt_task_metadata",
        "bolt_yaml_plan",
    }
    plan = next(item for item in payload["files"] if item["path"].endswith("deploy.yaml"))
    assert plan["step_count"] == 10
    assert plan["parameter_count"] == 2
    assert plan["dynamic_count"] == 8
    task = next(item for item in payload["files"] if item["path"].endswith("deploy.json"))
    assert task["implementation_count"] == 2
    assert task["file_count"] == 3
    assert task["sensitive_parameter_count"] == 0
    assert payload["total_changes"] == 62
    assert payload["risk_counts"]["dangerous"] == 30
    assert payload["risk_counts"]["review"] == 32
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-bolt" not in encoded
    assert "example.invalid" not in encoded
    assert "fixture-package" not in encoded


def test_project_scan_analyzes_bolt_task_implementation_code(tmp_path: Path) -> None:
    source = (
        FIXTURES
        / "bolt_task_implementation_risky"
        / "modules"
        / "fixture"
        / "tasks"
        / "deploy.sh"
    )
    target = tmp_path / "modules" / "fixture" / "tasks" / "deploy.sh"
    target.parent.mkdir(parents=True)
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["total_changes"] == 13
    assert payload["risk_counts"] == {
        "safe": 0,
        "review": 5,
        "dangerous": 8,
        "irreversible": 0,
    }
    task = payload["files"][0]
    assert task["path"] == "modules/fixture/tasks/deploy.sh"
    assert task["tool"] == "puppet-project"
    assert task["artifact_type"] == "bolt_task_implementation"
    assert task["language"] == "shell"
    assert task["source_kind"] == "target_task_implementation"
    assert task["source_line_count"] == 12
    assert task["task_name"] == "deploy"
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-bolt-implementation-secret-do-not-leak" not in encoded
    assert "downloads.example.invalid" not in encoded


def test_root_bolt_inventory_wins_over_generic_ansible_inventory(tmp_path: Path) -> None:
    (tmp_path / "bolt-project.yaml").write_text("name: root_project\n", encoding="utf-8")
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text("targets:\n  - target.example.com\n", encoding="utf-8")

    assert identify_project_input(inventory, "inventory.yaml") == "puppet-project"


def test_project_scan_analyzes_ansible_modules_plugins_and_module_utils(
    tmp_path: Path,
) -> None:
    source = FIXTURES / "ansible_collection_code_risky"
    target = tmp_path / "collections" / "acme" / "operations"
    shutil.copytree(source, target)

    payload = scan_project(tmp_path, display_root=".")

    code = [
        item
        for item in payload["files"]
        if item.get("artifact_type")
        in {"controller_plugin_source", "module_source", "module_utility_source"}
    ]
    assert len(code) == 4
    assert {item["source_kind"] for item in code} == {
        "controller_plugin",
        "shared_module_utility",
        "target_module",
    }
    assert {item["plugin_type"] for item in code} == {
        "action",
        "filter",
        "module",
        "module_utils",
    }
    module = next(item for item in code if item["artifact_type"] == "module_source")
    assert module["component_name"] == "deploy"
    assert module["source_line_count"] == 17
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "RTP_FIXTURE_ANSIBLE_SECRET_DO_NOT_LEAK" not in encoded
    assert "RTP_FIXTURE_CONTROLLER_SECRET_DO_NOT_LEAK" not in encoded


def test_project_scan_analyzes_puppet_ruby_module_extensions(tmp_path: Path) -> None:
    source = FIXTURES / "puppet_ruby_extensions_risky"
    shutil.copytree(source, tmp_path, dirs_exist_ok=True)

    payload = scan_project(tmp_path, display_root=".")
    extensions = [
        item for item in payload["files"] if item.get("artifact_type") == "ruby_extension"
    ]

    assert len(extensions) == 6
    assert {item["extension_type"] for item in extensions} == {
        "custom_fact",
        "legacy_function",
        "report_processor",
        "resource_provider",
        "resource_type",
        "ruby_function",
    }
    assert {item["source_kind"] for item in extensions} == {
        "agent_fact",
        "server_agent_provider",
        "server_agent_type",
        "server_compile_function",
        "server_report_processor",
    }
    assert {item["language"] for item in extensions} == {"ruby"}
    assert all(item["source_line_count"] > 0 for item in extensions)
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "DO_NOT_LEAK" not in encoded
    assert "facts.example.invalid" not in encoded
    assert "reports.example.invalid" not in encoded


def test_project_scan_analyzes_puppet_external_facts(tmp_path: Path) -> None:
    source = FIXTURES / "puppet_external_facts_risky"
    shutil.copytree(source, tmp_path, dirs_exist_ok=True)

    payload = scan_project(tmp_path, display_root=".")
    facts = [item for item in payload["files"] if item.get("artifact_type") == "external_fact"]

    assert len(facts) == 9
    assert {item["external_fact_type"] for item in facts} == {
        "executable",
        "structured_data",
    }
    assert {item.get("language") for item in facts if item.get("language")} == {
        "batch",
        "perl",
        "powershell",
        "python",
        "ruby",
        "shell",
    }
    assert {item.get("format") for item in facts if item.get("format")} == {
        "json",
        "text",
        "yaml",
    }
    assert {item["source_kind"] for item in facts} == {"agent_external_fact"}
    assert all(item["source_line_count"] > 0 for item in facts)
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "DO_NOT_LEAK" not in encoded
    assert "facts.example.invalid" not in encoded


def test_project_scan_discovers_extensionless_puppet_external_fact(tmp_path: Path) -> None:
    module = tmp_path / "modules" / "site"
    module.mkdir(parents=True)
    (module / "metadata.json").write_text('{"name":"fixture-site"}\n', encoding="utf-8")
    fact = module / "facts.d" / "site_inventory"
    fact.parent.mkdir()
    fact.write_text("#!/bin/sh\nprintf 'site=fixture\\n'\n", encoding="utf-8")

    assert identify_project_input(fact, "modules/site/facts.d/site_inventory") == "puppet-project"
    payload = scan_project(tmp_path, display_root=".")
    external = [
        item for item in payload["files"] if item.get("artifact_type") == "external_fact"
    ]
    assert len(external) == 1
    assert external[0]["language"] == "shell"
    assert external[0]["source_kind"] == "agent_external_fact"


def test_project_scan_ignores_unclassified_puppet_library_ruby(tmp_path: Path) -> None:
    helper = tmp_path / "modules" / "site" / "lib" / "puppet" / "util" / "helper.rb"
    helper.parent.mkdir(parents=True)
    helper.write_text("module Puppet::Util::Helper\nend\n", encoding="utf-8")

    assert identify_project_input(helper, "modules/site/lib/puppet/util/helper.rb") is None
    assert scan_project(tmp_path, display_root=".")["discovered_file_count"] == 0


def test_project_scan_does_not_claim_generic_python_plugin_paths(tmp_path: Path) -> None:
    plugin = tmp_path / "plugins" / "filter" / "example.py"
    plugin.parent.mkdir(parents=True)
    plugin.write_text("def filter_value(value):\n    return value\n", encoding="utf-8")

    assert identify_project_input(plugin, "plugins/filter/example.py") is None
    assert scan_project(tmp_path, display_root=".")["discovered_file_count"] == 0


def test_root_bolt_content_uses_project_or_module_context(tmp_path: Path) -> None:
    plans = tmp_path / "plans"
    tasks = tmp_path / "tasks"
    plans.mkdir()
    tasks.mkdir()
    plan = plans / "deploy.yaml"
    task = tasks / "deploy.json"
    implementation = tasks / "deploy"
    plan.write_text("steps:\n  - message: ok\n", encoding="utf-8")
    task.write_text('{"supports_noop":true}', encoding="utf-8")
    implementation.write_text("#!/usr/bin/env python3\nprint('ok')\n", encoding="utf-8")

    assert identify_project_input(plan, "plans/deploy.yaml") is None
    assert identify_project_input(task, "tasks/deploy.json") is None
    assert identify_project_input(implementation, "tasks/deploy") is None

    (tmp_path / "bolt-project.yaml").write_text("name: demo\n", encoding="utf-8")
    assert identify_project_input(plan, "plans/deploy.yaml") == "puppet-project"
    assert identify_project_input(task, "tasks/deploy.json") == "puppet-project"
    assert identify_project_input(implementation, "tasks/deploy") == "puppet-project"


def test_project_scan_propagates_jenkins_credential_exposure_metadata(tmp_path: Path) -> None:
    target = tmp_path / "Jenkinsfile"
    target.write_text(
        (FIXTURES / "Jenkinsfile.config-management-risky").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    result = payload["files"][0]
    assert result["tool"] == "jenkins"
    assert result["adapter"] == "jenkins"
    assert result["credential_binding_count"] == 1
    assert result["secret_interpolation_count"] == 1
    assert result["credential_exposure_capabilities"] == ["command"]
    assert result["total_changes"] == 18
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "production-deploy-token" not in encoded
    assert "DEPLOY_TOKEN" not in encoded
    assert "registry.example.com/platform/deployer:latest" not in encoded


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


def test_project_scan_analyzes_jenkins_controller_groovy_hooks() -> None:
    payload = scan_project(FIXTURES / "jenkins_groovy_hooks_risky", display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    hook = payload["files"][0]
    assert hook["tool"] == "jenkins-project"
    assert hook["artifact_type"] == "init_hook"
    assert hook["source_kind"] == "controller_init_hook"
    assert hook["hook_name"] == "init"
    assert hook["source_line_count"] == 15
    assert hook["total_changes"] == 17
    assert payload["total_changes"] == 17
    assert payload["risk_counts"] == {
        "safe": 0,
        "review": 3,
        "dangerous": 14,
        "irreversible": 0,
    }
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-controller-token-do-not-leak" not in encoded
    assert "fixture-controller-command-do-not-run" not in encoded
    assert "FIXTURE_ENDPOINT" not in encoded


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


def test_project_scan_analyzes_chef_cookbook_content() -> None:
    payload = scan_project(FIXTURES / "chef_cookbook_risky", display_root=".")

    assert payload["discovered_file_count"] == 5
    assert payload["scanned_file_count"] == 5
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {"chef", "chef-project"}
    assert {item["artifact_type"] for item in payload["files"]} == {
        "attribute_file",
        "custom_resource",
        "library",
        "metadata",
        "template",
    }
    resource = next(item for item in payload["files"] if item["artifact_type"] == "custom_resource")
    assert resource["resource_count"] == 1
    assert resource["action_count"] == 1
    assert resource["property_count"] == 2
    assert resource["dynamic_count"] == 2
    assert payload["total_changes"] == 24
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-secret-value" not in encoded
    assert "fixturectl" not in encoded
    assert "api_token" not in encoded


def test_project_scan_analyzes_chef_ohai_plugins() -> None:
    payload = scan_project(FIXTURES / "chef_ohai_risky", display_root=".")

    assert payload["discovered_file_count"] == 2
    assert payload["scanned_file_count"] == 2
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {"chef", "chef-project"}
    plugin = next(item for item in payload["files"] if item["tool"] == "chef")
    assert plugin["artifact_type"] == "ohai_plugin"
    assert plugin["plugin_count"] == 1
    assert plugin["named_plugin_count"] == 1
    assert plugin["provides_count"] == 2
    assert plugin["depends_count"] == 1
    assert plugin["collect_data_count"] == 1
    assert plugin["platform_count"] == 1
    assert plugin["dynamic_count"] == 7
    assert payload["total_changes"] == 20
    assert payload["risk_counts"] == {
        "safe": 0,
        "review": 11,
        "dangerous": 9,
        "irreversible": 0,
    }
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-ohai-secret-do-not-leak" not in encoded
    assert "FIXTURE_OHAI_ENDPOINT" not in encoded
    assert "fixture-ohai-inventory" not in encoded


def test_project_scan_discovers_standalone_chef_ohai_plugin_by_dsl(tmp_path: Path) -> None:
    plugin = tmp_path / "plugins" / "inventory.rb"
    plugin.parent.mkdir()
    plugin.write_text(
        """
Ohai.plugin(:Inventory) do
  provides 'inventory'
  collect_data do
    inventory Mash.new
  end
end
""",
        encoding="utf-8",
    )

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["error_count"] == 0
    assert payload["files"][0]["tool"] == "chef"
    assert payload["files"][0]["artifact_type"] == "ohai_plugin"


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


def test_project_scan_analyzes_chef_habitat_plans_and_hooks(tmp_path: Path) -> None:
    source = FIXTURES / "chef_habitat_risky" / "habitat"
    for relative in ("plan.sh", "plan.ps1", "hooks/run", "hooks/health-check"):
        target = tmp_path / "habitat" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((source / relative).read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 4
    assert payload["scanned_file_count"] == 4
    assert payload["error_count"] == 0
    assert {item["tool"] for item in payload["files"]} == {"chef-project"}
    assert {item["artifact_type"] for item in payload["files"]} == {
        "habitat_hook",
        "habitat_plan",
    }
    bash_plan = next(item for item in payload["files"] if item["path"].endswith("plan.sh"))
    assert bash_plan["language"] == "bash"
    assert bash_plan["variable_count"] == 14
    assert bash_plan["callback_count"] == 4
    assert bash_plan["command_count"] == 7
    assert bash_plan["dynamic_count"] > 0
    run_hook = next(item for item in payload["files"] if item["path"].endswith("hooks/run"))
    assert run_hook["hook_name"] == "run"
    assert run_hook["template_count"] == 1
    assert payload["total_changes"] == 55
    assert payload["risk_counts"]["dangerous"] == 41
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-habitat" not in encoded
    assert "fixture-password" not in encoded
    assert "example.invalid" not in encoded


def test_project_scan_analyzes_automation_controller_export(tmp_path: Path) -> None:
    fixture = FIXTURES / "ansible_controller_export_risky.json"
    target = tmp_path / "controller-export.json"
    target.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    result = payload["files"][0]
    assert result["tool"] == "ansible-project"
    assert result["artifact_type"] == "controller_export"
    assert result["asset_count"] == 12
    assert result["asset_type_count"] == 12
    assert payload["total_changes"] == 41
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-controller-password-do-not-leak" not in encoded
    assert "fixture-deploy" not in encoded
    assert "example.invalid" not in encoded


def test_project_scan_analyzes_event_driven_ansible_rulebook(tmp_path: Path) -> None:
    fixture = FIXTURES / "ansible_rulebook_risky.yml"
    target = tmp_path / "extensions" / "eda" / "rulebooks" / "remediate.yml"
    target.parent.mkdir(parents=True)
    target.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")

    payload = scan_project(tmp_path, display_root=".")

    assert payload["discovered_file_count"] == 1
    assert payload["scanned_file_count"] == 1
    assert payload["error_count"] == 0
    result = payload["files"][0]
    assert result["tool"] == "ansible-project"
    assert result["artifact_type"] == "rulebook"
    assert result["ruleset_count"] == 2
    assert result["source_count"] == 3
    assert result["rule_count"] == 7
    assert result["action_count"] == 8
    assert payload["total_changes"] == 44
    assert payload["decision"] == "block"
    encoded = json.dumps(payload)
    assert "fixture-rulebook-webhook-token-do-not-leak" not in encoded
    assert "fixture-edge-automation" not in encoded
    assert "events.example.invalid" not in encoded


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


def test_file_size_limit_records_validation_error_before_opening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "compose.yml"
    config.write_text("services: {}\n", encoding="utf-8")
    original_read_prefix = project_scan_module._read_prefix

    def guarded_read_prefix(path: Path, max_bytes: int) -> bytes:
        if path == config:
            raise AssertionError("oversized input content must not be opened")
        return original_read_prefix(path, max_bytes)

    monkeypatch.setattr(project_scan_module, "_read_prefix", guarded_read_prefix)

    payload = scan_project(tmp_path, display_root=".", max_file_bytes=1)

    assert payload["errors"] == [
        {"path": "compose.yml", "tool": "docker-compose", "code": "file-too-large"}
    ]
    assert payload["risk_counts"]["review"] == 1


def test_oversized_content_only_input_fails_closed_with_bounded_discovery_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "manifest.yml"
    manifest_source = b"apiVersion: v1\nkind: Pod\n" + b"# padding\n" * 20
    manifest.write_bytes(manifest_source)
    jenkinsfile = tmp_path / "Jenkinsfile"
    jenkinsfile.write_text(
        "pipeline {\n  stages {\n    echo 'ok'\n  }\n}\n",
        encoding="utf-8",
    )
    requested_sizes: list[int] = []
    original_read_prefix = project_scan_module._read_prefix

    def tracking_read_prefix(path: Path, max_bytes: int) -> bytes:
        if path == manifest:
            requested_sizes.append(max_bytes)
        return original_read_prefix(path, max_bytes)

    monkeypatch.setattr(project_scan_module, "_read_prefix", tracking_read_prefix)

    payload = scan_project(tmp_path, display_root=".", max_file_bytes=64)

    assert requested_sizes == [256 * 1024]
    assert payload["decision"] == "warn"
    assert payload["discovered_file_count"] == 2
    assert payload["scanned_file_count"] == 1
    assert payload["errors"] == [
        {"path": "manifest.yml", "tool": "kubernetes", "code": "file-too-large"}
    ]
    assert payload["files"][0]["path"] == "Jenkinsfile"
    assert payload["files"][0]["decision"] == "proceed"
    assert payload["files"][0]["risk"] == "safe"


def test_content_identification_requests_only_a_bounded_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "manifest.yml"
    source = b"apiVersion: v1\nkind: Pod\n"
    manifest.write_bytes(source)
    requested_sizes: list[int] = []
    original_read_prefix = project_scan_module._read_prefix

    def tracking_read_prefix(path: Path, max_bytes: int) -> bytes:
        requested_sizes.append(max_bytes)
        return original_read_prefix(path, max_bytes)

    monkeypatch.setattr(project_scan_module, "_read_prefix", tracking_read_prefix)

    assert identify_project_input(manifest, "manifest.yml") == "kubernetes"
    assert requested_sizes == [256 * 1024]


def test_secure_prefix_read_uses_descriptor_safety_flags_and_exact_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(b"x" * 64)
    observed_flags: list[int] = []
    original_open = project_scan_module.os.open

    def tracking_open(path: str | Path, flags: int, *, dir_fd: int | None = None) -> int:
        observed_flags.append(flags)
        if dir_fd is None:
            return original_open(path, flags)
        return original_open(path, flags, dir_fd=dir_fd)

    monkeypatch.setattr(project_scan_module.os, "open", tracking_open)

    assert project_scan_module._read_prefix(source, 17) == b"x" * 17
    assert observed_flags
    file_flags = observed_flags[-1]
    for flag_name in ("O_BINARY", "O_CLOEXEC", "O_NOINHERIT", "O_NOFOLLOW", "O_NONBLOCK"):
        flag = getattr(project_scan_module.os, flag_name, 0)
        if flag:
            assert file_flags & flag == flag
    directory_flag = getattr(project_scan_module.os, "O_DIRECTORY", 0)
    if project_scan_module.os.name != "nt" and directory_flag:
        assert any(flags & directory_flag == directory_flag for flags in observed_flags[:-1])


def test_secure_prefix_read_rejects_identity_swap_during_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "input.yml"
    replacement = tmp_path / "replacement.yml"
    displaced = tmp_path / "displaced.yml"
    source.write_text("apiVersion: v1\nkind: Pod\n", encoding="utf-8")
    replacement.write_text("apiVersion: v1\nkind: Secret\n", encoding="utf-8")
    original_open = project_scan_module.os.open

    swapped = False

    def swap_then_open(
        path: str | Path,
        flags: int,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        opening_target = (dir_fd is None and Path(path) == source) or (
            dir_fd is not None and project_scan_module.os.fspath(path) == source.name
        )
        if opening_target and not swapped:
            source.replace(displaced)
            replacement.replace(source)
            swapped = True
        if dir_fd is None:
            return original_open(path, flags)
        return original_open(path, flags, dir_fd=dir_fd)

    monkeypatch.setattr(project_scan_module.os, "open", swap_then_open)

    with pytest.raises(OSError, match="changed while it was opened"):
        project_scan_module._read_prefix(source, 256)


def test_secure_prefix_read_rejects_non_regular_opened_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "input.yml"
    source.write_text("apiVersion: v1\nkind: Pod\n", encoding="utf-8")
    directory_stat = project_scan_module.os.stat(tmp_path)
    monkeypatch.setattr(project_scan_module.os, "fstat", lambda descriptor: directory_stat)

    with pytest.raises(OSError, match="changed while it was opened"):
        project_scan_module._read_prefix(source, 256)


@pytest.mark.skipif(
    project_scan_module.os.name == "nt",
    reason="POSIX descriptor walk is not used on Windows",
)
def test_posix_secure_prefix_read_does_not_depend_on_procfs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "input.yml"
    content = b"apiVersion: v1\nkind: Pod\n"
    source.write_bytes(content)

    def reject_resolve(*args: object, **kwargs: object) -> Path:
        raise AssertionError("secure POSIX reads must not inspect /proc/self/fd")

    monkeypatch.setattr(Path, "resolve", reject_resolve)

    assert project_scan_module._read_prefix(source, len(content)) == content


@pytest.mark.skipif(
    project_scan_module.os.name == "nt",
    reason="POSIX descriptor walk is not used on Windows",
)
def test_posix_secure_prefix_read_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir()
    source = external / "input.yml"
    source.write_text("apiVersion: v1\nkind: Secret\n", encoding="utf-8")
    linked_ancestor = tmp_path / "project"
    try:
        linked_ancestor.symlink_to(external, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(OSError):
        project_scan_module._read_prefix(linked_ancestor / "input.yml", 256)


@pytest.mark.skipif(
    project_scan_module.os.name != "nt",
    reason="Windows handle verification is not used on POSIX",
)
def test_secure_prefix_read_rejects_ancestor_target_swap_even_with_matching_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    intended = tmp_path / "project" / "nested" / "input.yml"
    external = tmp_path / "external" / "nested" / "input.yml"
    intended.parent.mkdir(parents=True)
    external.parent.mkdir(parents=True)
    intended.write_text("apiVersion: v1\nkind: Pod\n", encoding="utf-8")
    external.write_text("apiVersion: v1\nkind: Secret\n", encoding="utf-8")
    intended_stat = project_scan_module.os.lstat(intended)
    original_open = project_scan_module.os.open

    def open_external_target(
        path: str | Path,
        flags: int,
        *,
        dir_fd: int | None = None,
    ) -> int:
        assert path == intended
        assert dir_fd is None
        return original_open(external, flags)

    monkeypatch.setattr(project_scan_module.os, "open", open_external_target)
    monkeypatch.setattr(project_scan_module.os, "fstat", lambda descriptor: intended_stat)

    with pytest.raises(OSError, match="changed while it was opened"):
        project_scan_module._read_prefix(intended, 256)


def test_file_identity_requires_nonzero_inode_for_both_sides() -> None:
    mode = project_scan_module.stat.S_IFREG
    missing_inode_left = project_scan_module.os.stat_result(
        (mode, 0, 7, 1, 0, 0, 10, 1, 1, 1)
    )
    missing_inode_right = project_scan_module.os.stat_result(
        (mode, 0, 7, 1, 0, 0, 10, 1, 1, 1)
    )
    strong_left = project_scan_module.os.stat_result((mode, 42, 7, 1, 0, 0, 10, 1, 1, 1))
    strong_right = project_scan_module.os.stat_result((mode, 42, 7, 1, 0, 0, 10, 1, 1, 1))

    assert not project_scan_module._same_file_identity(
        missing_inode_left,
        missing_inode_right,
    )
    assert not project_scan_module._same_file_identity(missing_inode_left, strong_right)
    assert project_scan_module._same_file_identity(strong_left, strong_right)


@pytest.mark.parametrize(
    ("extended", "plain"),
    [
        (r"\\?\C:\work\project\input.yml", r"C:\work\project\input.yml"),
        (
            r"\\?\UNC\server\share\project\input.yml",
            r"\\server\share\project\input.yml",
        ),
    ],
)
def test_windows_extended_path_normalization_matches_dos_and_unc_forms(
    extended: str,
    plain: str,
) -> None:
    normalize = project_scan_module._normalize_windows_path_for_comparison

    assert normalize(extended) == normalize(plain)
    assert normalize(plain) == normalize(extended)


def test_windows_extended_path_normalization_preserves_volume_guid_prefix() -> None:
    normalize = project_scan_module._normalize_windows_path_for_comparison
    volume_path = r"\\?\Volume{01234567-89AB-CDEF-0123-456789ABCDEF}\input.yml"

    normalized = normalize(volume_path)

    assert normalized.startswith(r"\\?\volume{")
    assert normalized != normalize(volume_path[4:])


def test_bounded_snapshot_reads_exactly_max_plus_one_when_cached_size_is_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "compose.yml"
    config.write_text("services:\n  web:\n    image: nginx\n", encoding="utf-8")
    requested_sizes: list[int] = []
    original_read_prefix = project_scan_module._read_prefix

    def tracking_read_prefix(path: Path, max_bytes: int) -> bytes:
        requested_sizes.append(max_bytes)
        return original_read_prefix(path, max_bytes)

    monkeypatch.setattr(project_scan_module, "_read_prefix", tracking_read_prefix)
    discovered = [
        DiscoveredInput(
            path=config,
            relative_path="compose.yml",
            tool="docker-compose",
            size=1,
        )
    ]

    payload = scan_discovered_inputs(
        discovered,
        display_root=".",
        max_file_bytes=16,
    )

    assert payload["errors"] == [
        {"path": "compose.yml", "tool": "docker-compose", "code": "file-too-large"}
    ]
    assert payload["scanned_file_count"] == 0
    assert requested_sizes == [17]


def test_analyzer_reads_stable_snapshot_after_source_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "nested" / "Jenkinsfile"
    source.parent.mkdir()
    original_source = "pipeline {\n  stages {\n    echo 'ok'\n  }\n}\n"
    source.write_text(original_source, encoding="utf-8")
    analyzed_paths: list[Path] = []

    def analyze_snapshot(item: DiscoveredInput, *, framework: str | None):
        assert framework is None
        analyzed_paths.append(item.path)
        source.write_text("pipeline { malicious mutation }\n", encoding="utf-8")
        assert item.path != source
        assert item.path.parts[-2:] == ("nested", "Jenkinsfile")
        assert item.path.read_text(encoding="utf-8") == original_source
        return {
            "decision": "proceed",
            "risk": "safe",
            "risk_counts": {
                "safe": 1,
                "review": 0,
                "dangerous": 0,
                "irreversible": 0,
            },
            "total_changes": 1,
            "required_checks": [],
            "reason": "Snapshot remained stable.",
        }

    monkeypatch.setattr(project_scan_module, "_analyze_input", analyze_snapshot)
    discovered = [
        DiscoveredInput(
            path=source,
            relative_path="nested/Jenkinsfile",
            tool="jenkins",
            size=len(original_source.encode("utf-8")),
        )
    ]

    payload = scan_discovered_inputs(discovered, display_root=".", max_file_bytes=128)

    assert payload["errors"] == []
    assert payload["files"][0]["path"] == "nested/Jenkinsfile"
    assert payload["files"][0]["decision"] == "proceed"
    assert source.read_text(encoding="utf-8") == "pipeline { malicious mutation }\n"
    assert len(analyzed_paths) == 1
    assert not analyzed_paths[0].exists()


def test_each_snapshot_is_removed_before_the_next_file_is_analyzed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovered: list[DiscoveredInput] = []
    for directory in ("first", "second"):
        source = tmp_path / directory / "Jenkinsfile"
        source.parent.mkdir()
        content = f"pipeline {{ stages {{ echo '{directory}' }} }}\n"
        source.write_text(content, encoding="utf-8")
        discovered.append(
            DiscoveredInput(
                path=source,
                relative_path=f"{directory}/Jenkinsfile",
                tool="jenkins",
                size=len(content.encode("utf-8")),
            )
        )
    analyzed_paths: list[Path] = []

    def analyze_snapshot(item: DiscoveredInput, *, framework: str | None):
        assert framework is None
        if analyzed_paths:
            assert not analyzed_paths[-1].exists()
        analyzed_paths.append(item.path)
        assert item.path.is_file()
        return {
            "decision": "proceed",
            "risk": "safe",
            "risk_counts": {
                "safe": 1,
                "review": 0,
                "dangerous": 0,
                "irreversible": 0,
            },
            "total_changes": 1,
            "required_checks": [],
            "reason": "Snapshot remained stable.",
        }

    monkeypatch.setattr(project_scan_module, "_analyze_input", analyze_snapshot)

    payload = scan_discovered_inputs(discovered, display_root=".")

    assert payload["errors"] == []
    assert payload["scanned_file_count"] == 2
    assert len(analyzed_paths) == 2
    assert analyzed_paths[0].parents[1] == analyzed_paths[1].parents[1]
    assert all(not path.exists() for path in analyzed_paths)


def test_partial_snapshot_write_is_removed_before_scanning_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovered: list[DiscoveredInput] = []
    for directory in ("first", "second"):
        source = tmp_path / directory / "Jenkinsfile"
        source.parent.mkdir()
        content = f"pipeline {{ stages {{ echo '{directory}' }} }}\n"
        source.write_text(content, encoding="utf-8")
        discovered.append(
            DiscoveredInput(
                path=source,
                relative_path=f"{directory}/Jenkinsfile",
                tool="jenkins",
                size=len(content.encode("utf-8")),
            )
        )
    partial_snapshot: list[Path] = []
    original_write_bytes = Path.write_bytes

    def fail_first_snapshot_write(path: Path, data: bytes) -> int:
        if not partial_snapshot:
            with path.open("wb") as snapshot:
                snapshot.write(data[:1])
            partial_snapshot.append(path)
            raise OSError("partial snapshot write")
        return original_write_bytes(path, data)

    def analyze_second_snapshot(item: DiscoveredInput, *, framework: str | None):
        assert framework is None
        assert len(partial_snapshot) == 1
        assert not partial_snapshot[0].exists()
        return {
            "decision": "proceed",
            "risk": "safe",
            "risk_counts": {
                "safe": 1,
                "review": 0,
                "dangerous": 0,
                "irreversible": 0,
            },
            "total_changes": 1,
            "required_checks": [],
            "reason": "Partial predecessor was removed.",
        }

    monkeypatch.setattr(Path, "write_bytes", fail_first_snapshot_write)
    monkeypatch.setattr(project_scan_module, "_analyze_input", analyze_second_snapshot)

    payload = scan_discovered_inputs(discovered, display_root=".")

    assert payload["scanned_file_count"] == 1
    assert payload["errors"] == [
        {"path": "first/Jenkinsfile", "tool": "jenkins", "code": "unreadable"}
    ]


@pytest.mark.parametrize(
    "relative_path",
    [
        "../escape.yml",
        "/absolute.yml",
        "nested/../../escape.yml",
    ],
)
def test_scan_rejects_universally_unsafe_snapshot_relative_paths(
    tmp_path: Path,
    relative_path: str,
) -> None:
    source = tmp_path / "compose.yml"
    source.write_text("services: {}\n", encoding="utf-8")
    discovered = [
        DiscoveredInput(
            path=source,
            relative_path=relative_path,
            tool="docker-compose",
            size=source.stat().st_size,
        )
    ]

    payload = scan_discovered_inputs(discovered, display_root=".")

    assert payload["errors"] == [
        {"path": relative_path, "tool": "docker-compose", "code": "unreadable"}
    ]
    assert payload["scanned_file_count"] == 0


@pytest.mark.parametrize(
    "relative_path",
    [
        "C:/escape.yml",
        "nested/D:escape.yml",
        "nested/input.yml:stream",
        "nested/CON",
        "nested/CON .txt",
        "nested/CONIN$",
        "nested/aux.txt",
        "nested/COM1.yml",
        "nested/trailing-dot.",
        "nested/trailing-space ",
        "nested/invalid?.yml",
        "nested/control\x01.yml",
    ],
)
def test_windows_snapshot_paths_reject_invalid_or_reserved_components(
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    monkeypatch.setattr(project_scan_module.os, "name", "nt")

    assert project_scan_module._snapshot_relative_parts(relative_path) is None


@pytest.mark.parametrize(
    "relative_path",
    [
        "aux.yaml",
        "nested/CON.yaml",
        "team:prod.yaml",
        "question?.yaml",
        r"nested/team\prod.yaml",
        "C:/escape.yml",
    ],
)
def test_posix_snapshot_paths_accept_valid_windows_specific_names(
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    monkeypatch.setattr(project_scan_module.os, "name", "posix")

    assert project_scan_module._snapshot_relative_parts(relative_path) == tuple(
        project_scan_module.PurePosixPath(relative_path).parts
    )


def test_scan_sanitizes_temporary_snapshot_allocation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "Jenkinsfile"
    content = "pipeline { stages { echo 'ok' } }\n"
    source.write_text(content, encoding="utf-8")
    discovered = [
        DiscoveredInput(
            path=source,
            relative_path="Jenkinsfile",
            tool="jenkins",
            size=len(content.encode("utf-8")),
        )
    ]

    def fail_allocation(*, prefix: str):
        assert prefix == "readtheplan-project-scan-"
        raise OSError("sensitive temporary root")

    monkeypatch.setattr(project_scan_module.tempfile, "TemporaryDirectory", fail_allocation)

    with pytest.raises(ProjectScanError) as exc_info:
        scan_discovered_inputs(discovered, display_root=".")

    assert str(exc_info.value) == (
        "project scan temporary snapshot could not be created or cleaned up"
    )
    assert "sensitive" not in str(exc_info.value)


def test_scan_sanitizes_temporary_snapshot_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot_root = tmp_path / "snapshot-root"
    source = tmp_path / "Jenkinsfile"
    content = "pipeline { stages { echo 'ok' } }\n"
    source.write_text(content, encoding="utf-8")
    discovered = [
        DiscoveredInput(
            path=source,
            relative_path="Jenkinsfile",
            tool="jenkins",
            size=len(content.encode("utf-8")),
        )
    ]

    class CleanupFailure:
        def __enter__(self) -> str:
            snapshot_root.mkdir()
            return str(snapshot_root)

        def __exit__(self, *args) -> None:
            raise OSError("sensitive cleanup path")

    monkeypatch.setattr(
        project_scan_module.tempfile,
        "TemporaryDirectory",
        lambda *, prefix: CleanupFailure(),
    )

    with pytest.raises(ProjectScanError) as exc_info:
        scan_discovered_inputs(discovered, display_root=".")

    assert str(exc_info.value) == (
        "project scan temporary snapshot could not be created or cleaned up"
    )
    assert "sensitive" not in str(exc_info.value)


def test_scan_avoids_temporary_storage_for_empty_and_rejected_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "compose.yml"
    source.write_text("services: {}\n", encoding="utf-8")

    def unexpected_allocation(*, prefix: str):
        raise AssertionError(f"unexpected temporary allocation: {prefix}")

    monkeypatch.setattr(
        project_scan_module.tempfile,
        "TemporaryDirectory",
        unexpected_allocation,
    )

    empty = scan_discovered_inputs([], display_root=".")
    rejected = scan_discovered_inputs(
        [
            DiscoveredInput(
                path=source,
                relative_path="compose.yml",
                tool="docker-compose",
                size=source.stat().st_size,
            ),
            DiscoveredInput(
                path=source,
                relative_path="unreadable.yml",
                tool="docker-compose",
                size=-1,
            ),
        ],
        display_root=".",
        max_file_bytes=1,
    )

    assert empty["discovered_file_count"] == 0
    assert rejected["errors"] == [
        {"path": "compose.yml", "tool": "docker-compose", "code": "file-too-large"},
        {"path": "unreadable.yml", "tool": "docker-compose", "code": "unreadable"},
    ]


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
