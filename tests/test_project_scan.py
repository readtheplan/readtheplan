from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.cli import main
from readtheplan.project_scan import (
    ProjectScanError,
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
        ("Jenkinsfile.deploy", "jenkins"),
        ("cookbooks/base/recipes/default.rb", "chef"),
        ("manifests/site.pp", "puppet"),
        ("states/web.sls", "salt"),
        ("flake.nix", "nix"),
        ("policy/main.rego", "opa"),
        ("Vagrantfile", "vagrant"),
        ("Dockerfile.production", "dockerfile"),
        ("compose.yaml", "docker-compose"),
        (".github/workflows/deploy.yml", "github-actions"),
        (".gitlab-ci.yml", "gitlab-ci"),
        (".travis.yml", "travis-ci"),
        (".drone.yml", "drone-ci"),
        (".woodpecker.yml", "woodpecker-ci"),
        (".woodpecker/deploy.yaml", "woodpecker-ci"),
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
