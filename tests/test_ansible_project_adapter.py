from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.ansible_project import (
    AnsibleProjectAdapter,
    AnsibleProjectInputError,
    analyze_ansible_project,
    parse_ansible_project,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(fixture: str):
    data = parse_ansible_project(
        (FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture
    )
    return AnsibleProjectAdapter().analyze(data, tool_name="Ansible project")


def test_ansible_cfg_surfaces_transport_privilege_plugins_secrets_and_galaxy() -> None:
    changes = _changes("ansible_project_risky.cfg")
    by_type = {change.resource_type: change for change in changes}

    assert by_type["ansible_project_host_key_checking"].risk == "dangerous"
    assert by_type["ansible_project_ssh_host_verification"].risk == "dangerous"
    assert by_type["ansible_project_ssh_proxy_command"].risk == "dangerous"
    assert by_type["ansible_project_global_privilege_escalation"].risk == "dangerous"
    assert by_type["ansible_project_privileged_remote_user"].risk == "dangerous"
    assert by_type["ansible_project_world_readable_tempfiles"].risk == "dangerous"
    assert by_type["ansible_project_broken_conditionals"].risk == "dangerous"
    assert by_type["ansible_project_argument_logging"].risk == "dangerous"
    assert by_type["ansible_project_controller_plugin_path"].risk == "dangerous"
    assert by_type["ansible_project_callback_execution"].risk == "dangerous"
    assert by_type["ansible_project_inventory_plugin_execution"].risk == "dangerous"
    assert by_type["ansible_project_plaintext_galaxy_server"].risk == "dangerous"
    assert by_type["ansible_project_galaxy_tls_verification"].risk == "dangerous"
    assert by_type["ansible_project_inline_galaxy_credential"].risk == "dangerous"
    assert by_type["ansible_project_secret_file"].risk == "review"


def test_hardened_ansible_cfg_stays_review_only() -> None:
    changes = _changes("ansible_project_review.cfg")
    kinds = {change.resource_type for change in changes}
    assert "ansible_project_host_key_checking" not in kinds
    assert "ansible_project_global_privilege_escalation" not in kinds
    assert "ansible_project_controller_plugin_path" not in kinds
    assert "ansible_project_inventory_plugin_execution" not in kinds
    assert "ansible_project_inline_galaxy_credential" not in kinds
    assert {change.risk for change in changes} == {"review"}


def test_requirements_surface_mutability_transport_credentials_and_includes() -> None:
    changes = _changes("ansible_requirements_risky.yml")
    roles = [
        change for change in changes if change.resource_type == "ansible_project_role_dependency"
    ]
    collections = [
        change
        for change in changes
        if change.resource_type == "ansible_project_collection_dependency"
    ]
    assert len(roles) == 4
    assert len(collections) == 5
    assert sum(change.risk == "dangerous" for change in roles) == 4
    assert sum(change.risk == "dangerous" for change in collections) == 3
    assert any(change.resource_type == "ansible_project_requirements_include" for change in changes)
    assert any("embeds credentials" in change.explanation for change in roles)


def test_exact_requirements_and_signatures_stay_review_only() -> None:
    changes = _changes("ansible_requirements_review.yml")
    assert {change.risk for change in changes} == {"review"}
    assert any("signatures" in change.explanation for change in changes)


def test_static_yaml_inventory_surfaces_targeting_identity_and_execution_risk() -> None:
    changes = _changes("ansible_inventory_risky.yml")
    by_type = {change.resource_type: change for change in changes}

    assert by_type["ansible_project_inventory_scope"].risk == "review"
    assert by_type["ansible_project_inventory_literal_credential"].risk == "dangerous"
    assert by_type["ansible_project_inventory_secret_boundary"].risk == "review"
    assert by_type["ansible_project_inventory_privileged_identity"].risk == "dangerous"
    assert by_type["ansible_project_inventory_ssh_host_verification"].risk == "dangerous"
    assert by_type["ansible_project_inventory_ssh_proxy_command"].risk == "dangerous"
    assert by_type["ansible_project_inventory_local_execution"].risk == "dangerous"
    assert by_type["ansible_project_inventory_interpreter_override"].risk == "dangerous"
    assert by_type["ansible_project_inventory_private_key_file"].risk == "review"
    assert by_type["ansible_project_inventory_variable_evaluation"].risk == "dangerous"
    assert "3 unique managed host(s)" in by_type[
        "ansible_project_inventory_scope"
    ].explanation


def test_static_inventory_explanations_do_not_echo_hosts_or_secret_values() -> None:
    explanations = "\n".join(
        change.explanation for change in _changes("ansible_inventory_risky.yml")
    )

    assert "web-primary" not in explanations
    assert "database-primary" not in explanations
    assert "fixture-inventory-password-do-not-leak" not in explanations
    assert "fixture-private-key-material-do-not-leak" not in explanations


def test_ini_inventory_with_external_secrets_stays_review_only() -> None:
    changes = _changes("ansible_inventory_review.ini")
    kinds = {change.resource_type for change in changes}

    assert {change.risk for change in changes} == {"review"}
    assert "ansible_project_inventory_scope" in kinds
    assert "ansible_project_inventory_connection_identity" in kinds
    assert "ansible_project_inventory_secret_boundary" in kinds
    assert "ansible_project_inventory_private_key_file" in kinds


def test_extensionless_hosts_file_uses_ini_inventory_parser() -> None:
    data = parse_ansible_project(
        "host-one ansible_host=192.0.2.10\n", filename="inventories/prod/hosts"
    )

    assert data["ansible_project"]["artifact_type"] == "inventory_ini"
    changes = AnsibleProjectAdapter().analyze(data, tool_name="Ansible project")
    assert "1 unique managed host(s)" in changes[0].explanation


def test_dynamic_inventory_plugin_surfaces_supply_chain_scope_and_api_risk() -> None:
    changes = _changes("ansible_inventory_plugin_risky.aws_ec2.yml")
    by_type = {change.resource_type: change for change in changes}

    dangerous = {
        "ansible_project_inventory_plugin_execution",
        "ansible_project_inventory_plugin_broad_scope",
        "ansible_project_inventory_plugin_literal_credential",
        "ansible_project_inventory_plugin_plaintext_endpoint",
        "ansible_project_inventory_plugin_tls_verification",
        "ansible_project_inventory_plugin_fail_open",
        "ansible_project_inventory_plugin_construction",
        "ansible_project_inventory_plugin_extra_vars",
    }
    assert dangerous <= set(by_type)
    assert {by_type[kind].risk for kind in dangerous} == {"dangerous"}
    assert by_type["ansible_project_inventory_plugin_secret_boundary"].risk == "review"
    assert by_type["ansible_project_inventory_plugin_cache"].risk == "review"
    assert by_type["ansible_project_inventory_plugin_identity"].risk == "review"

    explanations = "\n".join(change.explanation for change in changes)
    assert "fixture-aws-access-key-do-not-leak" not in explanations
    assert "AWS_SECRET_ACCESS_KEY" not in explanations


def test_execution_environment_surfaces_build_supply_chain_and_privilege_risk() -> None:
    changes = _changes("ansible_execution_environment/execution-environment.yml")
    by_type = {change.resource_type: change for change in changes}

    assert by_type["ansible_project_execution_environment_schema"].risk == "dangerous"
    assert by_type["ansible_project_execution_environment_image"].risk == "dangerous"
    assert by_type["ansible_project_execution_environment_build_file"].risk == "dangerous"
    assert by_type["ansible_project_execution_environment_build_command"].risk == "dangerous"
    assert by_type["ansible_project_execution_environment_literal_secret"].risk == "dangerous"
    assert by_type["ansible_project_execution_environment_root_user"].risk == "dangerous"
    assert by_type["ansible_project_execution_environment_container_init"].risk == "dangerous"
    assert by_type["ansible_project_execution_environment_hardening_bypass"].risk == "dangerous"
    assert by_type["ansible_project_execution_environment_mutable_tag"].risk == "dangerous"
    assert by_type["ansible_project_execution_environment_boundary"].risk == "review"
    assert "fixture-registry-password-do-not-leak" not in "\n".join(
        change.explanation for change in changes
    )


def test_navigator_surfaces_container_host_secret_and_command_risk() -> None:
    changes = _changes("ansible_navigator/ansible-navigator.yml")
    by_type = {change.resource_type: change for change in changes}

    assert by_type["ansible_project_navigator_host_execution"].risk == "dangerous"
    assert by_type["ansible_project_execution_environment_image"].risk == "dangerous"
    assert by_type["ansible_project_navigator_container_options"].risk == "dangerous"
    assert by_type["ansible_project_navigator_volume_mount"].risk == "review"
    assert by_type["ansible_project_navigator_secret_environment_boundary"].risk == "review"
    assert by_type["ansible_project_navigator_literal_secret"].risk == "dangerous"
    assert by_type["ansible_project_navigator_registry_tls"].risk == "dangerous"
    assert by_type["ansible_project_navigator_pull_policy"].risk == "review"
    assert by_type["ansible_project_navigator_ansible_arguments"].risk == "dangerous"
    assert by_type["ansible_project_navigator_exec_command"].risk == "dangerous"
    assert by_type["ansible_project_navigator_editor_command"].risk == "dangerous"
    assert by_type["ansible_project_navigator_debug_logging"].risk == "review"
    assert by_type["ansible_project_navigator_artifact_replay"].risk == "review"
    assert by_type["ansible_project_navigator_boundary"].risk == "review"
    assert "fixture-navigator-password-do-not-leak" not in "\n".join(
        change.explanation for change in changes
    )


def test_digest_pinned_execution_environment_stays_review_only() -> None:
    digest = "a" * 64
    data = parse_ansible_project(
        f"""
version: 3
images:
  base_image:
    name: registry.example.test/automation/ee@sha256:{digest}
dependencies:
  ansible_core:
    package_pip: ansible-core==2.18.6
options:
  user: 1000
""",
        filename="execution-environment.yml",
    )

    changes = AnsibleProjectAdapter().analyze(data, tool_name="Ansible project")
    assert data["ansible_project"]["artifact_type"] == "execution_environment"
    assert {change.risk for change in changes} == {"review"}


def test_navigator_json_uses_canonical_filename_routing() -> None:
    data = parse_ansible_project(
        '{"ansible-navigator":{"execution-environment":{"enabled":true}}}',
        filename="ansible-navigator.json",
    )

    assert data["ansible_project"]["artifact_type"] == "navigator"


@pytest.mark.parametrize(
    ("filename", "source", "error"),
    [
        ("execution-environment.yml", "version: true\n", "version must be an integer"),
        ("execution-environment.yml", "version: 3\nunknown: true\n", "unsupported"),
        ("ansible-navigator.yml", "[defaults]\nforks=5\n", "document start"),
        ("ansible-navigator.yml", "other: {}\n", "ansible-navigator mapping"),
    ],
)
def test_execution_layer_parser_rejects_malformed_canonical_files(
    filename: str, source: str, error: str
) -> None:
    with pytest.raises(AnsibleProjectInputError, match=error):
        parse_ansible_project(source, filename=filename)


@pytest.mark.parametrize(
    "source,error",
    [
        ("", "empty"),
        ("[web]\nhost = example.test\n", "must be attached"),
        ("- hosts: all\n  tasks: []\n", "Galaxy requirements"),
        ("roles:\n  - name: one\n  - name: one\n    name: two\n", "duplicate YAML key"),
        ("roles: {}\n", "must be YAML lists"),
    ],
)
def test_ansible_project_parser_rejects_unrelated_or_ambiguous_input(
    source: str, error: str
) -> None:
    with pytest.raises(AnsibleProjectInputError, match=error):
        parse_ansible_project(source)


@pytest.mark.parametrize(
    ("fixture", "artifact_type", "decision"),
    [
        ("ansible_project_risky.cfg", "config", "block"),
        ("ansible_requirements_risky.yml", "requirements", "block"),
        ("ansible_inventory_risky.yml", "inventory_yaml", "block"),
        ("ansible_inventory_review.ini", "inventory_ini", "warn"),
        (
            "ansible_execution_environment/execution-environment.yml",
            "execution_environment",
            "block",
        ),
        ("ansible_navigator/ansible-navigator.yml", "navigator", "block"),
        (
            "ansible_inventory_plugin_risky.aws_ec2.yml",
            "inventory_plugin",
            "block",
        ),
    ],
)
def test_ansible_project_gate_uses_shared_contract(
    fixture: str, artifact_type: str, decision: str
) -> None:
    data = parse_ansible_project(
        (FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture
    )
    gate = analyze_ansible_project(data)
    assert gate["adapter"] == "ansible-project"
    assert gate["artifact_type"] == artifact_type
    assert gate["decision"] == decision
    assert gate["total_changes"] == sum(gate["risk_counts"].values())


def test_ansible_project_cli_reads_both_formats(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for fixture in (
        "ansible_project_risky.cfg",
        "ansible_requirements_risky.yml",
        "ansible_inventory_risky.yml",
        "ansible_inventory_plugin_risky.aws_ec2.yml",
        "ansible_execution_environment/execution-environment.yml",
        "ansible_navigator/ansible-navigator.yml",
    ):
        source = tmp_path / Path(fixture).name
        source.write_text((FIXTURES / fixture).read_text(encoding="utf-8"), encoding="utf-8")
        assert main(["ansible-project", "--framework", "soc2", str(source)]) == 2
        payload = json.loads(capsys.readouterr().out)
        assert payload["adapter"] == "ansible-project"
        assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


def test_ansible_project_cli_reads_review_only_ini_inventory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "inventory.ini"
    source.write_text(
        (FIXTURES / "ansible_inventory_review.ini").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    assert main(["ansible-project", "--framework", "soc2", str(source)]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "ansible-project"
    assert payload["artifact_type"] == "inventory_ini"
    assert payload["decision"] == "warn"
    assert payload["risk_counts"]["dangerous"] == 0
