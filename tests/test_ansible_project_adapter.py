from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

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


def test_molecule_surfaces_provider_isolation_supply_chain_and_execution_risk() -> None:
    changes = _changes("ansible_molecule_risky/molecule/default/molecule.yml")
    by_type = {change.resource_type: change for change in changes}
    dangerous_types = {change.resource_type for change in changes if change.risk == "dangerous"}

    dangerous = {
        "ansible_project_molecule_dependency_execution",
        "ansible_project_molecule_dependency_command",
        "ansible_project_molecule_dependency_tls_verification",
        "ansible_project_molecule_dependency_literal_secret",
        "ansible_project_molecule_driver_boundary",
        "ansible_project_molecule_custom_driver",
        "ansible_project_molecule_login_command",
        "ansible_project_molecule_connection_override",
        "ansible_project_molecule_platform_image",
        "ansible_project_molecule_platform_isolation",
        "ansible_project_molecule_platform_volume",
        "ansible_project_molecule_platform_ports",
        "ansible_project_molecule_platform_runtime",
        "ansible_project_molecule_provider_options",
        "ansible_project_molecule_provider_tls_verification",
        "ansible_project_molecule_platform_literal_secret",
        "ansible_project_molecule_ansible_arguments",
        "ansible_project_molecule_ansible_configuration",
        "ansible_project_molecule_playbook_boundary",
        "ansible_project_molecule_inventory_injection",
        "ansible_project_molecule_scenario_mutation",
        "ansible_project_molecule_custom_sequence_step",
        "ansible_project_molecule_verifier_execution",
        "ansible_project_molecule_lint_command",
    }
    assert dangerous <= dangerous_types
    assert by_type["ansible_project_molecule_platform_scope"].risk == "review"
    assert by_type["ansible_project_molecule_unmanaged_platform"].risk == "review"
    assert by_type["ansible_project_molecule_idempotence_omitted"].risk == "review"
    assert by_type["ansible_project_molecule_boundary"].risk == "review"


def test_molecule_explanations_and_metadata_do_not_expose_values() -> None:
    fixture = "ansible_molecule_risky/molecule/default/molecule.yml"
    data = parse_ansible_project(
        (FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture
    )
    gate = analyze_ansible_project(data)
    encoded = json.dumps(gate)

    assert gate["artifact_type"] == "molecule"
    assert gate["platform_count"] == 2
    assert "privileged-platform" not in encoded
    assert "fixture-molecule-registry-password-do-not-leak" not in encoded
    assert "fixture-molecule-inventory-password-do-not-leak" not in encoded
    assert "MOLECULE_VERIFY_TOKEN" not in encoded


def test_collection_metadata_surfaces_dependencies_packaging_and_urls() -> None:
    changes = _changes("ansible_content_policy_risky/galaxy.yml")
    by_type = {change.resource_type: change for change in changes}
    dependencies = [
        change
        for change in changes
        if change.resource_type == "ansible_project_collection_metadata_dependency"
    ]

    assert len(dependencies) == 2
    assert {change.risk for change in dependencies} == {"dangerous", "review"}
    assert by_type["ansible_project_collection_metadata_insecure_url"].risk == "dangerous"
    assert by_type["ansible_project_collection_metadata_build_ignore"].risk == "dangerous"
    assert by_type["ansible_project_collection_metadata_manifest"].risk == "review"
    assert by_type["ansible_project_collection_metadata_prerelease"].risk == "review"
    assert by_type["ansible_project_collection_metadata_boundary"].risk == "review"


def test_role_metadata_surfaces_recursive_execution_and_embedded_specs() -> None:
    fixture = "ansible_content_policy_risky/roles/risky_role/meta/main.yml"
    changes = _changes(fixture)
    by_type = {change.resource_type: change for change in changes}
    dependencies = [
        change
        for change in changes
        if change.resource_type == "ansible_project_role_metadata_dependency"
    ]

    assert len(dependencies) == 2
    assert {change.risk for change in dependencies} == {"dangerous", "review"}
    assert by_type["ansible_project_role_metadata_duplicate_execution"].risk == "dangerous"
    assert by_type["ansible_project_role_metadata_collection_resolution"].risk == "review"
    assert by_type["ansible_project_argument_spec_secret_logging"].risk == "dangerous"
    assert by_type["ansible_project_argument_spec_literal_secret"].risk == "dangerous"
    assert by_type["ansible_project_role_metadata_boundary"].risk == "review"


def test_runtime_metadata_surfaces_loader_redirection_and_action_groups() -> None:
    changes = _changes("ansible_content_policy_risky/meta/runtime.yml")
    by_type = {change.resource_type: change for change in changes}

    assert by_type["ansible_project_runtime_ansible_compatibility"].risk == "dangerous"
    assert by_type["ansible_project_runtime_plugin_redirect"].risk == "dangerous"
    assert by_type["ansible_project_runtime_plugin_lifecycle"].risk == "review"
    assert by_type["ansible_project_runtime_import_redirect"].risk == "dangerous"
    assert by_type["ansible_project_runtime_action_groups"].risk == "dangerous"
    assert by_type["ansible_project_runtime_metadata_boundary"].risk == "review"


def test_argument_specs_surface_secret_logging_defaults_and_validation_gaps() -> None:
    fixture = "ansible_content_policy_risky/roles/risky_role/meta/argument_specs.yml"
    data = parse_ansible_project(
        (FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture
    )
    gate = analyze_ansible_project(data)
    changes = AnsibleProjectAdapter().analyze(data, tool_name="Ansible project")
    by_type = {change.resource_type: change for change in changes}

    assert data["ansible_project"]["artifact_type"] == "argument_specs"
    assert by_type["ansible_project_argument_spec_secret_logging"].risk == "dangerous"
    assert by_type["ansible_project_argument_spec_literal_secret"].risk == "dangerous"
    assert by_type["ansible_project_argument_spec_validation_gap"].risk == "dangerous"
    assert by_type["ansible_project_argument_spec_dynamic_value"].risk == "review"
    assert "fixture-argument-token-do-not-leak" not in json.dumps(gate)
    assert "fixture_private_key" not in json.dumps(gate)


def test_ansible_lint_config_surfaces_policy_bypasses_and_redacts_values() -> None:
    fixture = "ansible_content_policy_risky/.ansible-lint"
    data = parse_ansible_project(
        (FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture
    )
    gate = analyze_ansible_project(data)
    changes = AnsibleProjectAdapter().analyze(data, tool_name="Ansible project")
    by_type = {change.resource_type: change for change in changes}

    dangerous = {
        "ansible_project_lint_skipped_rules",
        "ansible_project_lint_downgraded_rules",
        "ansible_project_lint_excluded_content",
        "ansible_project_lint_default_rules_disabled",
        "ansible_project_lint_action_validation_disabled",
        "ansible_project_lint_custom_rule_execution",
        "ansible_project_lint_extra_vars",
    }
    assert dangerous <= set(by_type)
    assert {by_type[kind].risk for kind in dangerous} == {"dangerous"}
    assert by_type["ansible_project_lint_mocked_content"].risk == "review"
    assert by_type["ansible_project_lint_scope_selection"].risk == "review"
    assert by_type["ansible_project_lint_source_rewrite"].risk == "review"
    assert by_type["ansible_project_lint_reduced_profile"].risk == "review"
    assert "fixture-lint-password-do-not-leak" not in json.dumps(gate)


@pytest.mark.parametrize(
    ("filename", "source", "error"),
    [
        ("galaxy.yml", "name: incomplete\n", "missing required"),
        ("roles/demo/meta/main.yml", "dependencies: nope\n", "must be a list"),
        ("meta/runtime.yml", "plugin_routing: []\n", "must be a mapping"),
        ("meta/argument_specs.yml", "argument_specs: []\n", "one argument_specs"),
        (".ansible-lint", "skip_list: schema\n", "must be a list"),
        (".ansible-lint", "skip_list: []\nskip_list: []\n", "duplicate YAML key"),
    ],
)
def test_content_policy_parsers_reject_malformed_canonical_files(
    filename: str, source: str, error: str
) -> None:
    with pytest.raises(AnsibleProjectInputError, match=error):
        parse_ansible_project(source, filename=filename)


def test_digest_pinned_minimal_molecule_scenario_stays_review_only() -> None:
    digest = "b" * 64
    data = parse_ansible_project(
        f"""
driver:
  name: default
platforms:
  - name: isolated
    image: registry.example.test/automation/test@sha256:{digest}
scenario:
  test_sequence:
    - converge
    - idempotence
    - verify
    - destroy
""",
        filename="molecule/default/molecule.yml",
    )

    changes = AnsibleProjectAdapter().analyze(data, tool_name="Ansible project")
    assert data["ansible_project"]["artifact_type"] == "molecule"
    assert {change.risk for change in changes} == {"dangerous", "review"}
    assert {change.resource_type for change in changes if change.risk == "dangerous"} == {
        "ansible_project_molecule_driver_boundary",
        "ansible_project_molecule_scenario_mutation",
    }


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
        ("molecule.yml", "platforms: nope\n", "platforms must be a list"),
        ("molecule.yml", "platforms:\n  - image: alpine\n", "name must be"),
        ("molecule.yml", "platforms: []\nunknown: true\n", "unsupported top-level"),
        (
            "molecule.yml",
            "platforms: []\nscenario:\n  test_sequence: converge\n",
            "string list",
        ),
        ("molecule.yml", "dependency: {}\nplatforms: []\n", "dependency name"),
        (
            "molecule.yml",
            "driver:\n  name: mystery\nplatforms: []\n",
            "driver name is unsupported",
        ),
        (
            "molecule.yml",
            "ansible:\n  executor:\n    args: become\n",
            "executor args must be a mapping",
        ),
        (
            "molecule.yml",
            "platforms: &platforms\n  - name: one\n    groups: *platforms\n",
            "recursive YAML alias",
        ),
        (
            "molecule.yml",
            "platforms: []\nscenario: {}\nscenario: {}\n",
            "duplicate YAML key",
        ),
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


def test_controller_export_surfaces_execution_identity_rbac_and_automation_without_values() -> None:
    changes = _changes("ansible_controller_export_risky.json")
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps(
        [{"address": change.address, "explanation": change.explanation} for change in changes]
    )

    assert len(changes) == 41
    assert sum(change.risk == "dangerous" for change in changes) == 32
    assert sum(change.risk == "review" for change in changes) == 9
    assert "ansible_project_controller_credential_type" in kinds
    assert "ansible_project_controller_mutable_project_revision" in kinds
    assert "ansible_project_controller_inventory_launch_update" in kinds
    assert "ansible_project_controller_mutable_execution_environment" in kinds
    assert "ansible_project_controller_privilege_escalation" in kinds
    assert "ansible_project_controller_workflow_graph" in kinds
    assert "ansible_project_controller_rbac" in kinds
    assert "ansible_project_controller_import_boundary" in kinds
    for sensitive in (
        "fixture-controller-password-do-not-leak",
        "fixture-credential-secret-do-not-leak",
        "fixture-job-token-do-not-leak",
        "fixture-notification-token-do-not-leak",
        "fixture-survey-password-do-not-leak",
        "fixture-user",
        "fixture-password",
        "example.invalid",
        "fixture-deploy",
        "fixture-host",
    ):
        assert sensitive not in encoded


def test_controller_export_supports_module_assets_wrapper_and_content_detection() -> None:
    source = """
assets:
  credentials:
    - name: fixture
      inputs:
        password: $encrypted$
      natural_key:
        name: fixture
        type: credential
  schedules:
    - name: disabled
      enabled: false
      natural_key:
        name: disabled
        type: schedule
"""
    data = parse_ansible_project(source, filename="arbitrary-result.yml")
    changes = AnsibleProjectAdapter().analyze(data)

    assert data["ansible_project"]["artifact_type"] == "controller_export"
    assert data["ansible_project"]["document"]["wrapped_assets"] is True
    assert {change.risk for change in changes} == {"review"}
    assert not any(
        change.resource_type == "ansible_project_controller_literal_secret"
        for change in changes
    )


@pytest.mark.parametrize(
    ("source", "error"),
    [
        ("ordinary: yaml\n", "not a recognized Automation Controller"),
        ("projects: {}\n", "projects must be a list"),
        ("projects:\n  - nope\n", "entries must be mappings"),
        ("projects:\n  - name: missing-key\n", "require a natural_key"),
        (
            "projects:\n  - natural_key: {type: inventory}\n",
            "unexpected natural_key type",
        ),
        (
            "projects:\n  - natural_key: {name: one, type: project}\n"
            "  - natural_key: {name: one, type: project}\n",
            "duplicate natural_key",
        ),
        (
            "projects:\n  - natural_key: {type: project}\nunknown_assets: []\n",
            "unsupported resource types",
        ),
        (
            "projects:\n  - natural_key: {type: project}\n    related: []\n",
            "related data must be a mapping",
        ),
        (
            "projects:\n  - natural_key: {type: project}\n    name: one\n"
            "    name: two\n",
            "duplicate YAML key",
        ),
    ],
)
def test_controller_export_parser_rejects_malformed_canonical_bundles(
    source: str, error: str
) -> None:
    with pytest.raises(AnsibleProjectInputError, match=error):
        parse_ansible_project(source, filename="controller-export.yml")


def test_controller_export_gate_and_cli_expose_only_structural_counts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = FIXTURES / "ansible_controller_export_risky.json"
    data = parse_ansible_project(path.read_text(encoding="utf-8"), filename=str(path))
    gate = analyze_ansible_project(data)

    assert gate["adapter"] == "ansible-project"
    assert gate["artifact_type"] == "controller_export"
    assert gate["asset_count"] == 12
    assert gate["asset_type_count"] == 12
    assert gate["total_changes"] == 41
    assert gate["decision"] == "block"

    assert main(["ansible-project", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    encoded = json.dumps(payload)
    assert payload["risk_counts"]["dangerous"] == 32
    assert payload["asset_count"] == 12
    assert "fixture-controller-password-do-not-leak" not in encoded
    assert "fixture-deploy" not in encoded
    assert "example.invalid" not in encoded
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


def test_rulebook_surfaces_event_ingress_execution_and_runtime_risk_without_values() -> None:
    changes = _changes("ansible_rulebook_risky.yml")
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps(
        [{"address": change.address, "explanation": change.explanation} for change in changes]
    )

    assert len(changes) == 44
    assert sum(change.risk == "dangerous" for change in changes) == 30
    assert sum(change.risk == "review" for change in changes) == 14
    assert {
        "ansible_project_rulebook_action_retry",
        "ansible_project_rulebook_action_templating",
        "ansible_project_rulebook_controller_event_forwarding",
        "ansible_project_rulebook_event_filter",
        "ansible_project_rulebook_event_logging",
        "ansible_project_rulebook_event_source",
        "ansible_project_rulebook_fact_gathering",
        "ansible_project_rulebook_internal_event_state",
        "ansible_project_rulebook_literal_secret",
        "ansible_project_rulebook_multiple_rule_fanout",
        "ansible_project_rulebook_parallel_execution",
        "ansible_project_rulebook_plaintext_transport",
        "ansible_project_rulebook_run_job_template",
        "ansible_project_rulebook_run_module",
        "ansible_project_rulebook_run_playbook",
        "ansible_project_rulebook_run_workflow_template",
        "ansible_project_rulebook_runtime_boundary",
        "ansible_project_rulebook_shutdown",
        "ansible_project_rulebook_tls_verification",
        "ansible_project_rulebook_unconditional_rule",
        "ansible_project_rulebook_unlocked_parallel_action",
        "ansible_project_rulebook_webhook_ingress",
    } <= kinds
    for sensitive in (
        "fixture-rulebook-webhook-token-do-not-leak",
        "fixture-rulebook-filter-key-do-not-leak",
        "fixture-rulebook-root-password-do-not-leak",
        "fixture-rulebook-database-password-do-not-leak",
        "events.example.invalid",
        "fixture-workflow",
        "fixture-edge-automation",
    ):
        assert sensitive not in encoded


def test_rulebook_review_fixture_and_content_detection_stay_review_only() -> None:
    path = FIXTURES / "ansible_rulebook_review.yml"
    data = parse_ansible_project(
        path.read_text(encoding="utf-8"), filename="arbitrary-activation.yml"
    )
    changes = AnsibleProjectAdapter().analyze(data)

    assert data["ansible_project"]["artifact_type"] == "rulebook"
    assert {change.risk for change in changes} == {"review"}


@pytest.mark.parametrize(
    ("source", "error"),
    [
        ("{}\n", "non-empty list of rulesets"),
        (
            "- name: demo\n  hosts: localhost\n  rules:\n"
            "    - {name: one, condition: true, action: {none: null}}\n",
            "sources must be a non-empty list",
        ),
        (
            "- name: demo\n  hosts: localhost\n  sources: []\n  rules: []\n",
            "sources must be a non-empty list",
        ),
        (
            "- name: demo\n  hosts: localhost\n  sources:\n"
            "    - short_plugin: {}\n  rules:\n"
            "    - {name: one, condition: true, action: {none: null}}\n",
            "fully qualified collection name",
        ),
        (
            "- name: demo\n  hosts: localhost\n  sources:\n"
            "    - eda.builtin.range: {limit: 1}\n  rules:\n"
            "    - {name: one, condition: true, action: {unknown: null}}\n",
            "action is unsupported",
        ),
        (
            "- name: demo\n  hosts: localhost\n  sources:\n"
            "    - eda.builtin.range: {limit: 1}\n  rules:\n"
            "    - {name: same, condition: true, action: {none: null}}\n"
            "    - {name: same, condition: false, action: {none: null}}\n",
            "rule names must be unique",
        ),
        (
            "- name: demo\n  hosts: localhost\n  sources:\n"
            "    - eda.builtin.generic: &source\n"
            "        payload: *source\n  rules:\n"
            "    - {name: one, condition: true, action: {none: null}}\n",
            "recursive YAML alias",
        ),
        (
            "- name: demo\n  name: duplicate\n  hosts: localhost\n"
            "  sources: [{eda.builtin.range: {limit: 1}}]\n"
            "  rules: [{name: one, condition: true, action: {none: null}}]\n",
            "duplicate YAML key",
        ),
    ],
)
def test_rulebook_parser_rejects_malformed_canonical_files(
    source: str, error: str
) -> None:
    with pytest.raises(AnsibleProjectInputError, match=error):
        parse_ansible_project(source, filename="extensions/eda/rulebooks/demo.yml")


def test_rulebook_parser_enforces_source_size_and_nesting_limits() -> None:
    oversized = (
        "- name: demo\n  hosts: localhost\n  sources: []\n  rules: []\n#"
        + "x" * (2 * 1024 * 1024)
    )
    with pytest.raises(AnsibleProjectInputError, match="source size limit"):
        parse_ansible_project(oversized, filename="rulebook.yml")

    many_nodes = (
        "- name: demo\n  hosts: localhost\n  sources:\n"
        "    - eda.builtin.generic:\n        payload:\n"
        + "          - 0\n" * 100_001
        + "  rules:\n"
        "    - {name: one, condition: true, action: {none: null}}\n"
    )
    with pytest.raises(AnsibleProjectInputError, match="node count limit"):
        parse_ansible_project(many_nodes, filename="rulebook.yml")

    nested = "value"
    for _ in range(110):
        nested = {"nested": nested}
    source = yaml.safe_dump(
        [
            {
                "name": "demo",
                "hosts": "localhost",
                "sources": [{"eda.builtin.generic": nested}],
                "rules": [
                    {
                        "name": "one",
                        "condition": True,
                        "action": {"none": None},
                    }
                ],
            }
        ],
        sort_keys=False,
    )
    with pytest.raises(AnsibleProjectInputError, match="nesting depth limit"):
        parse_ansible_project(source, filename="rulebook.yml")


def test_rulebook_gate_and_cli_expose_only_structural_counts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = FIXTURES / "ansible_rulebook_risky.yml"
    data = parse_ansible_project(path.read_text(encoding="utf-8"), filename=str(path))
    gate = analyze_ansible_project(data)

    assert gate["adapter"] == "ansible-project"
    assert gate["artifact_type"] == "rulebook"
    assert gate["ruleset_count"] == 2
    assert gate["source_count"] == 3
    assert gate["rule_count"] == 7
    assert gate["action_count"] == 8
    assert gate["total_changes"] == 44
    assert gate["decision"] == "block"

    assert main(["ansible-project", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    encoded = json.dumps(payload)
    assert payload["risk_counts"]["dangerous"] == 30
    assert payload["ruleset_count"] == 2
    assert "fixture-rulebook-webhook-token-do-not-leak" not in encoded
    assert "fixture-edge-automation" not in encoded
    assert "events.example.invalid" not in encoded
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


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
            "ansible_molecule_risky/molecule/default/molecule.yml",
            "molecule",
            "block",
        ),
        ("ansible_controller_export_risky.json", "controller_export", "block"),
        ("ansible_rulebook_risky.yml", "rulebook", "block"),
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
        "ansible_molecule_risky/molecule/default/molecule.yml",
        "ansible_rulebook_risky.yml",
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
