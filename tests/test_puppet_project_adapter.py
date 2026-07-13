from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.puppet_project import (
    PuppetProjectAdapter,
    PuppetProjectInputError,
    analyze_puppet_project,
    parse_puppet_project,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(fixture: str):
    data = parse_puppet_project((FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture)
    return PuppetProjectAdapter().analyze(data, tool_name="Puppet project")


def test_puppetfile_surfaces_transport_mutability_paths_and_ruby_execution() -> None:
    changes = _changes("Puppetfile.project-risky")
    dependencies = [
        change for change in changes if change.resource_type == "puppet_project_module_dependency"
    ]

    assert len(changes) == 10
    assert sum(change.risk == "dangerous" for change in changes) == 7
    assert len(dependencies) == 6
    assert sum(change.risk == "dangerous" for change in dependencies) == 4
    assert any("plaintext transport" in change.explanation for change in changes)
    assert any("install_path escapes" in change.explanation for change in changes)
    assert any(change.resource_type == "puppet_project_ruby_execution" for change in changes)


def test_metadata_surfaces_unbounded_dependencies_and_plaintext_source() -> None:
    changes = _changes("puppet_metadata_risky.json")
    dependencies = [
        change for change in changes if change.resource_type == "puppet_project_module_dependency"
    ]
    requirements = [
        change for change in changes if change.resource_type == "puppet_project_runtime_requirement"
    ]

    assert len(dependencies) == 4
    assert sum(change.risk == "dangerous" for change in dependencies) == 2
    assert requirements[0].risk == "dangerous"
    assert any(change.resource_type == "puppet_project_module_source" for change in changes)
    assert any(
        change.resource_type == "puppet_project_operating_system_support" for change in changes
    )


def test_hiera_surfaces_legacy_version_path_escape_custom_backend_and_secret() -> None:
    changes = _changes("hiera_project_risky.yaml")
    kinds = {change.resource_type for change in changes}

    assert sum(change.risk == "dangerous" for change in changes) == 4
    assert "puppet_project_legacy_hiera_version" in kinds
    assert "puppet_project_data_path_escape" in kinds
    assert "puppet_project_backend_secret" in kinds
    assert any(
        change.resource_type == "puppet_project_data_backend" and change.risk == "dangerous"
        for change in changes
    )


def test_hiera_v5_builtin_backends_and_relative_paths_stay_review_only() -> None:
    changes = _changes("hiera_project_review.yaml")
    assert {change.risk for change in changes} == {"review"}
    assert any(
        change.resource_type == "puppet_project_backend_credential_file" for change in changes
    )


def test_puppet_conf_surfaces_trust_execution_fail_open_and_secret_risks() -> None:
    changes = _changes("puppet_conf_risky.conf")
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps(
        [
            {
                "address": change.address,
                "explanation": change.explanation,
                "risk": change.risk,
            }
            for change in changes
        ]
    )

    assert len(changes) == 34
    assert sum(change.risk == "dangerous" for change in changes) == 23
    assert sum(change.risk == "review" for change in changes) == 11
    assert {
        "puppet_project_certificate_autosign",
        "puppet_project_certificate_revocation",
        "puppet_project_external_command",
        "puppet_project_external_node_classifier",
        "puppet_project_cached_catalog_only",
        "puppet_project_credential",
        "puppet_project_report_processors",
    } <= kinds
    assert "fixture-puppet-proxy-password-do-not-leak" not in encoded
    assert "fixture-puppet-header-token-do-not-leak" not in encoded
    assert "primary.internal.example" not in encoded


def test_puppet_conf_strong_trust_and_noop_remain_review_or_safe() -> None:
    changes = _changes("puppet_conf_review.conf")

    assert len(changes) == 15
    assert {change.risk for change in changes} == {"review", "safe"}
    assert sum(change.risk == "review" for change in changes) == 12
    assert sum(change.risk == "safe" for change in changes) == 3
    assert any(change.resource_type == "puppet_project_dry_run" for change in changes)


def test_bolt_project_surfaces_modules_plugins_endpoints_and_execution() -> None:
    source = FIXTURES / "bolt_project" / "bolt-project.yaml"
    data = parse_puppet_project(source.read_text(encoding="utf-8"), filename=str(source))
    changes = PuppetProjectAdapter().analyze(data)
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps([change.explanation for change in changes])

    assert data["puppet_project"]["artifact_type"] == "bolt_project"
    assert sum(change.risk == "dangerous" for change in changes) >= 10
    assert {
        "puppet_project_bolt_module_dependency",
        "puppet_project_bolt_module_path",
        "puppet_project_bolt_literal_credential",
        "puppet_project_bolt_external_command",
        "puppet_project_bolt_configured_plugin",
        "puppet_project_bolt_plugin_hook",
        "puppet_project_bolt_sensitive_output",
    } <= kinds
    assert "fixture-bolt-token-do-not-leak" not in encoded
    assert "fixture-plugin-password-do-not-leak" not in encoded


def test_bolt_inventory_surfaces_dynamic_scope_transport_trust_and_secrets() -> None:
    source = FIXTURES / "bolt_inventory" / "inventory.yaml"
    data = parse_puppet_project(source.read_text(encoding="utf-8"), filename="inventory.yaml")
    changes = PuppetProjectAdapter().analyze(data)
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps([change.explanation for change in changes])

    assert data["puppet_project"]["artifact_type"] == "bolt_inventory"
    assert sum(change.risk == "dangerous" for change in changes) >= 10
    assert {
        "puppet_project_bolt_dynamic_inventory",
        "puppet_project_bolt_literal_credential",
        "puppet_project_bolt_transport_verification",
        "puppet_project_bolt_plaintext_transport",
        "puppet_project_bolt_privileged_identity",
        "puppet_project_bolt_command_execution",
        "puppet_project_bolt_legacy_ssh_algorithm",
        "puppet_project_bolt_target_scope",
    } <= kinds
    assert "fixture-ssh-password-do-not-leak" not in encoded
    assert "fixture-private-key-do-not-leak" not in encoded
    assert "windows.internal.example" not in encoded


def test_hiera_defaults_surface_custom_backend_secrets_and_windows_path_escape() -> None:
    data = parse_puppet_project(
        "version: 5\n"
        "defaults:\n"
        "  datadir: C:\\\\puppet\\\\data\n"
        "  data_dig: company::dig\n"
        "  options:\n"
        "    access_token: literal-token\n"
    )
    changes = PuppetProjectAdapter().analyze(data)
    dangerous = {change.resource_type for change in changes if change.risk == "dangerous"}
    assert "puppet_project_data_path_escape" in dangerous
    assert "puppet_project_data_backend" in dangerous
    assert "puppet_project_backend_secret" in dangerous


def test_file_backed_hiera_level_requires_name_and_path() -> None:
    data = parse_puppet_project("version: 5\nhierarchy:\n  - data_hash: yaml_data\n")
    changes = PuppetProjectAdapter().analyze(data)
    dangerous = {change.resource_type for change in changes if change.risk == "dangerous"}
    assert "puppet_project_missing_hierarchy_name" in dangerous
    assert "puppet_project_missing_data_path" in dangerous


def test_missing_required_metadata_fields_are_dangerous() -> None:
    data = parse_puppet_project('{"name":"example-minimal","version":"1.0.0","dependencies":[]}')
    changes = PuppetProjectAdapter().analyze(data)
    missing = [
        change
        for change in changes
        if change.resource_type == "puppet_project_missing_metadata_field"
    ]
    assert {change.address for change in missing} == {
        "metadata.author",
        "metadata.license",
        "metadata.source",
        "metadata.summary",
    }
    assert {change.risk for change in missing} == {"dangerous"}


def test_known_puppetfile_directive_cannot_hide_same_line_execution() -> None:
    data = parse_puppet_project(
        "forge 'https://forge.puppet.com'; system './mutate'\nmod 'stdlib', '9.0.2'\n"
    )
    changes = PuppetProjectAdapter().analyze(data)
    assert any(change.resource_type == "puppet_project_ruby_execution" for change in changes)


def test_quote_scanner_handles_long_adversarial_escape_sequences_linearly() -> None:
    escaped = "\\\\a" * 20_000
    data = parse_puppet_project(
        f"forge 'https://forge.puppet.com'\n"
        f"mod 'payload', :git => 'https://example.test/{escaped}', :branch => 'main'\n"
    )
    changes = PuppetProjectAdapter().analyze(data)
    dependencies = [
        change for change in changes if change.resource_type == "puppet_project_module_dependency"
    ]
    assert len(dependencies) == 1
    assert dependencies[0].risk == "dangerous"


def test_puppet_conf_filename_rejects_setting_before_section() -> None:
    with pytest.raises(PuppetProjectInputError, match="appears before a section"):
        parse_puppet_project("server = one\n", filename="puppet.conf")


@pytest.mark.parametrize(
    ("source", "error"),
    [
        ("", "empty"),
        ("this is not a Puppetfile", "not a recognized"),
        ('{"hello":"world"}', "not recognized"),
        (
            '{"name":"one","name":"two","dependencies":[]}',
            "duplicate JSON key",
        ),
        ("version: 5\nhierarchy:\n  - name: one\n    name: two\n", "duplicate YAML key"),
        ("version: 5\nhierarchy: {}\n", "hierarchy must be a list"),
        ("version: 5\nunknown: true\n", "unsupported top-level"),
        (
            "version: 5\ndefaults:\n  data_hash: yaml_data\n  lookup_key: custom::lookup\n",
            "only one lookup function",
        ),
        ("[main]\nserver = one\nserver = two\n", "duplicate puppet.conf setting"),
        ("[main]\nserver = one\n[main]\nserver = two\n", "duplicate puppet.conf section"),
        ("[database]\nserver = one\n", "unsupported puppet.conf section"),
        (" [main]\nserver = one\n", "must not be indented"),
        ("[main]\nserver one\n", "invalid puppet.conf setting"),
        ("[main]\n# no settings\n", "not a populated puppet.conf"),
    ],
)
def test_parser_rejects_unrelated_duplicate_or_malformed_input(source: str, error: str) -> None:
    with pytest.raises(PuppetProjectInputError, match=error):
        parse_puppet_project(source)


@pytest.mark.parametrize(
    ("source", "filename", "error"),
    [
        ("name: one\nname: two\n", "bolt-project.yaml", "duplicate YAML key"),
        ("targets: nope\n", "inventory.yaml", "list or plugin mapping"),
        ("groups:\n  - targets: []\n", "inventory.yaml", "string name"),
        ("targets:\n  - alias: missing-identity\n", "inventory.yaml", "name or uri"),
    ],
)
def test_bolt_parser_rejects_duplicate_unrelated_or_malformed_input(
    source: str, filename: str, error: str
) -> None:
    with pytest.raises(PuppetProjectInputError, match=error):
        parse_puppet_project(source, filename=filename)


def test_minimal_bolt_project_and_inventory_are_valid() -> None:
    project = parse_puppet_project("format: human\n", filename="bolt-project.yaml")
    inventory = parse_puppet_project("config:\n  transport: ssh\n", filename="inventory.yaml")

    assert project["puppet_project"]["artifact_type"] == "bolt_project"
    assert inventory["puppet_project"]["artifact_type"] == "bolt_inventory"


def test_bolt_puppetdb_token_path_is_an_external_boundary_not_literal_secret() -> None:
    data = parse_puppet_project(
        "puppetdb:\n  token: ~/.puppetlabs/token\n", filename="bolt-project.yaml"
    )
    changes = PuppetProjectAdapter().analyze(data)

    assert any(
        change.resource_type == "puppet_project_bolt_credential_file_boundary" for change in changes
    )
    assert not any(
        change.resource_type == "puppet_project_bolt_literal_credential" for change in changes
    )


def test_r10k_surfaces_sources_deletion_execution_credentials_and_collisions() -> None:
    fixture = FIXTURES / "puppet_r10k_risky" / "r10k.yaml"
    data = parse_puppet_project(fixture.read_text(encoding="utf-8"), filename=str(fixture))
    changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")
    encoded = json.dumps(
        [{"address": change.address, "explanation": change.explanation} for change in changes]
    )

    assert data["puppet_project"]["artifact_type"] == "r10k"
    assert len(changes) == 40
    assert sum(change.risk == "dangerous" for change in changes) == 22
    assert sum(change.risk == "review" for change in changes) == 18
    assert any("executable Puppet environments" in change.explanation for change in changes)
    assert any("same basedir" in change.explanation for change in changes)
    assert any(
        "shell command for every candidate branch" in change.explanation for change in changes
    )
    assert any("literal Forge authorization token" in change.explanation for change in changes)
    assert any("Environment-level purge" in change.explanation for change in changes)
    assert any(
        "cache and managed environment directory overlap" in change.explanation
        for change in changes
    )
    for secret in (
        "fixture-proxy-user",
        "fixture-proxy-password",
        "fixture-postrun-token",
        "fixture-git-user",
        "fixture-git-password",
        "fixture-repo-proxy-password",
        "fixture-forge-token-do-not-leak",
        "fixture-mail-password-do-not-leak",
        "git.example.invalid",
        "proxy.example.invalid",
    ):
        assert secret not in encoded


def test_r10k_supports_legacy_source_and_settings_aliases() -> None:
    source = (
        "remote: ssh://git@code.example.invalid/control.git\n"
        "r10k_basedir: /etc/puppetlabs/code/environments\n"
        "git_settings:\n"
        f"  default_ref: {'a' * 40}\n"
        "forge_settings:\n"
        "  baseurl: https://forgeapi.puppet.com\n"
        "deploy_settings:\n"
        "  write_lock: maintenance\n"
    )
    data = parse_puppet_project(source, filename="r10k.yaml")
    changes = PuppetProjectAdapter().analyze(data)
    gate = analyze_puppet_project(data)

    assert gate["source_count"] == 1
    assert any("legacy global" in change.explanation for change in changes)
    assert any("immutable commit" in change.explanation for change in changes)
    assert any("write lock" in change.explanation for change in changes)


def test_environment_conf_surfaces_code_paths_commands_and_cache_policy() -> None:
    changes = _changes("puppet_server_policy_risky/environment.conf")
    by_type = {change.resource_type: change for change in changes}

    assert by_type["puppet_project_environment_module_path"].risk == "dangerous"
    assert by_type["puppet_project_environment_manifest"].risk == "dangerous"
    assert by_type["puppet_project_environment_config_version_command"].risk == "dangerous"
    assert by_type["puppet_project_environment_cache_refresh"].risk == "review"
    assert by_type["puppet_project_project_boundary"].risk == "review"


def test_puppetdb_conf_surfaces_transport_fail_open_and_partial_persistence() -> None:
    changes = _changes("puppet_server_policy_risky/puppetdb.conf")
    kinds = {change.resource_type for change in changes}

    assert {
        "puppet_project_puppetdb_endpoint",
        "puppet_project_puppetdb_fail_open",
        "puppet_project_puppetdb_command_broadcast",
        "puppet_project_puppetdb_submission_quorum",
        "puppet_project_puppetdb_timeout",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) == 4


def test_server_auth_surfaces_header_identity_wildcards_and_privileged_apis() -> None:
    data = parse_puppet_project(
        (FIXTURES / "puppet_server_policy_risky" / "auth.conf").read_text(encoding="utf-8"),
        filename="auth.conf",
    )
    changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")
    kinds = {change.resource_type for change in changes}
    gate = analyze_puppet_project(data)

    assert data["puppet_project"]["artifact_type"] == "server_auth"
    assert gate["rule_count"] == 3
    assert {
        "puppet_project_server_hocon_include",
        "puppet_project_server_hocon_substitution",
        "puppet_project_server_header_identity",
        "puppet_project_server_unauthenticated_access",
        "puppet_project_server_wildcard_identity",
        "puppet_project_server_broad_authorization",
        "puppet_project_server_privileged_api",
        "puppet_project_server_auth_precedence",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) == 8


def test_server_ca_surfaces_impersonation_capable_signing_options() -> None:
    changes = _changes("puppet_server_policy_risky/ca.conf")
    by_type = {change.resource_type: change for change in changes}

    assert by_type["puppet_project_server_ca_subject_alt_names"].risk == "dangerous"
    assert by_type["puppet_project_server_ca_authorization_extensions"].risk == "dangerous"
    assert by_type["puppet_project_server_ca_revocation_scope"].risk == "review"


def test_server_web_surfaces_plaintext_mtls_tls_and_audit_gaps() -> None:
    changes = _changes("puppet_server_policy_risky/webserver.conf")
    by_type = {change.resource_type: change for change in changes}

    assert by_type["puppet_project_server_client_authentication"].risk == "dangerous"
    assert by_type["puppet_project_server_plaintext_listener"].risk == "dangerous"
    assert by_type["puppet_project_server_network_exposure"].risk == "review"
    assert by_type["puppet_project_server_legacy_tls"].risk == "dangerous"
    assert by_type["puppet_project_server_tls_renegotiation"].risk == "dangerous"
    assert by_type["puppet_project_server_tls_material"].risk == "dangerous"
    assert by_type["puppet_project_server_access_logging"].risk == "review"


def test_server_runtime_surfaces_code_paths_environment_and_jruby_lifecycle() -> None:
    changes = _changes("puppet_server_policy_risky/puppetserver.conf")
    kinds = {change.resource_type for change in changes}

    assert {
        "puppet_project_server_hocon_substitution",
        "puppet_project_server_removed_setting",
        "puppet_project_server_ruby_code_path",
        "puppet_project_server_jruby_environment",
        "puppet_project_server_jruby_concurrency",
        "puppet_project_server_jruby_recycling",
        "puppet_project_server_jruby_multithreading",
    } <= kinds
    assert (
        sum(change.resource_type == "puppet_project_server_ruby_code_path" for change in changes)
        == 3
    )


def test_server_routes_surface_admin_ca_status_and_metrics_mounts() -> None:
    changes = _changes("puppet_server_policy_risky/web-routes.conf")

    assert any(
        change.resource_type == "puppet_project_server_api_routes" and change.risk == "dangerous"
        for change in changes
    )


def test_puppet_server_findings_do_not_expose_policy_or_secret_values() -> None:
    encoded: list[str] = []
    for filename in (
        "auth.conf",
        "puppetdb.conf",
        "puppetserver.conf",
        "web-routes.conf",
        "webserver.conf",
    ):
        data = parse_puppet_project(
            (FIXTURES / "puppet_server_policy_risky" / filename).read_text(encoding="utf-8"),
            filename=filename,
        )
        encoded.append(json.dumps(analyze_puppet_project(data)))
    output = "\n".join(encoded)

    for secret_or_identity in (
        "fixture-puppetdb-password-do-not-leak",
        "fixture-unauthenticated-rule-do-not-leak",
        "fixture-admin-rule-do-not-leak",
        "fixture-jruby-token-do-not-leak",
        "fixture-key-do-not-leak",
        "puppetdb.invalid",
        "fixture-admin",
    ):
        assert secret_or_identity not in output


def test_hardened_puppet_server_policy_stays_review_only() -> None:
    documents = (
        (
            "auth.conf",
            "authorization: {\n"
            "  version: 1\n"
            "  rules: [{\n"
            "    match-request: {\n"
            '      path: "/puppet/v3/catalog"\n'
            "      type: path\n"
            "      method: post\n"
            "    }\n"
            '    allow: ["primary.example.test"]\n'
            "    sort-order: 500\n"
            '    name: "catalog"\n'
            "  }]\n"
            "}\n",
        ),
        (
            "webserver.conf",
            "webserver: {\n"
            "  client-auth: need\n"
            "  ssl-host: 127.0.0.1\n"
            "  ssl-protocols: [TLSv1.2]\n"
            "  access-log-config: /etc/puppetlabs/request-logging.xml\n"
            "}\n",
        ),
        (
            "ca.conf",
            "certificate-authority: {\n"
            "  allow-subject-alt-names: false\n"
            "  allow-authorization-extensions: false\n"
            "  enable-infra-crl: true\n"
            "}\n",
        ),
    )
    for filename, source in documents:
        data = parse_puppet_project(source, filename=filename)
        changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")
        assert {change.risk for change in changes} == {"review"}


def test_default_puppet_server_routes_stay_review_only() -> None:
    source = """
web-router-service: {
  "puppetlabs.services.ca.certificate-authority-service/certificate-authority-service": "/puppet-ca"
  "puppetlabs.services.master.master-service/master-service": "/puppet"
  "puppetlabs.services.puppet-admin.puppet-admin-service/puppet-admin-service": "/puppet-admin-api"
  "puppetlabs.trapperkeeper.services.status.status-service/status-service": "/status"
  "puppetlabs.trapperkeeper.services.metrics.metrics-service/metrics-webservice": "/metrics"
}
"""
    data = parse_puppet_project(source, filename="web-routes.conf")
    changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")

    assert {change.risk for change in changes} == {"review"}


@pytest.mark.parametrize(
    ("source", "filename", "error"),
    [
        ("modulepath = one\nmodulepath = two\n", "environment.conf", "duplicate"),
        ("[main]\nmodulepath = modules\n", "environment.conf", "must not contain"),
        ("unknown = value\n", "environment.conf", "unsupported"),
        (
            "[main]\nserver_urls = https://one\n[server]\nport = 8081\n",
            "puppetdb.conf",
            "only a main",
        ),
        ("authorization: {\nversion: 1\nversion: 1\n}\n", "auth.conf", "duplicate HOCON"),
        ("webserver: { client-auth want }\n", "webserver.conf", "missing"),
        ("certificate-authority: { /* nope\n", "ca.conf", "unterminated block"),
        (
            "jruby-puppet: { environment-vars: { X: ${ } } }\n",
            "puppetserver.conf",
            "invalid substitution",
        ),
    ],
)
def test_server_policy_parsers_reject_ambiguous_or_malformed_input(
    source: str, filename: str, error: str
) -> None:
    with pytest.raises(PuppetProjectInputError, match=error):
        parse_puppet_project(source, filename=filename)


def test_hocon_substitution_concatenation_is_an_unresolved_boundary() -> None:
    data = parse_puppet_project(
        "jruby-puppet: {\n  server-code-dir: ${?PUPPET_BASE}/code\n}\n",
        filename="puppetserver.conf",
    )
    changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")

    assert any(
        change.resource_type == "puppet_project_server_hocon_substitution" for change in changes
    )
    assert "PUPPET_BASE" not in json.dumps(analyze_puppet_project(data))


def test_hocon_parser_rejects_excessive_nesting() -> None:
    source = "root: {\n" + ("child: {\n" * 101) + "value: 1\n" + ("}\n" * 102)

    with pytest.raises(PuppetProjectInputError, match="nesting exceeds"):
        parse_puppet_project(source, filename="puppetserver.conf")


def test_bolt_yaml_plan_surfaces_orchestration_without_leaking_values() -> None:
    fixture = "bolt_content_risky/modules/fixture/plans/deploy.yaml"
    data = parse_puppet_project((FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture)
    changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")
    gate = analyze_puppet_project(data)
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps(gate)

    assert data["puppet_project"]["artifact_type"] == "bolt_yaml_plan"
    assert len(changes) == 37
    assert sum(change.risk == "dangerous" for change in changes) == 24
    assert sum(change.risk == "review" for change in changes) == 13
    assert gate["step_count"] == 10
    assert gate["parameter_count"] == 2
    assert gate["dynamic_count"] == 8
    assert {
        "puppet_project_bolt_plan_command",
        "puppet_project_bolt_plan_command_download",
        "puppet_project_bolt_plan_command_dynamic_execution",
        "puppet_project_bolt_plan_download",
        "puppet_project_bolt_plan_dynamic_expression",
        "puppet_project_bolt_plan_expression",
        "puppet_project_bolt_plan_failure_continuation",
        "puppet_project_bolt_plan_literal_secret",
        "puppet_project_bolt_plan_nested_plan",
        "puppet_project_bolt_plan_privilege",
        "puppet_project_bolt_plan_resource",
        "puppet_project_bolt_plan_script",
        "puppet_project_bolt_plan_sensitive_file",
        "puppet_project_bolt_plan_sensitive_parameter",
        "puppet_project_bolt_plan_target_scope",
        "puppet_project_bolt_plan_task",
        "puppet_project_bolt_plan_transfer_path",
        "puppet_project_bolt_plan_upload",
    } <= kinds
    for sensitive in (
        "fixture-bolt-plan-password-do-not-leak",
        "fixture-bolt-plan-token-do-not-leak",
        "fixture-task-password-do-not-leak",
        "fixture-script-secret-do-not-leak",
        "downloads.example.invalid",
        "windows.example.invalid",
        "fixture-package",
        "fixture-service",
    ):
        assert sensitive not in encoded


def test_bolt_task_metadata_surfaces_execution_contract_without_values() -> None:
    fixture = "bolt_content_risky/modules/fixture/tasks/deploy.json"
    data = parse_puppet_project((FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture)
    changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")
    gate = analyze_puppet_project(data)
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps(gate)

    assert data["puppet_project"]["artifact_type"] == "bolt_task_metadata"
    assert len(changes) == 12
    assert sum(change.risk == "dangerous" for change in changes) == 6
    assert sum(change.risk == "review" for change in changes) == 6
    assert gate["parameter_count"] == 4
    assert gate["implementation_count"] == 2
    assert gate["file_count"] == 3
    assert gate["sensitive_parameter_count"] == 0
    assert {
        "puppet_project_bolt_task_bundled_files",
        "puppet_project_bolt_task_implementation",
        "puppet_project_bolt_task_input_contract",
        "puppet_project_bolt_task_noop_unavailable",
        "puppet_project_bolt_task_private_visibility",
        "puppet_project_bolt_task_remote_execution",
        "puppet_project_bolt_task_sensitive_parameter",
        "puppet_project_bolt_task_unconstrained_input",
    } <= kinds
    assert "fixture-bolt-task-password-do-not-leak" not in encoded
    assert "fixture/files" not in encoded
    assert "deploy.sh" not in encoded


def test_bolt_shell_task_implementation_surfaces_target_code_without_values() -> None:
    fixture = "bolt_task_implementation_risky/modules/fixture/tasks/deploy.sh"
    data = parse_puppet_project((FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture)
    changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")
    gate = analyze_puppet_project(data)
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps(gate)

    assert data["puppet_project"]["artifact_type"] == "bolt_task_implementation"
    assert len(changes) == 13
    assert sum(change.risk == "dangerous" for change in changes) == 8
    assert sum(change.risk == "review" for change in changes) == 5
    assert gate["language"] == "shell"
    assert gate["source_kind"] == "target_task_implementation"
    assert gate["source_line_count"] == 12
    assert gate["task_name"] == "deploy"
    assert {
        "puppet_project_bolt_task_destructive_operation",
        "puppet_project_bolt_task_dynamic_execution",
        "puppet_project_bolt_task_implementation_boundary",
        "puppet_project_bolt_task_implementation_execution",
        "puppet_project_bolt_task_network_access",
        "puppet_project_bolt_task_parameter_input",
        "puppet_project_bolt_task_permission_change",
        "puppet_project_bolt_task_privilege_escalation",
        "puppet_project_bolt_task_remote_access",
        "puppet_project_bolt_task_secret_handling",
        "puppet_project_bolt_task_system_mutation",
    } <= kinds
    assert all(change.actions == ("execute",) for change in changes[:-1])
    assert "fixture-bolt-implementation-secret-do-not-leak" not in encoded
    assert "downloads.example.invalid" not in encoded
    assert "deploy@example.invalid" not in encoded
    assert "rm -rf is documentation" not in encoded


@pytest.mark.parametrize(
    ("filename", "source", "language", "expected"),
    [
        (
            "modules/demo/tasks/configure.ps1",
            "param([string]$Path)\n"
            "$api_token = 'fixture-powershell-secret'\n"
            "Invoke-Expression $env:PT_command\n"
            "Invoke-WebRequest 'https://example.invalid'\n"
            "Set-Content -Path $Path -Value 'ok'\n"
            "Remove-Item $Path -Recurse\n"
            "# Add-Type and Restart-Computer are comments\n",
            "powershell",
            {
                "puppet_project_bolt_task_destructive_operation",
                "puppet_project_bolt_task_dynamic_execution",
                "puppet_project_bolt_task_filesystem_mutation",
                "puppet_project_bolt_task_network_access",
            },
        ),
        (
            "modules/demo/tasks/configure.py",
            "import json, pickle, requests, shutil, subprocess, sys\n"
            "params = json.load(sys.stdin)\n"
            "api_token = 'fixture-python-secret'\n"
            "subprocess.run(params['command'], shell=True)\n"
            "requests.get(params['url'])\n"
            "shutil.rmtree(params['path'])\n"
            "pickle.loads(params['payload'])\n"
            "# os.system('comment only')\n",
            "python",
            {
                "puppet_project_bolt_task_destructive_operation",
                "puppet_project_bolt_task_dynamic_execution",
                "puppet_project_bolt_task_network_access",
                "puppet_project_bolt_task_process_execution",
                "puppet_project_bolt_task_unsafe_deserialization",
            },
        ),
        (
            "modules/demo/tasks/configure.rb",
            "require 'json'\n"
            "params = JSON.parse(STDIN.read)\n"
            "api_token = 'fixture-ruby-secret'\n"
            "system(params['command'])\n"
            "eval(params['ruby'])\n"
            "Net::HTTP.get(URI(params['url']))\n"
            "FileUtils.rm_rf(params['path'])\n"
            "YAML.load(params['payload'])\n"
            "# `comment only`\n",
            "ruby",
            {
                "puppet_project_bolt_task_destructive_operation",
                "puppet_project_bolt_task_dynamic_execution",
                "puppet_project_bolt_task_network_access",
                "puppet_project_bolt_task_process_execution",
                "puppet_project_bolt_task_unsafe_deserialization",
            },
        ),
    ],
)
def test_bolt_task_implementation_languages_are_bounded_and_comment_aware(
    filename: str, source: str, language: str, expected: set[str]
) -> None:
    data = parse_puppet_project(source, filename=filename)
    changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")
    gate = analyze_puppet_project(data)

    assert data["puppet_project"]["artifact_type"] == "bolt_task_implementation"
    assert gate["language"] == language
    assert expected <= {change.resource_type for change in changes}
    assert not any("comment only" in change.explanation for change in changes)
    assert "fixture-" not in json.dumps(gate)


def test_extensionless_bolt_task_uses_shebang_and_never_executes(tmp_path: Path) -> None:
    marker = tmp_path / "bolt-task-was-executed"
    source = f"#!/bin/sh\ntouch '{marker}'\n"
    data = parse_puppet_project(source, filename="modules/demo/tasks/configure")

    assert data["puppet_project"]["artifact_type"] == "bolt_task_implementation"
    assert data["puppet_project"]["document"]["language"] == "shell"
    assert not marker.exists()


@pytest.mark.parametrize(
    ("shebang", "language"),
    [
        ("#!/bin/bash", "shell"),
        ("#!/usr/bin/env pwsh", "powershell"),
        ("#!/usr/bin/python3.13", "python"),
        ("#!/usr/bin/env ruby", "ruby"),
    ],
)
def test_extensionless_bolt_task_recognizes_supported_shebangs(
    shebang: str, language: str
) -> None:
    data = parse_puppet_project(
        f"{shebang}\n# implementation\n", filename="modules/demo/tasks/configure"
    )

    assert data["puppet_project"]["artifact_type"] == "bolt_task_implementation"
    assert data["puppet_project"]["document"]["language"] == language


def test_bolt_task_implementation_rejects_unsupported_or_unsafe_text() -> None:
    with pytest.raises(PuppetProjectInputError, match="supported text formats"):
        parse_puppet_project("console.log('task')\n", filename="modules/demo/tasks/configure.js")
    with pytest.raises(PuppetProjectInputError, match="2 MiB"):
        parse_puppet_project(
            "#!/bin/sh\n" + "x" * (2 * 1024 * 1024),
            filename="modules/demo/tasks/configure",
        )
    with pytest.raises(PuppetProjectInputError, match="NUL byte"):
        parse_puppet_project("#!/bin/sh\necho bad\x00value\n", filename="tasks/configure")


def test_bolt_task_implementation_caps_finding_output() -> None:
    source = "#!/bin/sh\n" + "eval $PT_command\n" * 2_100
    data = parse_puppet_project(source, filename="modules/demo/tasks/configure.sh")
    changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")

    assert len(changes) == 2_003
    assert any(
        change.resource_type == "puppet_project_bolt_task_finding_limit" for change in changes
    )


def test_hardened_bolt_content_stays_review_only() -> None:
    fixtures = (
        "bolt_content_review/modules/fixture/plans/inspect.yaml",
        "bolt_content_review/modules/fixture/tasks/inspect.json",
    )
    for fixture in fixtures:
        changes = _changes(fixture)
        assert {change.risk for change in changes} == {"review"}


def test_bolt_content_parsers_never_execute_source(tmp_path: Path) -> None:
    marker = tmp_path / "bolt-source-was-executed"
    source = f"steps:\n  - command: touch '{marker}'\n    targets: localhost\n"

    parse_puppet_project(source, filename="modules/demo/plans/check.yaml")

    assert not marker.exists()


@pytest.mark.parametrize(
    ("source", "filename", "error"),
    [
        (
            "steps:\n  - command: one\n    task: two\n    targets: all\n",
            "modules/demo/plans/bad.yaml",
            "exactly one action",
        ),
        (
            "steps:\n  - command: one\n",
            "modules/demo/plans/bad.yaml",
            "missing required",
        ),
        (
            "steps:\n  - message: one\n    catch_errors: true\n",
            "modules/demo/plans/bad.yaml",
            "unsupported message fields",
        ),
        (
            "steps:\n  - message: one\nsteps: []\n",
            "modules/demo/plans/bad.yaml",
            "duplicate YAML key",
        ),
        (
            '{"parameters":{"Bad":{"type":"String"}}}',
            "modules/demo/tasks/bad.json",
            "lowercase identifiers",
        ),
        (
            '{"puppet_task_version":2}',
            "modules/demo/tasks/bad.json",
            "must be 1",
        ),
        (
            '{"remote":"yes"}',
            "modules/demo/tasks/bad.json",
            "must be a boolean",
        ),
        (
            '{"remote":true,"remote":false}',
            "modules/demo/tasks/bad.json",
            "duplicate JSON key",
        ),
    ],
)
def test_bolt_content_parsers_reject_ambiguous_or_malformed_input(
    source: str, filename: str, error: str
) -> None:
    with pytest.raises(PuppetProjectInputError, match=error):
        parse_puppet_project(source, filename=filename)


def test_bolt_content_parsers_enforce_source_and_structure_limits() -> None:
    filename = "modules/demo/plans/bad.yaml"
    with pytest.raises(PuppetProjectInputError, match="2 MiB"):
        parse_puppet_project("steps:\n  - message: " + "x" * (2 * 1024 * 1024), filename=filename)
    with pytest.raises(PuppetProjectInputError, match="line count"):
        parse_puppet_project("# filler\n" * 100_001, filename=filename)
    with pytest.raises(PuppetProjectInputError, match="NUL byte"):
        parse_puppet_project("steps:\n  - message: bad\x00value\n", filename=filename)
    nested = "steps:\n  - eval:\n" + "      -" * 102 + " value\n"
    with pytest.raises(PuppetProjectInputError, match="nesting depth"):
        parse_puppet_project(nested, filename=filename)


def test_bolt_yaml_plan_rejects_recursive_aliases() -> None:
    with pytest.raises(PuppetProjectInputError, match="recursive YAML alias"):
        parse_puppet_project(
            "steps: &steps\n  - eval: *steps\n",
            filename="modules/demo/plans/bad.yaml",
        )


@pytest.mark.parametrize(
    ("source", "error"),
    [
        ("{}\n", "does not contain settings"),
        ("- source\n", "one YAML mapping"),
        ("sources: []\n", "sources must be a mapping"),
        ("sources:\n  one: value\n", "source 1 must be a mapping"),
        (
            "sources:\n  one:\n    basedir: /environments\n",
            "Git source 1 requires a string remote",
        ),
        (
            "sources:\n  one:\n    remote: https://example.invalid/repo.git\n",
            "requires a string basedir",
        ),
        (
            "sources:\n  one:\n    remote: https://example.invalid/repo.git\n"
            "    basedir: /environments\nremote: https://example.invalid/legacy.git\n",
            "cannot be combined",
        ),
        ("git:\n  repositories: {}\n", "repositories must be a list"),
        ("git:\n  repositories:\n    - proxy: https://proxy.invalid\n", "string remote"),
        ("forge: true\n", "forge must be a mapping"),
        ("deploy:\n  purge_levels: deployment\n", "purge_levels must be a string list"),
        ("postrun: /bin/true\n", "postrun must be a non-empty string list"),
        ("pool_size: 0\n", "pool_size must be a positive integer"),
        ("unknown: true\n", "unsupported top-level r10k"),
        ("cachedir: one\ncachedir: two\n", "duplicate YAML key"),
    ],
)
def test_r10k_parser_rejects_duplicate_unrelated_or_malformed_input(
    source: str, error: str
) -> None:
    with pytest.raises(PuppetProjectInputError, match=error):
        parse_puppet_project(source, filename="r10k.yaml")


@pytest.mark.parametrize(
    ("fixture", "artifact_type"),
    [
        ("Puppetfile.project-risky", "puppetfile"),
        ("puppet_metadata_risky.json", "metadata"),
        ("hiera_project_risky.yaml", "hiera"),
        ("puppet_conf_risky.conf", "config"),
        ("bolt_project/bolt-project.yaml", "bolt_project"),
        ("bolt_inventory/inventory.yaml", "bolt_inventory"),
        ("bolt_content_risky/modules/fixture/plans/deploy.yaml", "bolt_yaml_plan"),
        ("bolt_content_risky/modules/fixture/tasks/deploy.json", "bolt_task_metadata"),
        (
            "bolt_task_implementation_risky/modules/fixture/tasks/deploy.sh",
            "bolt_task_implementation",
        ),
        ("puppet_r10k_risky/r10k.yaml", "r10k"),
        ("puppet_server_policy_risky/environment.conf", "environment"),
        ("puppet_server_policy_risky/puppetdb.conf", "puppetdb"),
        ("puppet_server_policy_risky/auth.conf", "server_auth"),
        ("puppet_server_policy_risky/ca.conf", "server_ca"),
        ("puppet_server_policy_risky/puppetserver.conf", "server_runtime"),
        ("puppet_server_policy_risky/web-routes.conf", "server_routes"),
        ("puppet_server_policy_risky/webserver.conf", "server_web"),
    ],
)
def test_gate_and_cli_support_every_puppet_project_format(
    fixture: str,
    artifact_type: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = parse_puppet_project((FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture)
    gate = analyze_puppet_project(data)
    assert gate["adapter"] == "puppet-project"
    assert gate["artifact_type"] == artifact_type
    assert gate["decision"] == "block"
    assert gate["total_changes"] == sum(gate["risk_counts"].values())

    assert main(["puppet-project", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "puppet-project"
    assert payload["artifact_type"] == artifact_type
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
