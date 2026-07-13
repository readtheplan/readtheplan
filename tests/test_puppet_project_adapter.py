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
    data = parse_puppet_project((FIXTURES / fixture).read_text(encoding="utf-8"))
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


@pytest.mark.parametrize(
    ("fixture", "artifact_type"),
    [
        ("Puppetfile.project-risky", "puppetfile"),
        ("puppet_metadata_risky.json", "metadata"),
        ("hiera_project_risky.yaml", "hiera"),
        ("puppet_conf_risky.conf", "config"),
        ("bolt_project/bolt-project.yaml", "bolt_project"),
        ("bolt_inventory/inventory.yaml", "bolt_inventory"),
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
