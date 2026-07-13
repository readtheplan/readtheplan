from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.chef_project import (
    ChefProjectAdapter,
    ChefProjectInputError,
    analyze_chef_project,
    parse_chef_project,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(fixture: str):
    data = parse_chef_project(
        (FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture
    )
    return ChefProjectAdapter().analyze(data, tool_name="Chef project")


def _runtime_changes(relative: str):
    path = FIXTURES / "chef_runtime" / relative
    data = parse_chef_project(path.read_text(encoding="utf-8"), filename=str(path))
    return data, ChefProjectAdapter().analyze(data, tool_name="Chef project")


def test_policyfile_surfaces_sources_mutability_attributes_and_ruby_execution() -> None:
    changes = _changes("chef_policyfile_risky.rb")
    by_type: dict[str, list] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change)

    assert len(changes) == 14
    assert sum(change.risk == "dangerous" for change in changes) == 8
    assert by_type["chef_project_default_cookbook_source"][0].risk == "dangerous"
    assert len(by_type["chef_project_cookbook_dependency"]) == 6
    assert (
        sum(change.risk == "dangerous" for change in by_type["chef_project_cookbook_dependency"])
        == 4
    )
    assert by_type["chef_project_secret_attribute"][0].risk == "dangerous"
    assert by_type["chef_project_ruby_execution"][0].risk == "dangerous"


def test_policy_lock_distinguishes_immutable_and_risky_resolution() -> None:
    review = _changes("chef_policy_lock_review.json")
    risky = _changes("chef_policy_lock_risky.json")

    assert {change.risk for change in review} == {"review"}
    assert sum(change.risk == "dangerous" for change in risky) == 5
    assert any("full commit" in change.explanation for change in risky)
    assert any("plaintext transport" in change.explanation for change in risky)
    assert any("no content identifier" in change.explanation for change in risky)
    assert any(change.resource_type == "chef_project_secret_attribute" for change in risky)


def test_metadata_surfaces_cookbook_gem_compatibility_privacy_and_execution() -> None:
    changes = _changes("chef_metadata_risky.rb")
    dependencies = [
        change for change in changes if change.resource_type == "chef_project_cookbook_dependency"
    ]
    gems = [change for change in changes if change.resource_type == "chef_project_gem_dependency"]

    assert len(dependencies) == 3
    assert sum(change.risk == "dangerous" for change in dependencies) == 2
    assert len(gems) == 2
    assert sum(change.risk == "dangerous" for change in gems) == 1
    assert any(change.resource_type == "chef_project_public_cookbook_upload" for change in changes)
    assert any(change.resource_type == "chef_project_ruby_execution" for change in changes)


def test_berksfile_surfaces_legacy_sources_pinning_groups_and_ruby_execution() -> None:
    changes = _changes("chef_berkshelf_risky/Berksfile")
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps([change.explanation for change in changes])

    assert "chef_project_berkshelf_legacy_workflow" in kinds
    assert "chef_project_berkshelf_source" in kinds
    assert "chef_project_berkshelf_source_precedence" in kinds
    assert "chef_project_berkshelf_metadata_dependency" in kinds
    assert "chef_project_berkshelf_solver" in kinds
    assert "chef_project_berkshelf_cookbook_dependency" in kinds
    assert "chef_project_ruby_execution" in kinds
    assert "chef_project_berkshelf_boundary" in kinds
    assert any(change.risk == "dangerous" for change in changes)
    assert "fixture-user" not in encoded
    assert "fixture-password" not in encoded
    assert "example.invalid" not in encoded


def test_berks_lock_surfaces_provenance_graph_integrity_and_missing_locks() -> None:
    changes = _changes("chef_berkshelf_risky/Berksfile.lock")
    direct = [
        change
        for change in changes
        if change.resource_type == "chef_project_berkshelf_direct_dependency"
    ]
    resolved = [
        change
        for change in changes
        if change.resource_type == "chef_project_berkshelf_resolved_cookbook"
    ]
    encoded = json.dumps([change.explanation for change in changes])

    assert len(direct) == 5
    assert len(resolved) == 5
    assert sum(change.risk == "dangerous" for change in direct) == 3
    assert sum(change.risk == "dangerous" for change in resolved) == 1
    assert any("no resolved graph entry" in change.explanation for change in direct)
    assert any(
        "conflicts with the exact direct constraint" in change.explanation for change in direct
    )
    assert any("graph node" in change.explanation for change in resolved)
    assert any("exact dependency constraint" in change.explanation for change in resolved)
    assert "fixture-user" not in encoded
    assert "fixture-password" not in encoded
    assert "example.invalid" not in encoded


def test_pinned_berkshelf_inputs_stay_review_only() -> None:
    assert {change.risk for change in _changes("chef_berkshelf_review/Berksfile")} == {
        "review"
    }
    assert {change.risk for change in _changes("chef_berkshelf_review/Berksfile.lock")} == {
        "review"
    }


def test_legacy_json_berks_lock_is_parsed_and_flagged_dangerous() -> None:
    data = parse_chef_project(
        '{"dependencies":{"base":{"locked_version":"1.2.3"}}}',
        filename="Berksfile.lock",
    )
    changes = ChefProjectAdapter().analyze(data, tool_name="Chef project")

    assert data["chef_project"]["artifact_type"] == "berks_lock"
    assert any(
        change.resource_type == "chef_project_berkshelf_legacy_lock_format"
        and change.risk == "dangerous"
        for change in changes
    )


def test_client_config_surfaces_trust_credentials_execution_and_runtime_controls() -> None:
    data, changes = _runtime_changes("client.rb")
    encoded = json.dumps(
        [{"address": change.address, "explanation": change.explanation} for change in changes]
    )

    assert data["chef_project"]["artifact_type"] == "client_config"
    assert len(data["chef_project"]["document"]["settings"]) == 16
    assert len(changes) == 18
    assert sum(change.risk == "dangerous" for change in changes) == 12
    assert sum(change.risk == "review" for change in changes) == 6
    assert any("TLS certificate verification is disabled" in c.explanation for c in changes)
    assert any("atomic file updates are disabled" in c.explanation for c in changes)
    assert any(c.resource_type == "chef_project_ruby_execution" for c in changes)
    assert "fixture-chef" not in encoded
    assert "example.invalid" not in encoded


def test_workstation_config_surfaces_ssh_secrets_auto_confirm_and_bootstrap_pin() -> None:
    data, changes = _runtime_changes(".chef/config.rb")
    encoded = json.dumps([change.explanation for change in changes])

    assert data["chef_project"]["artifact_type"] == "workstation_config"
    assert len(changes) == 13
    assert sum(change.risk == "dangerous" for change in changes) == 7
    assert any("forwards the local SSH agent" in c.explanation for c in changes)
    assert any("automatically confirms prompts" in c.explanation for c in changes)
    assert any("does not pin" in c.explanation for c in changes)
    assert "fixture-chef" not in encoded
    assert "example.invalid" not in encoded


def test_solo_config_surfaces_remote_cookbooks_secrets_paths_and_logging() -> None:
    data, changes = _runtime_changes("solo.rb")
    encoded = json.dumps([change.explanation for change in changes])

    assert data["chef_project"]["artifact_type"] == "solo_config"
    assert len(changes) == 11
    assert sum(change.risk == "dangerous" for change in changes) == 4
    assert any("executable cookbook content" in c.explanation for c in changes)
    assert any("filesystem input" in c.explanation for c in changes)
    assert "fixture-chef" not in encoded
    assert "example.invalid" not in encoded


def test_server_config_surfaces_transport_identity_secrets_and_forced_recipe() -> None:
    data, changes = _runtime_changes("chef-server.rb")
    encoded = json.dumps([change.explanation for change in changes])

    assert data["chef_project"]["artifact_type"] == "server_config"
    assert len(changes) == 19
    assert sum(change.risk == "dangerous" for change in changes) == 11
    assert any("accepts non-TLS traffic" in c.explanation for c in changes)
    assert any("legacy TLS protocol" in c.explanation for c in changes)
    assert any("LDAP identity endpoint" in c.explanation for c in changes)
    assert any("forces a recipe onto every" in c.explanation for c in changes)
    assert "fixture-chef" not in encoded
    assert "example.invalid" not in encoded


def test_minimal_static_metadata_is_recognized_without_dependency_directives() -> None:
    data = parse_chef_project(
        'name "simple"\nversion "1.0.0"\nlicense "Apache-2.0"\nmaintainer "Infra"\n'
    )
    assert data["chef_project"]["artifact_type"] == "metadata"


def test_missing_required_policy_and_metadata_identity_is_dangerous() -> None:
    policy = parse_chef_project('default_source :supermarket\ncookbook "nginx", "1.0.0"\n')
    metadata = parse_chef_project('depends "nginx", "= 1.0.0"\n')
    policy_types = {change.resource_type for change in ChefProjectAdapter().analyze(policy)}
    metadata_types = {change.resource_type for change in ChefProjectAdapter().analyze(metadata)}
    assert "chef_project_missing_policy_name" in policy_types
    assert "chef_project_missing_run_list" in policy_types
    assert "chef_project_missing_cookbook_name" in metadata_types
    assert "chef_project_missing_cookbook_version" in metadata_types


def test_known_directive_cannot_hide_same_line_ruby_execution() -> None:
    data = parse_chef_project('name "production"; system "./mutate"\nrun_list "recipe[base]"\n')
    changes = ChefProjectAdapter().analyze(data)
    execution = [
        change for change in changes if change.resource_type == "chef_project_ruby_execution"
    ]
    assert len(execution) == 1
    assert execution[0].risk == "dangerous"


def test_quote_scanner_handles_long_adversarial_escape_sequences_linearly() -> None:
    escaped = "\\\\a" * 20_000
    data = parse_chef_project(
        f'name "production"\nrun_list "recipe[base]"\n'
        f'cookbook "payload", git: "https://example.test/{escaped}", branch: "main"\n'
    )
    changes = ChefProjectAdapter().analyze(data)
    dependencies = [
        change for change in changes if change.resource_type == "chef_project_cookbook_dependency"
    ]
    assert len(dependencies) == 1
    assert dependencies[0].risk == "dangerous"


def test_runtime_config_detects_conflicting_overrides_without_exposing_values() -> None:
    data = parse_chef_project(
        "ssl_verify_mode :verify_peer\nssl_verify_mode :verify_none\n",
        filename="client.rb",
    )
    changes = ChefProjectAdapter().analyze(data)

    assert len(changes) == 3
    assert changes[1].risk == "dangerous"
    assert "overrides a different value" in changes[1].explanation


def test_runtime_config_marks_environment_and_interpolation_as_unresolved() -> None:
    data = parse_chef_project(
        "data_collector.token = ENV['CHEF_TOKEN']\n"
        'chef_server_url "https://#{ENV[\'CHEF_HOST\']}"\n',
        filename="client.rb",
    )
    changes = ChefProjectAdapter().analyze(data)

    assert len(data["chef_project"]["document"]["dynamic"]) == 2
    assert any(change.resource_type == "chef_project_dynamic_ruby" for change in changes)
    assert "CHEF_TOKEN" not in json.dumps([change.explanation for change in changes])


def test_runtime_config_treats_external_ruby_config_loading_as_execution() -> None:
    data = parse_chef_project(
        "Chef::Config.from_file('/etc/chef/extra.rb')\n",
        filename="client.rb",
    )
    changes = ChefProjectAdapter().analyze(data)

    assert any(change.resource_type == "chef_project_ruby_execution" for change in changes)


@pytest.mark.parametrize(
    ("filename", "artifact_type"),
    [
        ("/etc/chef/client.d/security.rb", "client_config"),
        ("/home/operator/.chef/config.d/cloud.rb", "workstation_config"),
        ("/etc/chef/solo.d/paths.rb", "solo_config"),
        ("knife.rb", "workstation_config"),
    ],
)
def test_runtime_config_recognizes_official_primary_and_fragment_paths(
    filename: str, artifact_type: str
) -> None:
    data = parse_chef_project("log_level :info\n", filename=filename)

    assert data["chef_project"]["artifact_type"] == artifact_type


@pytest.mark.parametrize(
    ("source", "error"),
    [
        ("", "empty"),
        ("puts 'hello'", "not a recognized"),
        ('{"name": "not-a-lock"}', "not recognized"),
        ('{"revision_id": "one", "revision_id": "two"}', "duplicate JSON key"),
        (
            '{"revision_id": "one", "cookbook_locks": {"bad": {"source_options": []}}}',
            "source_options",
        ),
        ('name "mixed"\nrun_list "recipe[x]"\ndepends "y"\n', "mixes"),
        ("# comments only\n", "not a recognized"),
    ],
)
def test_parser_rejects_unrelated_ambiguous_or_duplicate_input(source: str, error: str) -> None:
    with pytest.raises(ChefProjectInputError, match=error):
        parse_chef_project(source)


def test_runtime_parser_rejects_comments_only_configuration() -> None:
    with pytest.raises(ChefProjectInputError, match="no settings"):
        parse_chef_project("# comments only\n", filename="client.rb")


@pytest.mark.parametrize(
    ("source", "filename", "error"),
    [
        ("puts 'not a Berksfile'\n", "Berksfile", "recognized Berksfile"),
        ("group :test do\n  metadata\n", "Berksfile", "unterminated"),
        ("DEPENDENCIES\n  base\n", "Berksfile.lock", "DEPENDENCIES and GRAPH"),
        (
            "DEPENDENCIES\n  base\n  base\nGRAPH\n  base (1.0.0)\n",
            "Berksfile.lock",
            "duplicate Berksfile dependency",
        ),
        (
            "DEPENDENCIES\n  base\nGRAPH\n  base (1.0.0)\n  base (1.0.1)\n",
            "Berksfile.lock",
            "duplicate Berksfile graph entry",
        ),
        (
            "DEPENDENCIES\n  base\nGRAPH\n  base (1.0.0)\n"
            "    child (= 1.0.0)\n    child (= 1.0.0)\n  child (1.0.0)\n",
            "Berksfile.lock",
            "duplicate Berksfile graph dependency",
        ),
    ],
)
def test_berkshelf_parser_rejects_dynamic_or_malformed_inputs(
    source: str, filename: str, error: str
) -> None:
    with pytest.raises(ChefProjectInputError, match=error):
        parse_chef_project(source, filename=filename)


@pytest.mark.parametrize(
    ("fixture", "artifact_type"),
    [
        ("chef_policyfile_risky.rb", "policyfile"),
        ("chef_policy_lock_risky.json", "lock"),
        ("chef_metadata_risky.rb", "metadata"),
        ("chef_berkshelf_risky/Berksfile", "berksfile"),
        ("chef_berkshelf_risky/Berksfile.lock", "berks_lock"),
    ],
)
def test_gate_and_cli_support_every_chef_project_format(
    fixture: str,
    artifact_type: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = parse_chef_project(
        (FIXTURES / fixture).read_text(encoding="utf-8"), filename=fixture
    )
    gate = analyze_chef_project(data)
    assert gate["adapter"] == "chef-project"
    assert gate["artifact_type"] == artifact_type
    assert gate["decision"] == "block"
    assert gate["total_changes"] == sum(gate["risk_counts"].values())

    assert main(["chef-project", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "chef-project"
    assert payload["artifact_type"] == artifact_type
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize(
    ("relative", "artifact_type", "setting_count", "total_changes"),
    [
        ("client.rb", "client_config", 16, 18),
        (".chef/config.rb", "workstation_config", 12, 13),
        ("solo.rb", "solo_config", 10, 11),
        ("chef-server.rb", "server_config", 16, 19),
    ],
)
def test_gate_and_cli_support_chef_runtime_configuration(
    relative: str,
    artifact_type: str,
    setting_count: int,
    total_changes: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = FIXTURES / "chef_runtime" / relative
    data = parse_chef_project(path.read_text(encoding="utf-8"), filename=str(path))
    gate = analyze_chef_project(data)

    assert gate["adapter"] == "chef-project"
    assert gate["artifact_type"] == artifact_type
    assert gate["setting_count"] == setting_count
    assert gate["total_changes"] == total_changes
    assert gate["decision"] == "block"

    assert main(["chef-project", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    encoded = json.dumps(payload)
    assert payload["artifact_type"] == artifact_type
    assert payload["setting_count"] == setting_count
    assert "fixture-chef" not in encoded
    assert "example.invalid" not in encoded
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


def test_test_kitchen_surfaces_execution_trust_privilege_and_layering_without_values() -> None:
    changes = _changes("chef_test_kitchen_risky/.kitchen.yml")
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps(
        [{"address": change.address, "explanation": change.explanation} for change in changes]
    )

    assert len(changes) == 31
    assert sum(change.risk == "dangerous" for change in changes) == 22
    assert sum(change.risk == "review" for change in changes) == 9
    assert "chef_project_test_kitchen_erb" in kinds
    assert "chef_project_test_kitchen_driver" in kinds
    assert "chef_project_test_kitchen_host_access" in kinds
    assert "chef_project_test_kitchen_provisioner" in kinds
    assert "chef_project_test_kitchen_transport_trust" in kinds
    assert "chef_project_test_kitchen_verifier" in kinds
    assert "chef_project_test_kitchen_lifecycle_hook" in kinds
    assert "chef_project_test_kitchen_boundary" in kinds
    for secret in (
        "fixture-api-token-do-not-leak",
        "fixture-cloud-secret-do-not-leak",
        "fixture-hook-secret-do-not-leak",
        "fixture-transport-password-do-not-leak",
        "fixture-user",
        "fixture-password",
        "example.invalid",
        "fixture-local-command-do-not-run",
        "fixture-remote-command-do-not-run",
    ):
        assert secret not in encoded


def test_test_kitchen_gate_and_cli_expose_only_structural_metadata(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = FIXTURES / "chef_test_kitchen_risky" / ".kitchen.yml"
    data = parse_chef_project(path.read_text(encoding="utf-8"), filename=str(path))
    gate = analyze_chef_project(data)

    assert gate["adapter"] == "chef-project"
    assert gate["artifact_type"] == "test_kitchen"
    assert gate["platform_count"] == 1
    assert gate["suite_count"] == 1
    assert gate["dynamic_erb"] is True
    assert gate["total_changes"] == 31
    assert gate["decision"] == "block"

    assert main(["chef-project", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    encoded = json.dumps(payload)
    assert payload["artifact_type"] == "test_kitchen"
    assert payload["risk_counts"]["dangerous"] == 22
    assert "fixture-cloud-secret-do-not-leak" not in encoded
    assert "fixture-local-command-do-not-run" not in encoded
    assert "example.invalid" not in encoded
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize(
    ("source", "error"),
    [
        ("ordinary: yaml\n", "not a recognized Test Kitchen"),
        ("driver:\n  name: one\n  name: two\n", "duplicate Test Kitchen YAML key"),
        ("driver: vagrant\n", "driver must be a mapping"),
        ("platforms: {}\n", "platforms must be a list"),
        ("platforms:\n  - name: one\n    driver: vagrant\n", "driver override"),
        ("driver: {}\n---\nsuites: []\n", "exactly one YAML document"),
        ("driver:\n  name: <%= ENV['DRIVER']\n", "unterminated ERB"),
        ("driver: &driver\n  name: vagrant\n  loop: *driver\n", "recursive YAML alias"),
    ],
)
def test_test_kitchen_parser_rejects_ambiguous_or_unsafe_structure(
    source: str, error: str
) -> None:
    with pytest.raises(ChefProjectInputError, match=error):
        parse_chef_project(source, filename=".kitchen.yml")


def test_test_kitchen_parser_supports_nonrecursive_anchors_and_merge_keys() -> None:
    data = parse_chef_project(
        "driver: &driver\n  name: vagrant\nplatforms:\n  - name: one\n"
        "    driver:\n      <<: *driver\nsuites:\n  - name: default\n",
        filename="kitchen.yml",
    )
    document = data["chef_project"]["document"]["configuration"]

    assert data["chef_project"]["artifact_type"] == "test_kitchen"
    assert document["platforms"][0]["driver"]["name"] == "vagrant"


def test_test_kitchen_erb_is_masked_and_never_executed(tmp_path: Path) -> None:
    marker = tmp_path / "erb-was-executed"
    source = f"driver:\n  name: <%= File.write('{marker}', 'bad') %>\n"
    data = parse_chef_project(source, filename=".kitchen.yml")

    assert data["chef_project"]["document"]["erb_count"] == 1
    assert not marker.exists()


def test_test_kitchen_parser_enforces_size_and_depth_limits() -> None:
    with pytest.raises(ChefProjectInputError, match="2 MiB"):
        parse_chef_project(
            "driver:\n  name: vagrant\n  note: " + "x" * (2 * 1024 * 1024),
            filename=".kitchen.yml",
        )
    deeply_nested = "driver:\n  name: vagrant\n  nested:\n" + "".join(
        " " * (4 + depth * 2) + "value:\n" for depth in range(102)
    )
    with pytest.raises(ChefProjectInputError, match="nesting depth"):
        parse_chef_project(deeply_nested, filename=".kitchen.yml")


def test_habitat_plan_surfaces_supply_chain_runtime_and_execution_without_values() -> None:
    fixture = "chef_habitat_risky/habitat/plan.sh"
    changes = _changes(fixture)
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps(
        [{"address": change.address, "explanation": change.explanation} for change in changes]
    )

    assert len(changes) == 27
    assert sum(change.risk == "dangerous" for change in changes) == 20
    assert sum(change.risk == "review" for change in changes) == 7
    assert {
        "chef_project_habitat_build_callback",
        "chef_project_habitat_build_dependency",
        "chef_project_habitat_destructive",
        "chef_project_habitat_download",
        "chef_project_habitat_dynamic_plan",
        "chef_project_habitat_forced_shutdown",
        "chef_project_habitat_literal_secret",
        "chef_project_habitat_package_publish",
        "chef_project_habitat_package_source",
        "chef_project_habitat_plan_boundary",
        "chef_project_habitat_privilege",
        "chef_project_habitat_privileged_service",
        "chef_project_habitat_remote_access",
        "chef_project_habitat_runtime_dependency",
        "chef_project_habitat_secret_output",
        "chef_project_habitat_service_command",
        "chef_project_habitat_source_integrity",
        "chef_project_habitat_unsafe_permissions",
        "chef_project_habitat_verification_bypass",
    } <= kinds
    for sensitive in (
        "fixture-habitat-auth-token-do-not-leak",
        "fixture-password",
        "fixture-service",
        "fixture-origin",
        "example.invalid",
        "fixture-binary",
        "fixture-host",
    ):
        assert sensitive not in encoded


def test_habitat_powershell_plan_supports_arrays_callbacks_and_redaction() -> None:
    path = FIXTURES / "chef_habitat_risky" / "habitat" / "plan.ps1"
    data = parse_chef_project(path.read_text(encoding="utf-8"), filename=str(path))
    changes = ChefProjectAdapter().analyze(data)
    gate = analyze_chef_project(data)
    encoded = json.dumps(gate)

    assert data["chef_project"]["artifact_type"] == "habitat_plan"
    assert gate["language"] == "powershell"
    assert gate["variable_count"] == 8
    assert gate["callback_count"] == 3
    assert gate["command_count"] == 4
    assert gate["total_changes"] == 18
    assert sum(change.risk == "dangerous" for change in changes) == 14
    assert "fixture-habitat-windows-token-do-not-leak" not in encoded
    assert "fixture-password" not in encoded
    assert "example.invalid" not in encoded


def test_pinned_habitat_plan_and_suitability_hook_stay_review_only() -> None:
    assert {
        change.risk
        for change in _changes("chef_habitat_review/habitat/plan.sh")
    } == {"review"}
    assert {
        change.risk
        for change in _changes("chef_habitat_review/habitat/hooks/suitability")
    } == {"review"}


def test_habitat_hooks_surface_templates_commands_blocking_and_secrets() -> None:
    run_path = "chef_habitat_risky/habitat/hooks/run"
    health_path = "chef_habitat_risky/habitat/hooks/health-check"
    run_data = parse_chef_project(
        (FIXTURES / run_path).read_text(encoding="utf-8"), filename=run_path
    )
    run_gate = analyze_chef_project(run_data)
    run_kinds = {
        change.resource_type for change in ChefProjectAdapter().analyze(run_data)
    }
    health_changes = _changes(health_path)

    assert run_gate["artifact_type"] == "habitat_hook"
    assert run_gate["hook_name"] == "run"
    assert run_gate["template_count"] == 1
    assert run_gate["command_count"] == 2
    assert run_gate["total_changes"] == 6
    assert "chef_project_habitat_hook_templating" in run_kinds
    assert "chef_project_habitat_literal_secret" in run_kinds
    assert "chef_project_habitat_dynamic_execution" in run_kinds
    assert any(
        change.resource_type == "chef_project_habitat_blocking_hook"
        for change in health_changes
    )
    encoded = json.dumps(run_gate)
    assert "fixture-habitat-hook-token-do-not-leak" not in encoded
    assert "runtime.example.invalid" not in encoded


def test_habitat_plan_and_hook_parsers_never_execute_source(tmp_path: Path) -> None:
    marker = tmp_path / "habitat-source-was-executed"
    plan = f"pkg_name=x\npkg_origin=x\npkg_version=1\ntouch '{marker}'\n"
    hook = f"#!/bin/sh\ntouch '{marker}'\n"

    parse_chef_project(plan, filename="habitat/plan.sh")
    parse_chef_project(hook, filename="habitat/hooks/run")

    assert not marker.exists()


def test_habitat_parser_recognizes_target_paths_extensions_and_legacy_hook_names() -> None:
    cases = {
        "habitat/x86_64-linux/plan.sh": ("habitat_plan", "bash", ""),
        "habitat/x86_64-windows/plan.ps1": ("habitat_plan", "powershell", ""),
        "habitat/hooks/health-check.sh": ("habitat_hook", "bash", "health-check"),
        "habitat/hooks/health_check.ps1": (
            "habitat_hook",
            "powershell",
            "health-check",
        ),
    }
    for filename, (artifact_type, language, hook_name) in cases.items():
        data = parse_chef_project("#!/bin/sh\necho ok\n", filename=filename)
        document = data["chef_project"]["document"]
        assert data["chef_project"]["artifact_type"] == artifact_type
        assert document["language"] == language
        assert document["hook_name"] == hook_name


def test_habitat_parser_enforces_size_line_and_nul_limits() -> None:
    with pytest.raises(ChefProjectInputError, match="2 MiB"):
        parse_chef_project("pkg_name=x\n#" + "x" * (2 * 1024 * 1024), filename="plan.sh")
    with pytest.raises(ChefProjectInputError, match="line count"):
        parse_chef_project("# x\n" * 100_001, filename="plan.sh")
    with pytest.raises(ChefProjectInputError, match="NUL byte"):
        parse_chef_project("pkg_name=x\x00bad\n", filename="plan.sh")


def test_habitat_gate_and_cli_expose_only_structural_metadata(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = FIXTURES / "chef_habitat_risky" / "habitat" / "plan.sh"
    data = parse_chef_project(path.read_text(encoding="utf-8"), filename=str(path))
    gate = analyze_chef_project(data)

    assert gate["adapter"] == "chef-project"
    assert gate["artifact_type"] == "habitat_plan"
    assert gate["language"] == "bash"
    assert gate["variable_count"] == 14
    assert gate["callback_count"] == 4
    assert gate["command_count"] == 7
    assert gate["total_changes"] == 27
    assert gate["risk_counts"]["dangerous"] == 20
    assert gate["decision"] == "block"

    assert main(["chef-project", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    encoded = json.dumps(payload)
    assert payload["artifact_type"] == "habitat_plan"
    assert payload["variable_count"] == 14
    assert "fixture-habitat-auth-token-do-not-leak" not in encoded
    assert "fixture-password" not in encoded
    assert "example.invalid" not in encoded
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
