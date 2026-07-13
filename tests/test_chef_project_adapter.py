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
    data = parse_chef_project((FIXTURES / fixture).read_text(encoding="utf-8"))
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
    ("fixture", "artifact_type"),
    [
        ("chef_policyfile_risky.rb", "policyfile"),
        ("chef_policy_lock_risky.json", "lock"),
        ("chef_metadata_risky.rb", "metadata"),
    ],
)
def test_gate_and_cli_support_every_chef_project_format(
    fixture: str,
    artifact_type: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = parse_chef_project((FIXTURES / fixture).read_text(encoding="utf-8"))
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
