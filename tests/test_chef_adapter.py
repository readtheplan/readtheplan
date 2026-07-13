from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.chef import (
    ChefAdapter,
    ChefInputError,
    analyze_chef,
    parse_chef,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures" / "chef_cookbook_risky"
OHAI_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "chef_ohai_risky"
    / "cookbooks"
    / "platform"
    / "ohai"
    / "cloud_inventory.rb"
)


def test_chef_recipe_classification() -> None:
    source = """
log 'starting'

package 'nginx' do
  action :install
end

service 'nginx' do
  action [:enable, :restart]
end

execute 'migrate database' do
  command './migrate'
end
"""
    data = {"chef_recipe": source}
    assert isinstance(detect_adapter(data), ChefAdapter)
    changes = ChefAdapter().analyze(data, use_rules=False)
    assert [change.risk for change in changes] == ["safe", "review", "dangerous", "dangerous"]


def test_chef_gate_and_cli(tmp_path, capsys) -> None:
    gate = analyze_chef({"chef_recipe": "execute 'deploy' do\n command './deploy'\nend\n"})
    assert gate["decision"] == "block"
    assert "Chef" in gate["reason"]

    recipe = tmp_path / "default.rb"
    recipe.write_text("log 'hello'\n", encoding="utf-8")
    assert main(["chef", "--framework", "soc2", str(recipe)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "proceed"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


def test_chef_cli_rejects_plain_ruby(tmp_path, capsys) -> None:
    source = tmp_path / "script.rb"
    source.write_text("puts 'hello'\n", encoding="utf-8")
    assert main(["chef", str(source)]) == 1
    assert "not recognized" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("relative_path", "artifact_type"),
    [
        ("resources/application.rb", "custom_resource"),
        ("attributes/default.rb", "attribute_file"),
        ("libraries/helpers.rb", "library"),
        ("templates/default/application.conf.erb", "template"),
    ],
)
def test_parse_chef_recognizes_cookbook_artifacts(
    relative_path: str,
    artifact_type: str,
) -> None:
    path = FIXTURES / relative_path
    data = parse_chef(path.read_text(encoding="utf-8"), filename=str(path))

    assert data["chef_artifact_type"] == artifact_type
    assert data["chef_metadata"]["artifact_type"] == artifact_type
    assert data["chef_metadata"]["line_count"] > 0
    assert ChefAdapter().can_handle(data)


def test_custom_resource_surfaces_actions_state_secrets_and_commands() -> None:
    path = FIXTURES / "resources" / "application.rb"
    data = parse_chef(path.read_text(encoding="utf-8"), filename=str(path))
    changes = ChefAdapter().analyze(data, use_rules=False)
    by_type = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change)

    assert by_type["chef_custom_resource_boundary"][0].risk == "review"
    assert by_type["chef_sensitive_property"][0].risk == "dangerous"
    assert by_type["chef_current_value_loader"][0].risk == "review"
    assert by_type["chef_custom_resource_action"][0].risk == "review"
    assert len(by_type["chef_command_execution"]) == 2
    assert all(change.risk == "dangerous" for change in by_type["chef_command_execution"])
    assert data["chef_metadata"] == {
        "artifact_type": "custom_resource",
        "line_count": 17,
        "resource_count": 1,
        "action_count": 1,
        "property_count": 2,
        "dynamic_count": 2,
    }


def test_attributes_surface_precedence_secrets_and_external_data_without_values() -> None:
    path = FIXTURES / "attributes" / "default.rb"
    source = path.read_text(encoding="utf-8")
    data = parse_chef(source, filename=str(path))
    changes = ChefAdapter().analyze(data, use_rules=False)

    assignments = [
        change for change in changes if change.resource_type == "chef_attribute_assignment"
    ]
    assert [change.risk for change in assignments] == ["review", "dangerous", "review"]
    assert any(change.resource_type == "chef_secret_lookup" for change in changes)
    rendered = " ".join(change.explanation for change in changes)
    assert "fixture-secret-value" not in rendered
    assert "api_token" not in rendered


def test_library_surfaces_arbitrary_ruby_and_chef_extension() -> None:
    path = FIXTURES / "libraries" / "helpers.rb"
    data = parse_chef(path.read_text(encoding="utf-8"), filename=str(path))
    changes = ChefAdapter().analyze(data, use_rules=False)
    risks = {change.resource_type: change.risk for change in changes}

    assert risks["chef_library_boundary"] == "review"
    assert risks["chef_dynamic_dependency"] == "review"
    assert risks["chef_chef_extension"] == "dangerous"
    assert risks["chef_external_runtime_access"] == "dangerous"
    assert risks["chef_direct_file_mutation"] == "dangerous"


def test_template_surfaces_ruby_and_sensitive_interpolation() -> None:
    path = FIXTURES / "templates" / "default" / "application.conf.erb"
    data = parse_chef(path.read_text(encoding="utf-8"), filename=str(path))
    changes = ChefAdapter().analyze(data, use_rules=False)
    types = [change.resource_type for change in changes]

    assert types.count("chef_template_expression") == 2
    assert "chef_sensitive_template_value" in types
    assert "chef_template_statement" in types
    assert "chef_command_execution" in types
    assert data["chef_metadata"]["action_count"] == 3
    assert data["chef_metadata"]["dynamic_count"] == 3


def test_comments_and_string_literals_do_not_create_ruby_findings() -> None:
    source = """
# system('commented')
message = "system('inside a string')"
property :message, String
action :create do
  log 'safe'
end
"""
    data = parse_chef(source, filename="cookbooks/example/resources/example.rb")
    changes = ChefAdapter().analyze(data, use_rules=False)

    assert not any(change.resource_type == "chef_command_execution" for change in changes)


def test_library_surfaces_runtime_data_searches_and_event_handlers() -> None:
    source = """
endpoint = ENV['FIXTURE_ENDPOINT']
payload = File.read('/run/fixture/runtime')
nodes = search(:node, 'role:fixture')
Chef.event_handler do
  on :run_failed do
    notify_runtime(nodes, payload, endpoint)
  end
end
"""
    data = parse_chef(source, filename="cookbooks/example/libraries/runtime.rb")
    changes = ChefAdapter().analyze(data, use_rules=False)
    risks = {change.resource_type: change.risk for change in changes}

    assert risks["chef_runtime_data_access"] == "review"
    assert risks["chef_chef_server_query"] == "review"
    assert risks["chef_event_handler"] == "dangerous"


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("", "empty"),
        ("puts 'hidden-value'\x00", "NUL"),
        ("too-many-lines", "line limit"),
    ],
)
def test_parse_chef_rejects_invalid_inputs_without_echoing_source(
    source: str,
    message: str,
) -> None:
    if source == "too-many-lines":
        source = "x\n" * 100_001
    with pytest.raises(ChefInputError, match=message) as exc_info:
        parse_chef(source, filename="cookbooks/example/libraries/example.rb")
    assert "hidden-value" not in str(exc_info.value)


def test_chef_cli_emits_cookbook_metadata(capsys) -> None:
    path = FIXTURES / "resources" / "application.rb"

    assert main(["chef", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "chef"
    assert payload["artifact_type"] == "custom_resource"
    assert payload["action_count"] == 1
    assert payload["property_count"] == 2
    assert payload["dynamic_count"] == 2


def test_chef_ohai_plugin_metadata_and_risk_classification() -> None:
    source = OHAI_FIXTURE.read_text(encoding="utf-8")
    data = parse_chef(source, filename=str(OHAI_FIXTURE))

    assert data["chef_artifact_type"] == "ohai_plugin"
    assert data["chef_metadata"] == {
        "artifact_type": "ohai_plugin",
        "line_count": 29,
        "resource_count": 0,
        "action_count": 1,
        "property_count": 2,
        "dynamic_count": 7,
        "plugin_count": 1,
        "named_plugin_count": 1,
        "provides_count": 2,
        "depends_count": 1,
        "collect_data_count": 1,
        "platform_count": 1,
        "dynamic_provides_count": 0,
        "dynamic_depends_count": 0,
    }
    changes = ChefAdapter().analyze(data, use_rules=False)
    risks = {change.resource_type: change.risk for change in changes}
    assert risks["chef_ohai_plugin_boundary"] == "review"
    assert risks["chef_ohai_builtin_plugin_collision"] == "dangerous"
    assert risks["chef_ohai_core_attribute_override"] == "dangerous"
    assert risks["chef_ohai_sensitive_attribute"] == "dangerous"
    assert risks["chef_ohai_collection_code"] == "dangerous"
    assert risks["chef_ohai_plugin_dependency"] == "review"
    assert risks["chef_ohai_hint_data"] == "review"
    assert risks["chef_ohai_command_execution"] == "dangerous"
    assert risks["chef_ohai_network_access"] == "dangerous"
    assert risks["chef_ohai_runtime_data_access"] == "review"
    assert risks["chef_ohai_system_mutation"] == "dangerous"
    assert risks["chef_ohai_literal_secret"] == "dangerous"
    assert risks["chef_ohai_sensitive_logging"] == "dangerous"

    gate = analyze_chef(data)
    assert gate["decision"] == "block"
    assert gate["total_changes"] == 18
    assert gate["risk_counts"] == {
        "safe": 0,
        "review": 9,
        "dangerous": 9,
        "irreversible": 0,
    }
    assert gate["plugin_count"] == 1
    assert gate["provides_count"] == 2
    assert gate["depends_count"] == 1
    assert gate["collect_data_count"] == 1
    assert gate["platform_count"] == 1
    encoded = json.dumps(gate)
    assert "fixture-ohai-secret-do-not-leak" not in encoded
    assert "FIXTURE_OHAI_ENDPOINT" not in encoded
    assert "fixture-ohai-inventory" not in encoded


def test_chef_ohai_recognizes_standalone_plugin_and_shared_common_library() -> None:
    plugin = """
Ohai.plugin(:Inventory) do
  provides 'inventory'
  collect_data do
    inventory Mash.new
  end
end
"""
    plugin_data = parse_chef(plugin, filename="custom_plugins/inventory.rb")
    assert plugin_data["chef_artifact_type"] == "ohai_plugin"
    assert plugin_data["chef_metadata"]["platform_count"] == 0
    assert plugin_data["chef_metadata"]["collect_data_count"] == 1

    library = """
module Ohai
  module Common
    module Inventory
      def inventory_value
        File.read('/etc/inventory')
      end
    end
  end
end
"""
    library_data = parse_chef(
        library,
        filename="cookbooks/platform/ohai/common/inventory.rb",
    )
    assert library_data["chef_artifact_type"] == "ohai_library"
    library_risks = {
        change.resource_type: change.risk
        for change in ChefAdapter().analyze(library_data, use_rules=False)
    }
    assert library_risks["chef_ohai_library_boundary"] == "review"
    assert library_risks["chef_ohai_runtime_data_access"] == "review"


def test_chef_ohai_surfaces_dynamic_contracts_and_missing_collection() -> None:
    source = """
Ohai.plugin do
  attrs.each { |attribute| provides attribute }
  depends dependency_name
end
"""
    data = parse_chef(source, filename="cookbooks/platform/ohai/dynamic.rb")
    changes = ChefAdapter().analyze(data, use_rules=False)
    kinds = {change.resource_type for change in changes}
    assert "chef_ohai_dynamic_or_anonymous_plugin" in kinds
    assert "chef_ohai_dynamic_provides" in kinds
    assert "chef_ohai_dynamic_dependency" in kinds
    assert "chef_ohai_missing_collection_block" in kinds
    assert data["chef_metadata"]["plugin_count"] == 1


def test_chef_ohai_comments_and_strings_do_not_create_findings() -> None:
    source = """
Ohai.plugin(:Inventory) do
  provides 'inventory'
  collect_data do
    message = "system('hidden') Net::HTTP File.write ENV['TOKEN']"
    # YAML.load(File.read('/tmp/hidden'))
    # api_token = "commented-secret"
    inventory Mash.new
  end
end
"""
    data = parse_chef(source, filename="cookbooks/platform/ohai/inventory.rb")
    kinds = {
        change.resource_type for change in ChefAdapter().analyze(data, use_rules=False)
    }
    assert "chef_ohai_command_execution" not in kinds
    assert "chef_ohai_network_access" not in kinds
    assert "chef_ohai_runtime_data_access" not in kinds
    assert "chef_ohai_system_mutation" not in kinds
    assert "chef_ohai_unsafe_deserialization" not in kinds
    assert "chef_ohai_literal_secret" not in kinds


def test_chef_ohai_surfaces_metadata_tls_deserialization_and_dynamic_ruby() -> None:
    source = """
Ohai.plugin(:Inventory) do
  provides *%w{ inventory inventory/private_key }
  depends 'network'
  collect_data(:linux, :windows) do
    can_metadata_connect?(EC2_METADATA_ADDR, 80)
    OpenSSL::SSL::VERIFY_NONE
    payload = YAML.load(File.read('/run/inventory'))
    inventory eval(payload)
  end
end
"""
    data = parse_chef(source, filename="cookbooks/platform/ohai/inventory.rb")
    kinds = {
        change.resource_type for change in ChefAdapter().analyze(data, use_rules=False)
    }
    assert "chef_ohai_cloud_metadata_access" in kinds
    assert "chef_ohai_tls_verification_disabled" in kinds
    assert "chef_ohai_unsafe_deserialization" in kinds
    assert "chef_ohai_dynamic_evaluation" in kinds
    assert "chef_ohai_sensitive_attribute" in kinds
    assert data["chef_metadata"]["provides_count"] == 2
    assert data["chef_metadata"]["platform_count"] == 2


def test_chef_ohai_static_analysis_never_executes_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Ohai source execution is forbidden")

    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    source = """
Ohai.plugin(:Inventory) do
  provides 'inventory'
  collect_data do
    system('fixture-command-must-not-run')
  end
end
"""
    data = parse_chef(source, filename="cookbooks/platform/ohai/inventory.rb")
    changes = ChefAdapter().analyze(data, use_rules=False)
    assert any(change.resource_type == "chef_ohai_command_execution" for change in changes)


def test_chef_ohai_cli_emits_redacted_plugin_metadata(capsys) -> None:
    assert main(["chef", "--framework", "soc2", str(OHAI_FIXTURE)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "chef"
    assert payload["artifact_type"] == "ohai_plugin"
    assert payload["plugin_count"] == 1
    assert payload["provides_count"] == 2
    assert payload["collect_data_count"] == 1
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
    encoded = json.dumps(payload)
    assert "fixture-ohai-secret-do-not-leak" not in encoded
