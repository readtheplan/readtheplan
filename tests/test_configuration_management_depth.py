from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
import yaml

from readtheplan.adapters.ansible import AnsibleAdapter
from readtheplan.adapters.chef import ChefAdapter
from readtheplan.adapters.jenkins import JenkinsAdapter
from readtheplan.adapters.puppet import PuppetAdapter
from readtheplan.mcp_server import MCPToolInputError, agent_gate_configuration_management

FIXTURES = Path(__file__).parent / "fixtures"


def test_ansible_fixture_surfaces_execution_scope_and_task_controls() -> None:
    source = (FIXTURES / "ansible_config_management_risky.yml").read_text()
    changes = AnsibleAdapter().analyze({"plays": yaml.safe_load(source)}, tool_name="Ansible")
    by_type = {change.resource_type: change for change in changes}

    assert Counter(change.risk for change in changes) == {"dangerous": 7, "review": 2}
    assert "every inventory host" in by_type["ansible_play"].explanation
    assert "credential-like" not in by_type["ansible_play"].explanation
    assert "controller host" in by_type["ansible_shell"].explanation
    assert "TLS certificate validation is disabled" in by_type["ansible_get_url"].explanation
    assert "forces execution even during check mode" in by_type["ansible_command"].explanation
    assert "without no_log" in by_type["ansible_debug"].explanation
    assert by_type["ansible_import_playbook"].risk == "review"


def test_jenkins_fixture_surfaces_supply_chain_agents_and_dynamic_groovy() -> None:
    source = (FIXTURES / "Jenkinsfile.config-management-risky").read_text()
    changes = JenkinsAdapter().analyze({"jenkinsfile": source}, tool_name="Jenkins")
    by_type = {change.resource_type: change for change in changes}

    assert Counter(change.risk for change in changes) == {
        "dangerous": 9,
        "review": 5,
        "safe": 2,
    }
    assert "not pinned by digest" in by_type["jenkins_container_image"].explanation
    assert by_type["jenkins_agent_args"].risk == "dangerous"
    assert "mutable or implicit" in by_type["jenkins_shared_library"].explanation
    assert by_type["jenkins_script_block"].risk == "dangerous"
    assert by_type["jenkins_checkout"].risk == "review"
    assert by_type["jenkins_clean_workspace"].risk == "dangerous"


def test_chef_fixture_surfaces_remote_content_notifications_guards_and_identity() -> None:
    source = (FIXTURES / "chef_config_management_risky.rb").read_text()
    changes = ChefAdapter().analyze({"chef_recipe": source}, tool_name="Chef")
    by_type = {change.resource_type: change for change in changes}

    assert Counter(change.risk for change in changes) == {
        "dangerous": 6,
        "review": 1,
        "safe": 1,
    }
    assert "no checksum" in by_type["chef_remote_file"].explanation
    assert "local identity" in by_type["chef_user"].explanation
    assert "immediately notifies" in by_type["chef_template"].explanation
    assert "guard code" in by_type["chef_execute"].explanation
    assert by_type["chef_include_recipe"].risk == "review"


def test_puppet_fixture_surfaces_modules_dynamic_data_and_cross_node_resources() -> None:
    source = (FIXTURES / "puppet_config_management_risky.pp").read_text()
    changes = PuppetAdapter().analyze({"puppet_manifest": source}, tool_name="Puppet")
    by_type = {change.resource_type: change for change in changes}

    assert Counter(change.risk for change in changes) == {
        "dangerous": 6,
        "review": 4,
        "safe": 1,
    }
    assert "world-writable" in by_type["puppet_file"].explanation
    assert "PuppetDB" in by_type["puppet_ssh_authorized_key"].explanation
    assert "without a filter" in by_type["puppet_resource_collector"].explanation
    assert "not expanded" in by_type["puppet_class_include"].explanation
    assert "external data" in by_type["puppet_dynamic_function"].explanation
    assert by_type["puppet_profile_application"].risk == "review"


@pytest.mark.parametrize(
    ("ecosystem", "fixture"),
    [
        ("ansible", "ansible_config_management_risky.yml"),
        ("jenkins", "Jenkinsfile.config-management-risky"),
        ("chef", "chef_config_management_risky.rb"),
        ("puppet", "puppet_config_management_risky.pp"),
    ],
)
def test_configuration_management_mcp_gate_supports_all_four_ecosystems(
    ecosystem: str, fixture: str
) -> None:
    result = agent_gate_configuration_management(
        str(FIXTURES / fixture), ecosystem, framework="soc2"
    )
    assert result["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in result["required_checks"]


def test_configuration_management_mcp_gate_rejects_unknown_ecosystem() -> None:
    with pytest.raises(MCPToolInputError, match="ecosystem must be one of"):
        agent_gate_configuration_management("input.txt", "unknown")


def test_configuration_management_mcp_gate_enforces_working_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "Jenkinsfile"
    outside.write_text("pipeline { stages { echo 'outside' } }")
    monkeypatch.setenv("MCP_ROOT", str(root))

    with pytest.raises(MCPToolInputError, match="PATH_TRAVERSAL"):
        agent_gate_configuration_management(str(outside), "jenkins")


def test_jenkins_comment_handling_preserves_urls_and_ignores_commented_steps() -> None:
    source = """
pipeline {
  stages {
    // sh 'do-not-run'
    httpRequest url: 'https://example.com/hook'
  }
}
"""
    changes = JenkinsAdapter().analyze({"jenkinsfile": source}, use_rules=False)
    assert [change.resource_type for change in changes] == ["jenkins_http_request"]


def test_chef_nothing_action_and_one_line_resource_do_not_inherit_later_actions() -> None:
    source = """
log 'before'
service 'application' do
  action :nothing
end
"""
    changes = ChefAdapter().analyze({"chef_recipe": source}, use_rules=False)
    assert [change.risk for change in changes] == ["safe", "review"]
    assert changes[0].actions == ("converge",)


def test_unrealized_puppet_virtual_resource_requires_review_without_claiming_effect() -> None:
    source = "@user { 'deploy': ensure => present, }"
    change = PuppetAdapter().analyze({"puppet_manifest": source}, use_rules=False)[0]
    assert change.resource_type == "puppet_user"
    assert change.risk == "review"
    assert "only when realized" in change.explanation
