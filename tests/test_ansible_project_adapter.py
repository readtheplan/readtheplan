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
    data = parse_ansible_project((FIXTURES / fixture).read_text(encoding="utf-8"))
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


@pytest.mark.parametrize(
    "source,error",
    [
        ("", "empty"),
        ("[web]\nhost = example.test\n", "recognized ansible.cfg"),
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
    ("fixture", "artifact_type"),
    [
        ("ansible_project_risky.cfg", "config"),
        ("ansible_requirements_risky.yml", "requirements"),
    ],
)
def test_ansible_project_gate_uses_shared_contract(fixture: str, artifact_type: str) -> None:
    data = parse_ansible_project((FIXTURES / fixture).read_text(encoding="utf-8"))
    gate = analyze_ansible_project(data)
    assert gate["adapter"] == "ansible-project"
    assert gate["artifact_type"] == artifact_type
    assert gate["decision"] == "block"
    assert gate["total_changes"] == sum(gate["risk_counts"].values())


def test_ansible_project_cli_reads_both_formats(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for fixture in ("ansible_project_risky.cfg", "ansible_requirements_risky.yml"):
        source = tmp_path / fixture
        source.write_text((FIXTURES / fixture).read_text(encoding="utf-8"), encoding="utf-8")
        assert main(["ansible-project", "--framework", "soc2", str(source)]) == 2
        payload = json.loads(capsys.readouterr().out)
        assert payload["adapter"] == "ansible-project"
        assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
