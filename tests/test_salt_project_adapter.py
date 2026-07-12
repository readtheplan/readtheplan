from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.salt_project import (
    SaltProjectAdapter,
    SaltProjectInputError,
    analyze_salt_project,
    parse_salt_project,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(fixture: str):
    data = parse_salt_project((FIXTURES / fixture).read_text(encoding="utf-8"))
    return data, SaltProjectAdapter().analyze(data, tool_name="Salt project")


def test_master_config_surfaces_trust_sources_automation_acl_and_secrets() -> None:
    data, changes = _changes("salt_master_project_risky.yaml")
    dangerous = {change.resource_type for change in changes if change.risk == "dangerous"}

    assert data["salt_project"]["artifact_type"] == "config"
    assert isinstance(detect_adapter(data), SaltProjectAdapter)
    assert "salt_project_open_mode" in dangerous
    assert "salt_project_auto_accept" in dangerous
    assert "salt_project_broad_remote_authorization" in dangerous
    assert "salt_project_remote_state_source" in dangerous
    assert "salt_project_event_reactor" in dangerous
    assert "salt_project_scheduled_execution" in dangerous
    assert "salt_project_external_pillar" in dangerous
    assert "salt_project_pillar_disk_cache" in dangerous
    assert "salt_project_literal_secret" in dangerous
    assert any(
        change.resource_type == "salt_project_remote_state_source" and change.risk == "review"
        for change in changes
    )
    assert any(change.resource_type == "salt_project_credential_reference" for change in changes)


def test_minion_config_surfaces_dynamic_master_startup_mine_and_includes() -> None:
    _, changes = _changes("salt_minion_project_risky.yaml")
    by_type = {change.resource_type: change for change in changes}

    assert by_type["salt_project_dynamic_master_selection"].risk == "dangerous"
    assert by_type["salt_project_master_identity_verification"].risk == "dangerous"
    assert by_type["salt_project_startup_state_execution"].risk == "dangerous"
    assert by_type["salt_project_mine_execution"].risk == "dangerous"
    assert by_type["salt_project_event_beacons"].risk == "review"
    assert by_type["salt_project_master_endpoint"].risk == "review"
    assert by_type["salt_project_included_configuration"].risk == "review"


def test_top_file_surfaces_fleet_scope_matchers_and_environment_boundary() -> None:
    data, changes = _changes("salt_top_project_risky.sls")
    targets = [change for change in changes if change.resource_type.endswith("_target")]

    assert data["salt_project"]["artifact_type"] == "top"
    assert len(targets) == 3
    assert sum(change.risk == "dangerous" for change in targets) == 1
    assert any("entire minion fleet" in change.explanation for change in targets)
    assert any("nodegroup" in change.explanation for change in targets)


def test_roster_surfaces_password_privilege_host_key_proxy_and_preflight() -> None:
    data, changes = _changes("salt_roster_project_risky.yaml")
    dangerous = {change.resource_type for change in changes if change.risk == "dangerous"}

    assert data["salt_project"]["artifact_type"] == "roster"
    assert "salt_project_privileged_ssh" in dangerous
    assert "salt_project_literal_secret" in dangerous
    assert "salt_project_host_key_bypass" in dangerous
    assert "salt_project_preflight_execution" in dangerous
    assert sum(change.resource_type == "salt_project_ssh_target" for change in changes) == 2
    assert any(change.resource_type == "salt_project_private_key_file" for change in changes)
    assert any(change.resource_type == "salt_project_ssh_proxy" for change in changes)


def test_roster_defaults_root_user_when_user_is_omitted() -> None:
    data = parse_salt_project("node:\n  host: node.example.test\n  priv: /run/key\n")
    changes = SaltProjectAdapter().analyze(data)
    assert any(
        change.resource_type == "salt_project_privileged_ssh" and change.risk == "dangerous"
        for change in changes
    )


def test_yaml_merge_keys_are_supported_but_duplicate_explicit_keys_are_rejected() -> None:
    data = parse_salt_project(
        "defaults: &defaults\n  user: deploy\n  priv: /run/key\n"
        "node:\n  <<: *defaults\n  host: node.example.test\n"
    )
    assert data["salt_project"]["artifact_type"] == "roster"

    with pytest.raises(SaltProjectInputError, match="duplicate YAML key"):
        parse_salt_project("master: one\nmaster: two\n")


@pytest.mark.parametrize(
    ("source", "error"),
    [
        ("", "empty"),
        ("[]", "one YAML mapping"),
        ("hello: world", "not recognized"),
        ("base:\n  '*': 7\n", "string, list, or mapping"),
        ("node:\n  host: [bad]\n", "host must be a string"),
        ("master: '{{ pillar.master }}'\n", "rendered YAML"),
        ("master: one\n---\nmaster: two\n", "exactly one"),
    ],
)
def test_parser_rejects_unrelated_malformed_or_dynamic_input(source: str, error: str) -> None:
    with pytest.raises(SaltProjectInputError, match=error):
        parse_salt_project(source)


@pytest.mark.parametrize(
    ("fixture", "artifact_type"),
    [
        ("salt_master_project_risky.yaml", "config"),
        ("salt_top_project_risky.sls", "top"),
        ("salt_roster_project_risky.yaml", "roster"),
    ],
)
def test_gate_and_cli_support_every_salt_project_format(
    fixture: str,
    artifact_type: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = parse_salt_project((FIXTURES / fixture).read_text(encoding="utf-8"))
    gate = analyze_salt_project(data)
    assert gate["adapter"] == "salt-project"
    assert gate["artifact_type"] == artifact_type
    assert gate["decision"] == "block"
    assert gate["total_changes"] == sum(gate["risk_counts"].values())

    assert main(["salt-project", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "salt-project"
    assert payload["artifact_type"] == artifact_type
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
