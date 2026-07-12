from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.nix import (
    NixInputError,
    NixProjectAdapter,
    analyze_nix_project,
    parse_nix_project,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(fixture: str):
    data = parse_nix_project((FIXTURES / fixture).read_text(encoding="utf-8"))
    return data, NixProjectAdapter().analyze(data, tool_name="Nix/NixOS")


def test_flake_source_surfaces_inputs_fetches_impurity_builds_and_overlays() -> None:
    data, changes = _changes("flake_risky.nix")
    kinds = {change.resource_type for change in changes}

    assert data["nix_project"]["artifact_type"] == "flake"
    assert isinstance(detect_adapter(data), NixProjectAdapter)
    assert sum(change.resource_type == "nix_flake_input" for change in changes) == 2
    assert "nix_input_follows" in kinds
    assert "nix_source_fetch" in kinds
    assert "nix_impure_evaluation" in kinds
    assert "nix_build_code" in kinds
    assert "nix_package_overlay" in kinds
    assert "nix_evaluation_boundary" in kinds
    assert any(
        change.resource_type == "nix_flake_input" and change.risk == "dangerous"
        for change in changes
    )


def test_nixos_module_surfaces_daemon_identity_network_scripts_and_secrets() -> None:
    data, changes = _changes("nixos_module_risky.nix")
    dangerous = {change.resource_type for change in changes if change.risk == "dangerous"}

    assert data["nix_project"]["artifact_type"] == "module"
    assert "nix_wildcard_trusted_users" in dangerous
    assert "nix_sandbox_disabled" in dangerous
    assert "nix_signature_verification_disabled" in dangerous
    assert "nix_import_from_derivation" in dangerous
    assert "nix_accept_flake_config" in dangerous
    assert "nix_firewall_disabled" in dangerous
    assert "nix_ssh_root_login" in dangerous
    assert "nix_ssh_password_authentication" in dangerous
    assert "nix_weak_ssh_authentication" in dangerous
    assert "nix_null_pam_password" in dangerous
    assert "nix_passwordless_wheel_sudo" in dangerous
    assert "nix_root_password" in dangerous
    assert "nix_host_script_execution" in dangerous
    assert "nix_kernel_parameters" in dangerous
    assert "nix_privileged_container" in dangerous
    assert "nix_root_remote_builder" in dangerous
    assert "nix_plaintext_substituter" in dangerous
    assert "nix_literal_secret" in dangerous
    assert any(change.resource_type == "nix_secret_reference" for change in changes)
    assert sum(change.resource_type == "nix_enabled_service" for change in changes) == 2


def test_flake_lock_surfaces_graph_integrity_mutability_transport_and_local_paths() -> None:
    data, changes = _changes("flake_lock_risky.json")
    by_address = {change.address: change for change in changes}

    assert data["nix_project"]["artifact_type"] == "lock"
    assert by_address["lock.nodes.root.inputs.missing"].risk == "dangerous"
    assert by_address["lock.nodes.root.inputs.shared"].risk == "review"
    assert by_address["lock.nodes.nixpkgs"].risk == "review"
    assert by_address["lock.nodes.ops"].risk == "dangerous"
    assert "credentials" in by_address["lock.nodes.ops"].explanation
    assert by_address["lock.nodes.local"].risk == "review"
    assert by_address["lock.nodes.unlocked.locked"].risk == "dangerous"
    assert any(change.resource_type == "nix_lock_boundary" for change in changes)


def test_lock_cycles_and_invalid_follows_paths_are_dangerous() -> None:
    data = parse_nix_project(
        '{"nodes":{"root":{"inputs":{"a":"a"}},'
        '"a":{"inputs":{"b":"b","bad":[]},"locked":{"type":"path",'
        '"path":"a","narHash":"sha256-a"}},'
        '"b":{"inputs":{"a":"a"},"locked":{"type":"path",'
        '"path":"b","narHash":"sha256-b"}}},"root":"root","version":7}'
    )
    changes = NixProjectAdapter().analyze(data)
    dangerous = {change.resource_type for change in changes if change.risk == "dangerous"}
    assert "nix_invalid_follows_path" in dangerous
    assert "nix_input_cycle" in dangerous


def test_comments_do_not_create_fake_nix_findings() -> None:
    data = parse_nix_project(
        "{ ... }: {\n"
        "  # networking.firewall.enable = false;\n"
        "  /* users.users.root.password = \"fake\"; */\n"
        "  services.openssh.enable = true;\n"
        "}\n"
    )
    changes = NixProjectAdapter().analyze(data)
    kinds = {change.resource_type for change in changes}
    assert "nix_firewall_disabled" not in kinds
    assert "nix_root_password" not in kinds
    assert "nix_enabled_service" in kinds


def test_nested_flake_input_set_is_discovered() -> None:
    data = parse_nix_project(
        "{\n"
        "  inputs = {\n"
        "    nixpkgs.url = \"github:NixOS/nixpkgs/nixos-unstable\";\n"
        "    home-manager.url = \"github:nix-community/home-manager\";\n"
        "  };\n"
        "  outputs = inputs: { };\n"
        "}\n"
    )
    changes = NixProjectAdapter().analyze(data)
    assert sum(change.resource_type == "nix_flake_input" for change in changes) == 2


@pytest.mark.parametrize(
    ("source", "error"),
    [
        ("", "empty"),
        ("hello = world;", "not recognized"),
        ('{"nodes":{},"root":"root","version":7}', "non-empty"),
        ('{"nodes":{"root":{}},"root":"missing","version":7}', "existing node"),
        ('{"nodes":{"root":{}},"root":"root","version":0}', "positive integer"),
        ('{"nodes":{"root":{}},"root":"root","version":7', "invalid flake.lock JSON"),
        ('{"nodes":{"root":{},"root":{}},"root":"root","version":7}', "duplicate JSON key"),
        ("{ ... }: { services.openssh.enable = true; /*", "unterminated block"),
        ('{ ... }: { services.openssh.enable = "oops; };', "unterminated quoted"),
    ],
)
def test_parser_rejects_unrelated_or_malformed_input(source: str, error: str) -> None:
    with pytest.raises(NixInputError, match=error):
        parse_nix_project(source)


@pytest.mark.parametrize(
    ("fixture", "artifact_type"),
    [
        ("flake_risky.nix", "flake"),
        ("nixos_module_risky.nix", "module"),
        ("flake_lock_risky.json", "lock"),
    ],
)
def test_gate_and_cli_support_every_nix_artifact(
    fixture: str,
    artifact_type: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = parse_nix_project((FIXTURES / fixture).read_text(encoding="utf-8"))
    gate = analyze_nix_project(data)
    assert gate["adapter"] == "nix"
    assert gate["artifact_type"] == artifact_type
    assert gate["decision"] == "block"
    assert gate["total_changes"] == sum(gate["risk_counts"].values())

    assert main(["nix", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "nix"
    assert payload["artifact_type"] == artifact_type
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
