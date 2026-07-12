from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.hashicorp import (
    ConsulAdapter,
    HashiCorpInputError,
    VaultAdapter,
    parse_hashicorp_config,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(ecosystem: str, fixture: str) -> dict[str, list[str]]:
    data = parse_hashicorp_config((FIXTURES / fixture).read_text(encoding="utf-8"), ecosystem)
    adapter = VaultAdapter() if ecosystem == "vault" else ConsulAdapter()
    result: dict[str, list[str]] = defaultdict(list)
    for change in adapter.analyze(data, tool_name=ecosystem):
        result[change.resource_type].append(change.risk)
    return result


def test_vault_surfaces_listener_storage_seal_plugin_and_lockout_risks() -> None:
    risks = _risks("vault", "vault_risky.hcl")
    assert risks["vault_listener"] == ["review"]
    assert risks["vault_public_listener"] == ["dangerous"]
    assert risks["vault_plaintext_listener"] == ["dangerous"]
    assert risks["vault_legacy_tls"] == ["dangerous"]
    assert len(risks["vault_unauthenticated_metrics"]) == 2
    assert risks["vault_proxy_trust"] == ["dangerous"]
    assert risks["vault_storage_backend"] == ["review"]
    assert risks["vault_non_ha_storage"] == ["review"]
    assert risks["vault_ha_storage"] == ["review"]
    assert risks["vault_auto_unseal"] == ["dangerous"]
    assert risks["vault_memory_locking"] == ["dangerous"]
    assert risks["vault_raw_storage_api"] == ["dangerous"]
    assert risks["vault_plugin_execution"] == ["dangerous"]
    assert risks["vault_authentication_hardening"] == ["dangerous"]
    assert len(risks["vault_secret_material"]) >= 3


def test_consul_surfaces_cluster_acl_tls_mesh_and_execution_risks() -> None:
    risks = _risks("consul", "consul_risky.hcl")
    assert risks["consul_server_agent"] == ["review"]
    assert risks["consul_single_server_bootstrap"] == ["dangerous"]
    assert risks["consul_public_listener"] == ["dangerous"]
    assert risks["consul_plaintext_api"] == ["dangerous"]
    assert risks["consul_access_control"] == ["review"]
    assert risks["consul_disabled_acl"] == ["dangerous"]
    assert risks["consul_permissive_acl"] == ["dangerous"]
    assert len(risks["consul_insecure_tls"]) == 3
    assert risks["consul_gossip_encryption"] == ["dangerous"]
    assert len(risks["consul_insecure_gossip"]) == 2
    assert risks["consul_service_mesh"] == ["review"]
    assert len(risks["consul_cluster_discovery"]) == 2
    assert len(risks["consul_script_execution"]) == 2
    assert risks["consul_remote_execution"] == ["dangerous"]
    assert risks["consul_dynamic_configuration"] == ["dangerous"]
    assert len(risks["consul_secret_material"]) >= 2


def test_vault_json_and_consul_json_are_supported() -> None:
    vault = parse_hashicorp_config(
        json.dumps(
            {
                "listener": {"tcp": {"address": "127.0.0.1:8200"}},
                "storage": {"raft": {"path": "/vault"}},
            }
        ),
        "vault",
    )
    consul = parse_hashicorp_config(
        json.dumps({"server": False, "datacenter": "dc1", "data_dir": "/consul"}),
        "consul",
    )
    assert VaultAdapter().can_handle(vault)
    assert ConsulAdapter().can_handle(consul)


def test_secure_vault_listener_keeps_transport_at_review() -> None:
    data = parse_hashicorp_config(
        'listener "tcp" { address = "127.0.0.1:8200" tls_cert_file = "/tls/cert" }\n'
        'storage "raft" { path = "/vault" }\n',
        "vault",
    )
    changes = VaultAdapter().analyze(data, tool_name="vault")
    kinds = {change.resource_type: change.risk for change in changes}
    assert "vault_plaintext_listener" not in kinds
    assert kinds["vault_listener"] == "review"
    assert kinds["vault_storage_backend"] == "review"


def test_secure_consul_disables_http_and_verifies_tls() -> None:
    data = parse_hashicorp_config(
        json.dumps(
            {
                "server": False,
                "data_dir": "/consul",
                "ports": {"http": -1, "https": 8501},
                "tls": {
                    "defaults": {
                        "verify_incoming": True,
                        "verify_outgoing": True,
                        "verify_server_hostname": True,
                    }
                },
            }
        ),
        "consul",
    )
    changes = ConsulAdapter().analyze(data, tool_name="consul")
    kinds = {change.resource_type: change.risk for change in changes}
    assert "consul_plaintext_api" not in kinds
    assert "consul_insecure_tls" not in kinds
    assert kinds["consul_tls"] == "review"


@pytest.mark.parametrize(
    ("ecosystem", "source"),
    [
        ("vault", ""),
        ("vault", "server = true"),
        ("consul", 'listener "tcp" {}'),
        ("consul", "[]"),
        ("unknown", "foo = true"),
    ],
)
def test_parser_rejects_wrong_or_unrecognized_inputs(ecosystem: str, source: str) -> None:
    with pytest.raises(HashiCorpInputError):
        parse_hashicorp_config(source, ecosystem)


@pytest.mark.parametrize(
    ("ecosystem", "fixture"),
    [("vault", "vault_risky.hcl"), ("consul", "consul_risky.hcl")],
)
def test_cli_supports_framework_checks(capsys, ecosystem: str, fixture: str) -> None:
    assert main([ecosystem, "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == ecosystem
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
