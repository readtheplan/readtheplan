from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from readtheplan.plan import analyze_plan_file
from readtheplan.rules._shared import _RULE_REGISTRY

FIXTURES = Path(__file__).parent / "fixtures"


def _summary_for(*changes: dict):
    return analyze_plan_file(
        {
            "format_version": "1.2",
            "terraform_version": "1.11.4",
            "resource_changes": list(changes),
        }
    )


def _change(
    resource_type: str,
    actions: list[str],
    *,
    before=None,
    after=None,
) -> dict:
    return {
        "address": f"{resource_type}.example",
        "type": resource_type,
        "name": "example",
        "change": {"actions": actions, "before": before, "after": after},
    }


def test_vault_provider_fixture_receives_resource_aware_rules() -> None:
    plan = json.loads((FIXTURES / "vault_provider_plan_risky.json").read_text())
    changes = analyze_plan_file(plan).resource_changes
    by_address = {change.address: change for change in changes}

    assert len(changes) == 36
    assert Counter(change.risk for change in changes) == {
        "dangerous": 28,
        "irreversible": 4,
        "review": 4,
    }
    assert "Terraform plan/state" in by_address[
        "vault_generic_secret.database"
    ].explanation
    assert "orphan token" in by_address["vault_token.automation"].explanation
    assert "wildcard, root, or sudo" in by_address[
        "vault_policy.platform_admin"
    ].explanation
    assert "wildcard identity" in by_address[
        "vault_aws_auth_backend_role.production"
    ].explanation
    assert "broaden issuance" in by_address[
        "vault_pki_secret_backend_role.unrestricted"
    ].explanation
    assert "certificate-authority trust anchor" in by_address[
        "vault_pki_secret_backend_root_cert.root"
    ].explanation
    assert "key export/deletion/plaintext backup" in by_address[
        "vault_transit_secret_backend_key.payments"
    ].explanation
    assert "skip managed credential rotation" in by_address[
        "vault_database_secret_backend_connection.production"
    ].explanation
    assert "administrative backend scope" in by_address[
        "vault_aws_secret_backend_role.administrator"
    ].explanation
    assert "arbitrary Vault API path" in by_address[
        "vault_generic_endpoint.root_config"
    ].explanation
    assert "strict destination networking" in by_address[
        "vault_secrets_sync_aws_destination.production"
    ].explanation
    assert "wildcard secret scope" in by_address[
        "vault_secrets_sync_association.everything"
    ].explanation
    assert "without a visible digest" in by_address[
        "vault_plugin.custom_database"
    ].explanation
    assert "enterprise isolation" in by_address[
        "vault_namespace.production"
    ].explanation
    assert "full Vault snapshots" in by_address[
        "vault_raft_snapshot_agent_config.disaster_recovery"
    ].explanation
    assert "any origin" in by_address["vault_sys_config_cors.public"].explanation
    assert "raw request or response" in by_address["vault_audit.file"].explanation
    assert by_address["vault_generic_secret.legacy"].risk == "irreversible"
    assert by_address["vault_audit_request_header.correlation"].risk == "review"


def test_published_vault_provider_resource_catalog_never_falls_back_to_safe() -> None:
    resource_types = sorted(
        resource_type
        for resource_type in _RULE_REGISTRY
        if resource_type.startswith("vault_")
    )
    assert len(resource_types) == 198

    for resource_type in resource_types:
        result = _summary_for(
            _change(resource_type, ["create"], after={})
        ).resource_changes[0]
        assert result.risk in {"review", "dangerous"}, resource_type
        assert "Vault" in result.explanation, resource_type


@pytest.mark.parametrize(
    ("resource_type", "after", "phrase"),
    [
        (
            "vault_pki_secret_backend_role",
            {"allow_any_name": True},
            "broaden issuance",
        ),
        (
            "vault_transit_secret_backend_key",
            {"exportable": True},
            "key export/deletion",
        ),
        (
            "vault_database_secret_backend_connection",
            {"verify_connection": False},
            "disable connection verification",
        ),
        (
            "vault_secrets_sync_gh_destination",
            {"name": "github"},
            "external cloud, GitHub, or Vercel",
        ),
        (
            "vault_plugin_runtime",
            {"name": "container"},
            "executable plugin code",
        ),
        (
            "vault_generic_endpoint",
            {"path": "sys/example"},
            "arbitrary Vault API path",
        ),
        (
            "vault_sys_config_cors",
            {"allowed_origins": ["*"]},
            "any origin",
        ),
    ],
)
def test_vault_high_value_provider_surfaces_have_first_party_semantics(
    resource_type: str, after: dict, phrase: str
) -> None:
    result = _summary_for(_change(resource_type, ["create"], after=after)).resource_changes[0]
    assert result.risk == "dangerous"
    assert phrase in result.explanation


@pytest.mark.parametrize(
    "resource_type",
    [
        "vault_generic_secret",
        "vault_kv_secret",
        "vault_kv_secret_v2",
        "vault_token",
        "vault_approle_auth_backend_role_secret_id",
    ],
)
def test_vault_secret_deletions_explain_irrecoverable_revocation(
    resource_type: str,
) -> None:
    result = _summary_for(
        _change(resource_type, ["delete"], before={"name": "secret"})
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "may not be recoverable from Terraform state" in result.explanation


def test_vault_replacement_explains_namespace_and_mount_migration() -> None:
    result = _summary_for(
        _change(
            "vault_mount",
            ["delete", "create"],
            before={"path": "old", "type": "kv"},
            after={"path": "new", "type": "kv-v2"},
        )
    ).resource_changes[0]
    assert result.risk == "dangerous"
    assert "namespace and mount identity" in result.explanation


def test_unrelated_provider_resource_keeps_generic_baseline() -> None:
    result = _summary_for(
        _change("example_policy", ["create"], after={"policy": "root"})
    ).resource_changes[0]
    assert result.risk == "safe"
    assert "Vault" not in result.explanation
