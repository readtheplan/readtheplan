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


def test_tfe_provider_fixture_receives_resource_aware_rules() -> None:
    plan = json.loads((FIXTURES / "tfe_provider_plan_risky.json").read_text())
    changes = analyze_plan_file(plan).resource_changes
    by_address = {change.address: change for change in changes}

    assert len(changes) == 36
    assert Counter(change.risk for change in changes) == {
        "dangerous": 28,
        "irreversible": 4,
        "review": 4,
    }
    assert "bearer credential" in by_address["tfe_agent_token.production"].explanation
    assert "without a visible finite lifetime" in by_address[
        "tfe_organization_token.automation"
    ].explanation
    assert "secret-like value without the sensitive flag" in by_address[
        "tfe_variable.database_password"
    ].explanation
    assert "write-only input value" in by_address["tfe_variable.dynamic"].explanation
    assert "plan/apply/state/variable permissions" in by_address[
        "tfe_team_access.platform_admin"
    ].explanation
    assert "owner, administrative, or wildcard" in by_address[
        "tfe_organization_membership.owner"
    ].explanation
    assert "disable an identity or federation guardrail" in by_address[
        "tfe_saml_settings.authentication"
    ].explanation
    assert "weaken enforcement" in by_address[
        "tfe_policy.no_public_access"
    ].explanation
    assert "allow policy override" in by_address["tfe_policy_set.global"].explanation
    assert "exclude a project or workspace" in by_address[
        "tfe_workspace_policy_set_exclusion.production"
    ].explanation
    assert "automatic apply, destroy, force deletion" in by_address[
        "tfe_workspace.production"
    ].explanation
    assert "execution mode from remote to local" in by_address[
        "tfe_workspace.production"
    ].explanation
    assert "beta multi-deployment stack" in by_address["tfe_stack.platform"].explanation
    assert "which infrastructure can execute" in by_address[
        "tfe_agent_pool_allowed_workspaces.production"
    ].explanation
    assert "plaintext HTTP" in by_address[
        "tfe_organization_run_task.security"
    ].explanation
    assert "without a visible HMAC" in by_address[
        "tfe_organization_run_task.security"
    ].explanation
    assert "without human confirmation" in by_address[
        "tfe_workspace_run.bootstrap"
    ].explanation
    assert "initiate or chain infrastructure runs" in by_address[
        "tfe_run_trigger.downstream"
    ].explanation
    assert "VCS credentials in Terraform state" in by_address[
        "tfe_oauth_client.github"
    ].explanation
    assert "VCS private key in Terraform state" in by_address[
        "tfe_ssh_key.github"
    ].explanation
    assert "without a visible checksum" in by_address[
        "tfe_terraform_version.custom"
    ].explanation
    assert "plaintext HTTP" in by_address[
        "tfe_notification_configuration.webhook"
    ].explanation
    assert "hold-your-own-key encryption" in by_address[
        "tfe_hyok_configuration.production"
    ].explanation
    assert by_address["tfe_workspace.legacy"].risk == "irreversible"
    assert by_address["tfe_project.platform"].risk == "review"


def test_published_tfe_provider_resource_catalog_never_falls_back_to_safe() -> None:
    resource_types = sorted(
        resource_type for resource_type in _RULE_REGISTRY if resource_type.startswith("tfe_")
    )
    assert len(resource_types) == 72

    for resource_type in resource_types:
        result = _summary_for(
            _change(resource_type, ["create"], after={})
        ).resource_changes[0]
        assert result.risk in {"review", "dangerous"}, resource_type
        assert "HCP Terraform/TFE" in result.explanation, resource_type


@pytest.mark.parametrize(
    ("resource_type", "after", "phrase"),
    [
        (
            "tfe_workspace",
            {"auto_apply": True, "global_remote_state": True},
            "automatic apply",
        ),
        (
            "tfe_variable",
            {"key": "API_TOKEN", "value": "x", "sensitive": False},
            "secret-like value",
        ),
        (
            "tfe_team_access",
            {"access": "admin"},
            "plan/apply/state/variable permissions",
        ),
        (
            "tfe_workspace_policy_set_exclusion",
            {"workspace_id": "workspace"},
            "exclude a project or workspace",
        ),
        (
            "tfe_organization_run_task",
            {"url": "http://task.internal"},
            "without a visible HMAC",
        ),
        (
            "tfe_oauth_client",
            {"api_url": "http://vcs.internal", "oauth_token": "redacted"},
            "VCS credentials in Terraform state",
        ),
        (
            "tfe_terraform_version",
            {"url": "http://artifacts.internal/terraform.zip"},
            "without a visible checksum",
        ),
    ],
)
def test_tfe_high_value_provider_surfaces_have_first_party_semantics(
    resource_type: str, after: dict, phrase: str
) -> None:
    result = _summary_for(_change(resource_type, ["create"], after=after)).resource_changes[0]
    assert result.risk == "dangerous"
    assert phrase in result.explanation


@pytest.mark.parametrize(
    "resource_type",
    [
        "tfe_agent_token",
        "tfe_audit_trail_token",
        "tfe_organization_token",
        "tfe_scim_token",
        "tfe_team_token",
    ],
)
def test_tfe_token_deletions_explain_revocation(resource_type: str) -> None:
    result = _summary_for(
        _change(resource_type, ["delete"], before={"description": "token"})
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "Credential revocation" in result.explanation


def test_tfe_replacement_explains_state_and_run_migration() -> None:
    result = _summary_for(
        _change(
            "tfe_workspace",
            ["delete", "create"],
            before={"name": "old"},
            after={"name": "new"},
        )
    ).resource_changes[0]
    assert result.risk == "dangerous"
    assert "migration order" in result.explanation


def test_unrelated_provider_resource_keeps_generic_baseline() -> None:
    result = _summary_for(
        _change("example_workspace", ["create"], after={"auto_apply": True})
    ).resource_changes[0]
    assert result.risk == "safe"
    assert "HCP Terraform/TFE" not in result.explanation
