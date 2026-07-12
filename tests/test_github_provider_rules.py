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


def test_github_provider_fixture_receives_resource_aware_rules() -> None:
    plan = json.loads((FIXTURES / "github_provider_plan_risky.json").read_text())
    changes = analyze_plan_file(plan).resource_changes
    by_address = {change.address: change for change in changes}

    assert len(changes) == 36
    assert Counter(change.risk for change in changes) == {
        "dangerous": 22,
        "irreversible": 4,
        "review": 10,
    }
    assert "public Internet" in by_address["github_repository.public_api"].explanation
    assert "does not currently unarchive" in by_address[
        "github_repository.archived_service"
    ].explanation
    assert by_address["github_repository.legacy"].risk == "irreversible"
    assert by_address["github_branch.release"].risk == "review"
    assert "allow force pushes" in by_address["github_branch_protection.main"].explanation
    assert "disable ruleset enforcement" in by_address[
        "github_repository_ruleset.main"
    ].explanation
    assert by_address["github_organization_ruleset.baseline"].risk == "review"
    assert by_address["github_membership.platform_admin"].risk == "dangerous"
    assert by_address["github_team.platform"].risk == "review"
    assert "broad default repository permissions" in by_address[
        "github_organization_settings.security"
    ].explanation
    assert "unpinned actions" in by_address[
        "github_actions_repository_permissions.api"
    ].explanation
    assert "approve pull requests" in by_address[
        "github_actions_organization_workflow_permissions.default"
    ].explanation
    assert "Terraform state exposure" in by_address[
        "github_actions_secret.deploy"
    ].explanation
    assert "deployment self-review" in by_address[
        "github_repository_environment.production"
    ].explanation
    assert "write capability" in by_address[
        "github_repository_deploy_key.release"
    ].explanation
    assert "without a configured signing secret" in by_address[
        "github_repository_webhook.deploy"
    ].explanation
    assert by_address["github_organization_webhook.audit"].risk == "review"
    assert "public repositories" in by_address[
        "github_actions_runner_group.shared"
    ].explanation
    assert "identity asserted to cloud providers" in by_address[
        "github_actions_repository_oidc_subject_claim_customization_template.api"
    ].explanation
    assert "bypass the normal pull-request path" in by_address[
        "github_repository_file.release_workflow"
    ].explanation
    assert by_address["github_repository_file.readme"].risk == "review"
    assert "appears to disable coverage" in by_address[
        "github_enterprise_security_analysis_settings.defaults"
    ].explanation


def test_current_github_provider_resource_catalog_never_falls_back_to_safe() -> None:
    resource_types = sorted(
        resource_type for resource_type in _RULE_REGISTRY if resource_type.startswith("github_")
    )
    assert len(resource_types) == 88

    for resource_type in resource_types:
        result = _summary_for(
            _change(resource_type, ["create"], after={})
        ).resource_changes[0]
        assert result.risk in {"review", "dangerous"}, resource_type
        assert "GitHub" in result.explanation, resource_type


@pytest.mark.parametrize(
    ("resource_type", "after", "phrase"),
    [
        (
            "github_branch_protection_v3",
            {"repository": "api", "branch": "main", "enforce_admins": False},
            "administrators to bypass",
        ),
        (
            "github_enterprise_actions_permissions",
            {"allowed_actions": "all", "sha_pinning_required": False},
            "allow all actions",
        ),
        (
            "github_codespaces_organization_secret",
            {"secret_name": "TOKEN", "visibility": "all"},
            "credential",
        ),
        (
            "github_repository_environment_deployment_policy",
            {"repository": "api", "environment": "production", "branch_pattern": "*"},
            "which refs may deploy",
        ),
        (
            "github_enterprise_actions_runner_group",
            {"visibility": "all", "restricted_to_workflows": False},
            "all repositories",
        ),
        (
            "github_actions_organization_oidc_subject_claim_customization_template",
            {"include_claim_keys": ["repo", "environment"]},
            "cloud providers",
        ),
    ],
)
def test_github_high_value_provider_surfaces_have_first_party_semantics(
    resource_type: str, after: dict, phrase: str
) -> None:
    result = _summary_for(_change(resource_type, ["create"], after=after)).resource_changes[0]
    assert result.risk in {"dangerous", "review"}
    assert phrase in result.explanation


def test_github_repository_security_analysis_disable_is_dangerous() -> None:
    result = _summary_for(
        _change(
            "github_repository",
            ["update"],
            before={"name": "api", "visibility": "private"},
            after={
                "name": "api",
                "visibility": "private",
                "security_and_analysis": [
                    {
                        "advanced_security": [{"status": "enabled"}],
                        "secret_scanning_push_protection": [{"status": "disabled"}],
                    }
                ],
            },
        )
    ).resource_changes[0]
    assert result.risk == "dangerous"
    assert "disable secret scanning push protection" in result.explanation


def test_github_repository_without_visibility_uses_public_default_conservatively() -> None:
    result = _summary_for(
        _change("github_repository", ["create"], after={"name": "api"})
    ).resource_changes[0]
    assert result.risk == "dangerous"
    assert "public Internet" in result.explanation


def test_github_repository_archive_on_destroy_is_explained_not_called_data_deletion() -> None:
    result = _summary_for(
        _change(
            "github_repository",
            ["delete"],
            before={"name": "api", "archive_on_destroy": True},
        )
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "archive it instead of deleting it" in result.explanation


def test_github_inactive_signed_webhook_is_review() -> None:
    result = _summary_for(
        _change(
            "github_repository_webhook",
            ["create"],
            after={
                "repository": "api",
                "active": False,
                "configuration": [
                    {
                        "url": "https://events.example.com/github",
                        "insecure_ssl": False,
                        "secret": "configured",
                    }
                ],
            },
        )
    ).resource_changes[0]
    assert result.risk == "review"
    assert "outbound delivery" in result.explanation


@pytest.mark.parametrize(
    "resource_type",
    [
        "github_actions_secret",
        "github_actions_environment_secret",
        "github_actions_organization_secret",
        "github_codespaces_secret",
        "github_dependabot_secret",
    ],
)
def test_github_secret_deletions_explain_revocation(resource_type: str) -> None:
    result = _summary_for(
        _change(resource_type, ["delete"], before={"secret_name": "TOKEN"})
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "Credential revocation" in result.explanation


def test_unrelated_provider_resource_keeps_generic_baseline() -> None:
    result = _summary_for(
        _change("example_repository", ["create"], after={"visibility": "public"})
    ).resource_changes[0]
    assert result.risk == "safe"
    assert "GitHub" not in result.explanation


@pytest.mark.parametrize(
    ("resource_type", "after", "risk", "phrase"),
    [
        (
            "github_enterprise_ip_allow_list_entry",
            {"value": "0.0.0.0/0", "name": "anywhere", "is_active": True},
            "dangerous",
            "network locations",
        ),
        (
            "github_release",
            {"repository": "api", "tag_name": "v2.0.0", "draft": False},
            "dangerous",
            "software supply-chain",
        ),
        (
            "github_organization_custom_properties",
            {"properties": [{"property_name": "tier", "value_type": "single_select"}]},
            "review",
            "governance metadata",
        ),
        (
            "github_repository_topics",
            {"repository": "api", "topics": ["terraform", "security"]},
            "review",
            "repository-discovery",
        ),
    ],
)
def test_remaining_github_provider_catalog_has_explicit_semantics(
    resource_type: str, after: dict, risk: str, phrase: str
) -> None:
    result = _summary_for(_change(resource_type, ["create"], after=after)).resource_changes[0]
    assert result.risk == risk
    assert phrase in result.explanation
