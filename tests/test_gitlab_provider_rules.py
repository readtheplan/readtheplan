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


def test_gitlab_provider_fixture_receives_resource_aware_rules() -> None:
    plan = json.loads((FIXTURES / "gitlab_provider_plan_risky.json").read_text())
    changes = analyze_plan_file(plan).resource_changes
    by_address = {change.address: change for change in changes}

    assert len(changes) == 36
    assert Counter(change.risk for change in changes) == {
        "dangerous": 24,
        "irreversible": 4,
        "review": 8,
    }
    assert "public Internet" in by_address["gitlab_project.public_api"].explanation
    assert "immediate permanent removal" in by_address["gitlab_project.legacy"].explanation
    assert "disable group two-factor" in by_address["gitlab_group.platform"].explanation
    assert "broaden network, signup" in by_address[
        "gitlab_application_settings.security"
    ].explanation
    assert "allow force pushes" in by_address["gitlab_branch_protection.main"].explanation
    assert "no deployment approval rule" in by_address[
        "gitlab_project_protected_environment.production"
    ].explanation
    assert "require zero approvals" in by_address[
        "gitlab_project_approval_rule.security"
    ].explanation
    assert by_address["gitlab_project_external_status_check.change_ticket"].risk == "review"
    assert by_address["gitlab_group_membership.platform_admin"].risk == "dangerous"
    assert by_address["gitlab_group_saml_link.engineering"].risk == "review"
    assert "high-privilege token scope" in by_address[
        "gitlab_project_access_token.deploy"
    ].explanation
    assert "unmasked" in by_address["gitlab_project_variable.cloud_key"].explanation
    assert "unprotected runner execution" in by_address[
        "gitlab_user_runner.shared"
    ].explanation
    assert "without a configured signing" in by_address[
        "gitlab_project_hook.deploy"
    ].explanation
    assert "overwrite diverged branches" in by_address[
        "gitlab_project_pull_mirror.upstream"
    ].explanation
    assert by_address["gitlab_pages_domain.docs"].risk == "dangerous"
    assert "disable the job-token inbound allowlist" in by_address[
        "gitlab_project_job_token_scopes.api"
    ].explanation
    assert "recurring pipeline execution" in by_address[
        "gitlab_pipeline_schedule.nightly"
    ].explanation
    assert "mutate a CI" in by_address["gitlab_repository_file.pipeline"].explanation
    assert "software supply-chain" in by_address["gitlab_release.v2"].explanation
    assert by_address["gitlab_compliance_framework.soc2"].risk == "review"
    assert "appears to disable coverage" in by_address[
        "gitlab_project_secret_detection_validity_checks.api"
    ].explanation
    assert "activate runner-controller" in by_address[
        "gitlab_runner_controller.autoscaler"
    ].explanation


def test_current_gitlab_provider_resource_catalog_never_falls_back_to_safe() -> None:
    resource_types = sorted(
        resource_type for resource_type in _RULE_REGISTRY if resource_type.startswith("gitlab_")
    )
    assert len(resource_types) == 130

    for resource_type in resource_types:
        result = _summary_for(
            _change(resource_type, ["create"], after={})
        ).resource_changes[0]
        assert result.risk in {"review", "dangerous"}, resource_type
        assert "GitLab" in result.explanation, resource_type


@pytest.mark.parametrize(
    ("resource_type", "after", "phrase"),
    [
        (
            "gitlab_group_branch_protection",
            {"branch": "main", "allow_force_push": True},
            "force pushes",
        ),
        (
            "gitlab_group_access_token",
            {"name": "automation", "scopes": ["api"], "access_level": "owner"},
            "credential",
        ),
        (
            "gitlab_project_job_token_scopes",
            {"project": 1, "enabled": False},
            "inbound allowlist",
        ),
        (
            "gitlab_project_push_mirror",
            {"project": 1, "url": "ssh://git@example.com/api", "enabled": True},
            "source/package replication",
        ),
        (
            "gitlab_project_security_policy_attachment",
            {"project": 1, "policy_project": 2},
            "security-policy attachment",
        ),
        (
            "gitlab_project_container_repository_protection",
            {"project": 1, "container_repository_path_pattern": "*"},
            "supply-chain",
        ),
    ],
)
def test_gitlab_high_value_provider_surfaces_have_first_party_semantics(
    resource_type: str, after: dict, phrase: str
) -> None:
    result = _summary_for(_change(resource_type, ["create"], after=after)).resource_changes[0]
    assert result.risk in {"review", "dangerous"}
    assert phrase in result.explanation


def test_gitlab_project_archive_on_destroy_is_explained_separately() -> None:
    result = _summary_for(
        _change(
            "gitlab_project",
            ["delete"],
            before={"name": "api", "archive_on_destroy": True},
        )
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "archive it instead of deleting it" in result.explanation


def test_gitlab_signed_tls_verified_hook_is_review() -> None:
    result = _summary_for(
        _change(
            "gitlab_project_hook",
            ["create"],
            after={
                "project": 1,
                "url": "https://events.example.com/gitlab",
                "enable_ssl_verification": True,
                "signing_token": "configured",
            },
        )
    ).resource_changes[0]
    assert result.risk == "review"
    assert "third-party service boundary" in result.explanation


@pytest.mark.parametrize(
    "resource_type",
    [
        "gitlab_personal_access_token",
        "gitlab_group_access_token",
        "gitlab_project_access_token",
        "gitlab_project_deploy_token",
        "gitlab_cluster_agent_token",
    ],
)
def test_gitlab_credential_deletions_explain_revocation(resource_type: str) -> None:
    result = _summary_for(
        _change(resource_type, ["delete"], before={"name": "TOKEN"})
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "Credential revocation" in result.explanation


def test_unrelated_provider_resource_keeps_generic_baseline() -> None:
    result = _summary_for(
        _change("example_project", ["create"], after={"visibility_level": "public"})
    ).resource_changes[0]
    assert result.risk == "safe"
    assert "GitLab" not in result.explanation
