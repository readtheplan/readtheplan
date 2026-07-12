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


def test_grafana_provider_fixture_receives_resource_aware_rules() -> None:
    plan = json.loads((FIXTURES / "grafana_provider_plan_risky.json").read_text())
    changes = analyze_plan_file(plan).resource_changes
    by_address = {change.address: change for change in changes}

    assert len(changes) == 36
    assert Counter(change.risk for change in changes) == {
        "dangerous": 28,
        "irreversible": 4,
        "review": 4,
    }
    assert "Terraform plan/state" in by_address[
        "grafana_cloud_access_policy_token.automation"
    ].explanation
    assert "without a finite lifetime" in by_address[
        "grafana_service_account_token.ci"
    ].explanation
    assert "sensitive metadata or hashes" in by_address[
        "grafana_apps_secret_securevalue_v1beta1.database"
    ].explanation
    assert "administrative, wildcard, or edit access" in by_address[
        "grafana_folder_permission.platform"
    ].explanation
    assert "plaintext HTTP" in by_address[
        "grafana_data_source.production"
    ].explanation
    assert "external service credentials" in by_address[
        "grafana_data_source.production"
    ].explanation
    assert "allow signup/admin mapping" in by_address[
        "grafana_sso_settings.ldap"
    ].explanation
    assert "synchronization guardrail" in by_address[
        "grafana_scim_config.organization"
    ].explanation
    assert "outside normal authenticated access" in by_address[
        "grafana_dashboard_public.status"
    ].explanation
    assert "rendered dashboard data" in by_address[
        "grafana_report.executives"
    ].explanation
    assert "out-of-band mutation" in by_address[
        "grafana_contact_point.security"
    ].explanation
    assert "suppress alert notifications" in by_address[
        "grafana_mute_timing.maintenance"
    ].explanation
    assert "cloud-account telemetry" in by_address[
        "grafana_cloud_provider_aws_account.production"
    ].explanation
    assert "write-only repository credentials" in by_address[
        "grafana_apps_provisioning_repository_v0alpha1.dashboards"
    ].explanation
    assert "auto-approve one or more MCP tool calls" in by_address[
        "grafana_assistant_mcp_server.operations"
    ].explanation
    assert "execute or schedule load" in by_address[
        "grafana_k6_schedule.hourly"
    ].explanation
    assert "plaintext HTTP" in by_address[
        "grafana_oncall_outgoing_webhook.remediate"
    ].explanation
    assert "private-probe credentials" in by_address[
        "grafana_synthetic_monitoring_probe.corporate"
    ].explanation
    assert "hosted observability stack" in by_address[
        "grafana_cloud_stack.production"
    ].explanation
    assert "unpinned latest plugin" in by_address[
        "grafana_cloud_plugin_installation.dynamic"
    ].explanation
    assert by_address["grafana_dashboard.legacy"].risk == "irreversible"
    assert by_address["grafana_annotation.release"].risk == "review"


def test_published_grafana_provider_resource_catalog_never_falls_back_to_safe() -> None:
    resource_types = sorted(
        resource_type
        for resource_type in _RULE_REGISTRY
        if resource_type.startswith("grafana_")
    )
    assert len(resource_types) == 111

    for resource_type in resource_types:
        result = _summary_for(
            _change(resource_type, ["create"], after={})
        ).resource_changes[0]
        assert result.risk in {"review", "dangerous"}, resource_type
        assert "Grafana" in result.explanation, resource_type


@pytest.mark.parametrize(
    ("resource_type", "after", "phrase"),
    [
        (
            "grafana_dashboard_public",
            {"dashboard_uid": "status", "is_enabled": True},
            "outside normal authenticated access",
        ),
        (
            "grafana_data_source",
            {"url": "http://metrics.internal", "secure_json_data_encoded": "{}"},
            "plaintext HTTP",
        ),
        (
            "grafana_folder_permission",
            {"permissions": [{"role": "Admin", "permission": "Admin"}]},
            "administrative, wildcard, or edit access",
        ),
        (
            "grafana_assistant_mcp_server",
            {"tool_approval_policies": {"apply": "auto_approve"}},
            "auto-approve",
        ),
        (
            "grafana_apps_provisioning_repository_v0alpha1",
            {"secure": {"token": {"value": "redacted"}}},
            "write-only repository credentials",
        ),
        (
            "grafana_oncall_outgoing_webhook",
            {"url": "http://automation.internal"},
            "without visible request authentication",
        ),
        (
            "grafana_cloud_plugin_installation",
            {"slug": "plugin", "version": "latest"},
            "unpinned latest plugin version",
        ),
    ],
)
def test_grafana_high_value_provider_surfaces_have_first_party_semantics(
    resource_type: str, after: dict, phrase: str
) -> None:
    result = _summary_for(_change(resource_type, ["create"], after=after)).resource_changes[0]
    assert result.risk == "dangerous"
    assert phrase in result.explanation


@pytest.mark.parametrize(
    "resource_type",
    [
        "grafana_cloud_access_policy_token",
        "grafana_cloud_stack_service_account_token",
        "grafana_service_account_token",
        "grafana_cloud_private_data_source_connect_network_token",
    ],
)
def test_grafana_credential_deletions_explain_revocation(resource_type: str) -> None:
    result = _summary_for(
        _change(resource_type, ["delete"], before={"name": "credential"})
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "Credential revocation" in result.explanation


def test_grafana_replacement_explains_dependency_migration() -> None:
    result = _summary_for(
        _change(
            "grafana_cloud_stack",
            ["delete", "create"],
            before={"slug": "old", "region_slug": "us"},
            after={"slug": "new", "region_slug": "eu"},
        )
    ).resource_changes[0]
    assert result.risk == "dangerous"
    assert "migration order" in result.explanation


def test_unrelated_provider_resource_keeps_generic_baseline() -> None:
    result = _summary_for(
        _change("example_dashboard", ["create"], after={"public": True})
    ).resource_changes[0]
    assert result.risk == "safe"
    assert "Grafana" not in result.explanation
