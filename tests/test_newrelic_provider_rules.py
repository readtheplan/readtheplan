from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from readtheplan.plan import analyze_plan_file
from readtheplan.rules._shared import _RULE_REGISTRY
from readtheplan.rules.newrelic import NEWRELIC_PROVIDER_RESOURCES

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


def test_newrelic_fixture_receives_resource_aware_rules() -> None:
    plan = json.loads((FIXTURES / "newrelic_provider_plan_risky.json").read_text())
    changes = analyze_plan_file(plan).resource_changes
    by_address = {change.address: change for change in changes}

    assert len(changes) == 36
    assert Counter(change.risk for change in changes) == {
        "dangerous": 28,
        "irreversible": 4,
        "review": 4,
    }
    assert "billable sub-account" in by_address[
        "newrelic_account_management.production"
    ].explanation
    assert "returned through Terraform plan/state" in by_address[
        "newrelic_api_access_key.automation"
    ].explanation
    assert "observability blind spot" in by_address[
        "newrelic_alert_muting_rule.deployments"
    ].explanation
    assert "plaintext HTTP" in by_address[
        "newrelic_notification_destination.webhook"
    ].explanation
    assert "YAML-defined query, loop, switch, wait, and action steps" in by_address[
        "newrelic_workflow_automation.remediate"
    ].explanation
    assert "capture screenshots" in by_address[
        "newrelic_synthetics_script_monitor.checkout"
    ].explanation
    assert "forced drift" in by_address[
        "newrelic_synthetics_script_monitor.checkout"
    ].explanation
    assert "persist cloud credentials in Terraform state" in by_address[
        "newrelic_cloud_gcp_link_account.production"
    ].explanation
    assert "June 30, 2026 end-of-life" in by_address[
        "newrelic_nrql_drop_rule.customer_data"
    ].explanation
    assert "external object storage" in by_address[
        "newrelic_federated_logs_setup.production"
    ].explanation
    assert "roll observability agents" in by_address[
        "newrelic_fleet_deployment.production"
    ].explanation
    assert "sensitive attributes" in by_address[
        "newrelic_insights_event.customer"
    ].explanation
    assert by_address["newrelic_api_access_key.legacy"].risk == "irreversible"
    assert by_address["newrelic_one_dashboard.operations"].risk == "review"


def test_published_newrelic_provider_catalog_never_falls_back_to_safe() -> None:
    assert len(NEWRELIC_PROVIDER_RESOURCES) == 63
    registered = {
        resource_type
        for resource_type in _RULE_REGISTRY
        if resource_type.startswith("newrelic_")
    }
    assert registered == NEWRELIC_PROVIDER_RESOURCES

    for resource_type in sorted(NEWRELIC_PROVIDER_RESOURCES):
        result = _summary_for(
            _change(resource_type, ["create"], after={})
        ).resource_changes[0]
        assert result.risk in {"review", "dangerous"}, resource_type
        assert "New Relic" in result.explanation or "insights event" in result.explanation
        assert result.source == "builtin", resource_type


@pytest.mark.parametrize(
    ("resource_type", "after", "phrase"),
    [
        (
            "newrelic_api_access_key",
            {"key_type": "USER"},
            "Terraform plan/state",
        ),
        (
            "newrelic_alert_muting_rule",
            {"enabled": True},
            "observability blind spot",
        ),
        (
            "newrelic_notification_destination",
            {"property": [{"key": "url", "value": "http://hooks.internal"}]},
            "plaintext HTTP",
        ),
        (
            "newrelic_synthetics_script_monitor",
            {"script": "console.log('test')", "vse_password": "secret"},
            "omit the explicit Synthetics runtime version",
        ),
        (
            "newrelic_cloud_azure_link_account",
            {"client_id": "client", "client_secret": "secret"},
            "persist cloud credentials",
        ),
        (
            "newrelic_pipeline_cloud_rule",
            {"type": "drop_data", "nrql": "DELETE FROM Log"},
            "permanently discard telemetry",
        ),
        (
            "newrelic_fleet_deployment",
            {"agent": [{"version": "latest"}]},
            "mutable latest",
        ),
    ],
)
def test_high_value_newrelic_surfaces_have_first_party_semantics(
    resource_type: str, after: dict, phrase: str
) -> None:
    result = _summary_for(_change(resource_type, ["create"], after=after)).resource_changes[0]
    assert result.risk == "dangerous"
    assert phrase in result.explanation


@pytest.mark.parametrize(
    "resource_type",
    [
        "newrelic_alert_policy",
        "newrelic_api_access_key",
        "newrelic_cloud_aws_link_account",
        "newrelic_synthetics_script_monitor",
        "newrelic_workflow_automation",
    ],
)
def test_newrelic_control_plane_deletes_require_recovery(resource_type: str) -> None:
    result = _summary_for(
        _change(resource_type, ["delete"], before={"name": "legacy"})
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "may not be recoverable" in result.explanation


def test_account_management_destroy_only_removes_terraform_state() -> None:
    result = _summary_for(
        _change("newrelic_account_management", ["delete"], before={"name": "account"})
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "does not delete the upstream account" in result.explanation


def test_newrelic_replacement_explains_monitoring_migration() -> None:
    result = _summary_for(
        _change(
            "newrelic_nrql_alert_condition",
            ["delete", "create"],
            before={"name": "old"},
            after={"name": "new"},
        )
    ).resource_changes[0]
    assert result.risk == "dangerous"
    assert "migration order" in result.explanation
    assert "alerting" in result.explanation


def test_unrelated_provider_resource_keeps_generic_baseline() -> None:
    result = _summary_for(
        _change("example_workflow", ["create"], after={"enabled": False})
    ).resource_changes[0]
    assert result.risk == "safe"
    assert "New Relic" not in result.explanation
