from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from readtheplan.plan import analyze_plan_file
from readtheplan.rules._shared import _RULE_REGISTRY
from readtheplan.rules.pagerduty import PAGERDUTY_PROVIDER_RESOURCES

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


def test_pagerduty_fixture_receives_resource_aware_rules() -> None:
    plan = json.loads((FIXTURES / "pagerduty_provider_plan_risky.json").read_text())
    changes = analyze_plan_file(plan).resource_changes
    by_address = {change.address: change for change in changes}

    assert len(changes) == 36
    assert Counter(change.risk for change in changes) == {
        "dangerous": 28,
        "irreversible": 4,
        "review": 4,
    }
    assert "administrative or managerial role" in by_address[
        "pagerduty_user.incident_commander"
    ].explanation
    assert "phone, email, SMS, or push destination" in by_address[
        "pagerduty_user_contact_method.phone"
    ].explanation
    assert "coverage gap/overlap" in by_address[
        "pagerduty_schedule.primary"
    ].explanation
    assert "disable incident response" in by_address[
        "pagerduty_service.api"
    ].explanation
    assert "suppress or suspend alert delivery" in by_address[
        "pagerduty_event_orchestration_global.account"
    ].explanation
    assert "trigger downstream automation" in by_address[
        "pagerduty_event_orchestration_service.api"
    ].explanation
    assert "private infrastructure" in by_address[
        "pagerduty_automation_actions_runner.production"
    ].explanation
    assert "plaintext HTTP" in by_address[
        "pagerduty_extension_servicenow.production"
    ].explanation
    assert "credentials or keys in Terraform state" in by_address[
        "pagerduty_service_integration.events"
    ].explanation
    assert "suppress service alerts" in by_address[
        "pagerduty_maintenance_window.deploy"
    ].explanation
    assert by_address["pagerduty_service.legacy"].risk == "irreversible"
    assert by_address["pagerduty_incident_custom_field.customer"].risk == "review"


def test_published_pagerduty_provider_catalog_never_falls_back_to_safe() -> None:
    assert len(PAGERDUTY_PROVIDER_RESOURCES) == 51
    registered = {
        resource_type
        for resource_type in _RULE_REGISTRY
        if resource_type.startswith("pagerduty_")
    }
    assert registered == PAGERDUTY_PROVIDER_RESOURCES

    for resource_type in sorted(PAGERDUTY_PROVIDER_RESOURCES):
        result = _summary_for(
            _change(resource_type, ["create"], after={})
        ).resource_changes[0]
        assert result.risk in {"review", "dangerous"}, resource_type
        assert "PagerDuty" in result.explanation, resource_type
        assert result.source == "builtin", resource_type


@pytest.mark.parametrize(
    ("resource_type", "after", "phrase"),
    [
        (
            "pagerduty_team_membership",
            {"role": "manager"},
            "team-manager authority",
        ),
        (
            "pagerduty_service",
            {"status": "disabled", "auto_resolve_timeout": 0},
            "disable incident response",
        ),
        (
            "pagerduty_event_orchestration_service",
            {"actions": {"suppress": True, "automation_action": "restart"}},
            "trigger downstream automation",
        ),
        (
            "pagerduty_automation_actions_runner",
            {"api_key": "redacted", "endpoint": "http://runner.internal"},
            "plaintext HTTP",
        ),
        (
            "pagerduty_webhook_subscription",
            {"delivery_method": {"url": "http://hooks.internal", "secret": "x"}},
            "persist integration credentials",
        ),
        (
            "pagerduty_maintenance_window",
            {"services": ["production"]},
            "suppress service alerts",
        ),
    ],
)
def test_high_value_pagerduty_surfaces_have_first_party_semantics(
    resource_type: str, after: dict, phrase: str
) -> None:
    result = _summary_for(_change(resource_type, ["create"], after=after)).resource_changes[0]
    assert result.risk == "dangerous"
    assert phrase in result.explanation


@pytest.mark.parametrize(
    "resource_type",
    [
        "pagerduty_escalation_policy",
        "pagerduty_schedule",
        "pagerduty_service",
        "pagerduty_user",
        "pagerduty_webhook_subscription",
    ],
)
def test_control_plane_deletes_require_recovery(resource_type: str) -> None:
    result = _summary_for(
        _change(resource_type, ["delete"], before={"name": "legacy"})
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "may not be recoverable" in result.explanation


def test_pagerduty_replacement_explains_active_incident_migration() -> None:
    result = _summary_for(
        _change(
            "pagerduty_service",
            ["delete", "create"],
            before={"name": "old"},
            after={"name": "new"},
        )
    ).resource_changes[0]
    assert result.risk == "dangerous"
    assert "active incidents" in result.explanation
    assert "migration ordering" in result.explanation


def test_unrelated_provider_resource_keeps_generic_baseline() -> None:
    result = _summary_for(
        _change("example_service", ["create"], after={"status": "disabled"})
    ).resource_changes[0]
    assert result.risk == "safe"
    assert "PagerDuty" not in result.explanation
