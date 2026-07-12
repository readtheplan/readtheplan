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


def test_datadog_provider_fixture_receives_resource_aware_rules() -> None:
    plan = json.loads((FIXTURES / "datadog_provider_plan_risky.json").read_text())
    changes = analyze_plan_file(plan).resource_changes
    by_address = {change.address: change for change in changes}

    assert len(changes) == 36
    assert Counter(change.risk for change in changes) == {
        "dangerous": 25,
        "irreversible": 5,
        "review": 6,
    }
    assert "credential" in by_address["datadog_api_key.agent"].explanation
    assert "non-secure global Synthetics" in by_address[
        "datadog_synthetics_global_variable.password"
    ].explanation
    assert "organization-wide authorization boundary" in by_address[
        "datadog_role.platform_admin"
    ].explanation
    assert "disable an identity or access guardrail" in by_address[
        "datadog_ip_allowlist.corporate"
    ].explanation
    assert "disable security coverage" in by_address[
        "datadog_security_monitoring_default_rule.cloud"
    ].explanation
    assert "exclude assets" in by_address[
        "datadog_appsec_waf_exclusion_filter.health"
    ].explanation
    assert "mute or suppress" in by_address[
        "datadog_security_findings_mute_rule.all"
    ].explanation
    assert "cloud-account trust" in by_address[
        "datadog_integration_aws_account.production"
    ].explanation
    assert "without visible request authentication" in by_address[
        "datadog_webhook.deploy"
    ].explanation
    assert "storage or processing boundary" in by_address[
        "datadog_logs_archive.security"
    ].explanation
    assert "reduce rate from 1.0 to 0.1" in by_address[
        "datadog_apm_retention_filter.traces"
    ].explanation
    assert "suppress monitor notifications" in by_address[
        "datadog_downtime.production"
    ].explanation
    assert "weaken or disable an observability signal" in by_address[
        "datadog_monitor.api"
    ].explanation
    assert "private probe placement" in by_address[
        "datadog_synthetics_private_location.corporate"
    ].explanation
    assert "automated production or responder decision path" in by_address[
        "datadog_deployment_gate.production"
    ].explanation
    assert "mutable hosted data" in by_address[
        "datadog_datastore_item.release"
    ].explanation
    assert by_address["datadog_application_key.legacy"].risk == "irreversible"
    assert by_address["datadog_dashboard.overview"].risk == "review"


def test_current_datadog_provider_resource_catalog_never_falls_back_to_safe() -> None:
    resource_types = sorted(
        resource_type
        for resource_type in _RULE_REGISTRY
        if resource_type.startswith("datadog_")
    )
    assert len(resource_types) == 146

    for resource_type in resource_types:
        result = _summary_for(
            _change(resource_type, ["create"], after={})
        ).resource_changes[0]
        assert result.risk in {"review", "dangerous"}, resource_type
        assert "Datadog" in result.explanation, resource_type


@pytest.mark.parametrize(
    ("resource_type", "after", "phrase"),
    [
        (
            "datadog_security_monitoring_suppression",
            {"name": "maintenance", "suppression": True},
            "mute or suppress",
        ),
        (
            "datadog_integration_gcp_sts",
            {"automute": True},
            "cloud-account trust",
        ),
        (
            "datadog_logs_custom_destination",
            {"name": "lake"},
            "storage or processing boundary",
        ),
        (
            "datadog_downtime_schedule",
            {"scope": "env:prod"},
            "suppress monitor notifications",
        ),
        (
            "datadog_on_call_escalation_policy",
            {"name": "platform"},
            "responder decision path",
        ),
        (
            "datadog_app_builder_app",
            {"name": "operations"},
            "executable application behavior",
        ),
    ],
)
def test_datadog_high_value_provider_surfaces_have_first_party_semantics(
    resource_type: str, after: dict, phrase: str
) -> None:
    result = _summary_for(_change(resource_type, ["create"], after=after)).resource_changes[0]
    assert result.risk == "dangerous"
    assert phrase in result.explanation


@pytest.mark.parametrize(
    "resource_type",
    [
        "datadog_api_key",
        "datadog_application_key",
        "datadog_service_access_token",
        "datadog_service_account_application_key",
    ],
)
def test_datadog_credential_deletions_explain_revocation(resource_type: str) -> None:
    result = _summary_for(
        _change(resource_type, ["delete"], before={"name": "credential"})
    ).resource_changes[0]
    assert result.risk == "irreversible"
    assert "Credential revocation" in result.explanation


def test_datadog_replacement_explains_dependency_migration() -> None:
    result = _summary_for(
        _change(
            "datadog_logs_archive",
            ["delete", "create"],
            before={"name": "old"},
            after={"name": "new"},
        )
    ).resource_changes[0]
    assert result.risk == "dangerous"
    assert "migration order" in result.explanation


def test_unrelated_provider_resource_keeps_generic_baseline() -> None:
    result = _summary_for(
        _change("example_monitor", ["create"], after={"notify_no_data": False})
    ).resource_changes[0]
    assert result.risk == "safe"
    assert "Datadog" not in result.explanation
