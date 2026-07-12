from __future__ import annotations

from typing import Any

from readtheplan.rules._shared import RuleResult, register_rule

# Exact resource catalog published by PagerDuty/pagerduty v3.33.0.
PAGERDUTY_PROVIDER_RESOURCES = frozenset(
    {
        "pagerduty_addon",
        "pagerduty_alert_grouping_setting",
        "pagerduty_automation_actions_action",
        "pagerduty_automation_actions_action_service_association",
        "pagerduty_automation_actions_action_team_association",
        "pagerduty_automation_actions_runner",
        "pagerduty_automation_actions_runner_team_association",
        "pagerduty_business_service",
        "pagerduty_business_service_subscriber",
        "pagerduty_enablement",
        "pagerduty_escalation_policy",
        "pagerduty_event_orchestration",
        "pagerduty_event_orchestration_global",
        "pagerduty_event_orchestration_global_cache_variable",
        "pagerduty_event_orchestration_integration",
        "pagerduty_event_orchestration_router",
        "pagerduty_event_orchestration_service",
        "pagerduty_event_orchestration_service_cache_variable",
        "pagerduty_event_orchestration_unrouted",
        "pagerduty_event_rule",
        "pagerduty_extension",
        "pagerduty_extension_servicenow",
        "pagerduty_incident_custom_field",
        "pagerduty_incident_custom_field_option",
        "pagerduty_incident_type",
        "pagerduty_incident_type_custom_field",
        "pagerduty_incident_workflow",
        "pagerduty_incident_workflow_trigger",
        "pagerduty_jira_cloud_account_mapping_rule",
        "pagerduty_maintenance_window",
        "pagerduty_response_play",
        "pagerduty_ruleset",
        "pagerduty_ruleset_rule",
        "pagerduty_schedule",
        "pagerduty_schedulev2",
        "pagerduty_service",
        "pagerduty_service_custom_field",
        "pagerduty_service_custom_field_value",
        "pagerduty_service_dependency",
        "pagerduty_service_event_rule",
        "pagerduty_service_integration",
        "pagerduty_slack_connection",
        "pagerduty_tag",
        "pagerduty_tag_assignment",
        "pagerduty_team",
        "pagerduty_team_membership",
        "pagerduty_user",
        "pagerduty_user_contact_method",
        "pagerduty_user_handoff_notification_rule",
        "pagerduty_user_notification_rule",
        "pagerduty_webhook_subscription",
    }
)


_IDENTITY_RESOURCES = {
    "pagerduty_team",
    "pagerduty_team_membership",
    "pagerduty_user",
    "pagerduty_user_contact_method",
    "pagerduty_user_handoff_notification_rule",
    "pagerduty_user_notification_rule",
}

_ON_CALL_RESOURCES = {
    "pagerduty_escalation_policy",
    "pagerduty_schedule",
    "pagerduty_schedulev2",
}

_SERVICE_RESOURCES = {
    "pagerduty_alert_grouping_setting",
    "pagerduty_business_service",
    "pagerduty_business_service_subscriber",
    "pagerduty_service",
    "pagerduty_service_dependency",
}

_ORCHESTRATION_RESOURCES = {
    "pagerduty_event_orchestration",
    "pagerduty_event_orchestration_global",
    "pagerduty_event_orchestration_global_cache_variable",
    "pagerduty_event_orchestration_integration",
    "pagerduty_event_orchestration_router",
    "pagerduty_event_orchestration_service",
    "pagerduty_event_orchestration_service_cache_variable",
    "pagerduty_event_orchestration_unrouted",
    "pagerduty_event_rule",
    "pagerduty_ruleset",
    "pagerduty_ruleset_rule",
    "pagerduty_service_event_rule",
}

_AUTOMATION_RESOURCES = {
    "pagerduty_automation_actions_action",
    "pagerduty_automation_actions_action_service_association",
    "pagerduty_automation_actions_action_team_association",
    "pagerduty_automation_actions_runner",
    "pagerduty_automation_actions_runner_team_association",
}

_INTEGRATION_RESOURCES = {
    "pagerduty_extension",
    "pagerduty_extension_servicenow",
    "pagerduty_jira_cloud_account_mapping_rule",
    "pagerduty_service_integration",
    "pagerduty_slack_connection",
    "pagerduty_webhook_subscription",
}

_INCIDENT_AUTOMATION_RESOURCES = {
    "pagerduty_incident_workflow",
    "pagerduty_incident_workflow_trigger",
    "pagerduty_maintenance_window",
    "pagerduty_response_play",
}

_CUSTOMIZATION_RESOURCES = {
    "pagerduty_incident_custom_field",
    "pagerduty_incident_custom_field_option",
    "pagerduty_incident_type",
    "pagerduty_incident_type_custom_field",
    "pagerduty_service_custom_field",
    "pagerduty_service_custom_field_value",
}

_ASSOCIATION_RESOURCES = {
    "pagerduty_automation_actions_action_service_association",
    "pagerduty_automation_actions_action_team_association",
    "pagerduty_automation_actions_runner_team_association",
    "pagerduty_business_service_subscriber",
    "pagerduty_incident_type_custom_field",
    "pagerduty_service_custom_field_value",
    "pagerduty_tag_assignment",
    "pagerduty_team_membership",
}

_HARD_DELETE_RESOURCES = PAGERDUTY_PROVIDER_RESOURCES - _ASSOCIATION_RESOURCES - {
    "pagerduty_addon",
    "pagerduty_enablement",
    "pagerduty_tag",
}


def _desired(change: dict[str, Any]) -> dict[str, Any]:
    after = change.get("after")
    return after if isinstance(after, dict) else {}


def _walk(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk(item)


def _values(value: Any, *keys: str) -> list[Any]:
    expected = set(keys)
    return [item for key, item in _walk(value) if key in expected]


def _contains_text(value: Any, *needles: str) -> bool:
    expected = tuple(needle.lower() for needle in needles)
    return any(
        (isinstance(key, str) and any(needle in key.lower() for needle in expected))
        or (isinstance(item, str) and any(needle in item.lower() for needle in expected))
        for key, item in _walk(value)
    )


def _any_true(value: Any, *keys: str) -> bool:
    return any(item is True for item in _values(value, *keys))


def _plain_http(value: Any) -> bool:
    return any(
        isinstance(item, str) and item.lower().startswith("http://")
        for _key, item in _walk(value)
    )


def _label(resource_type: str) -> str:
    return resource_type.removeprefix("pagerduty_").replace("_", " ")


def _delete(resource_type: str, action_set: set[str]) -> RuleResult | None:
    if "delete" not in action_set:
        return None
    label = _label(resource_type)
    if "create" in action_set:
        return RuleResult(
            "dangerous",
            f"__TOOL__ will replace this PagerDuty {label}. Incident routing, escalation, "
            "identity, automation, or integration references may be interrupted. Review "
            "stable IDs, migration ordering, active incidents, dependents, and rollback.",
        )
    if resource_type in _HARD_DELETE_RESOURCES:
        return RuleResult(
            "irreversible",
            f"__TOOL__ will delete this PagerDuty {label}. On-call coverage, alert routing, "
            "incident automation, integration identity, or configuration history may not be "
            "recoverable. Verify exports, dependents, active incidents, and restoration steps.",
        )
    return RuleResult(
        "dangerous",
        f"__TOOL__ will remove this PagerDuty {label} association or configuration. Review "
        "affected responders, services, workflows, routing, ownership, and rollback.",
    )


@register_rule(*sorted(PAGERDUTY_PROVIDER_RESOURCES))
def _pagerduty_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(resource_type, action_set)
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []

    desired = _desired(change)
    label = _label(resource_type)

    if resource_type in _IDENTITY_RESOURCES:
        findings = ["change who can receive notifications or administer incident response"]
        if _contains_text(desired, "admin", "owner", "manager"):
            findings.append("grant an administrative or managerial role")
        if resource_type == "pagerduty_team_membership" and desired.get("role") == "manager":
            findings.append("grant team-manager authority")
        if resource_type == "pagerduty_user_contact_method":
            findings.append("change a responder's phone, email, SMS, or push destination")
        if "notification_rule" in resource_type:
            findings.append("change escalation delay and responder delivery channels")
        return [
            RuleResult(
                "dangerous",
                f"This PagerDuty {label} can {'; '.join(findings)}. Review least privilege, "
                "responder ownership, contact verification, notification gaps, offboarding, "
                "SSO/SCIM authority, time zones, and break-glass coverage.",
            )
        ]

    if resource_type in _ON_CALL_RESOURCES:
        findings = ["change who is on call and when incidents escalate"]
        if _contains_text(desired, "no one", "null", "unassigned"):
            findings.append("leave an escalation target unresolved")
        if _values(desired, "handoff_type", "handoffType"):
            findings.append("change handoff behavior between schedule layers")
        return [
            RuleResult(
                "dangerous",
                f"This PagerDuty {label} can {'; '.join(findings)}. Review every escalation "
                "target, delay, repeat count, rotation layer, restriction, handoff, time zone, "
                "coverage gap/overlap, override interaction, and fallback responder.",
            )
        ]

    if resource_type in _SERVICE_RESOURCES:
        findings = ["change ownership, incident creation, urgency, or service relationships"]
        if desired.get("status") == "disabled":
            findings.append("disable incident response for the service")
        if desired.get("alert_creation") == "create_incidents":
            findings.append("create incidents directly instead of retaining alerts")
        if desired.get("auto_resolve_timeout") in {0, "0"}:
            findings.append("disable automatic incident resolution")
        if desired.get("alert_grouping") in {"time", "intelligent", "content_based"}:
            findings.append("group alerts and potentially hide distinct failures")
        if resource_type == "pagerduty_service_dependency":
            findings.append("change technical dependency and business-impact propagation")
        return [
            RuleResult(
                "dangerous",
                f"This PagerDuty {label} can {'; '.join(findings)}. Review escalation policy, "
                "alert/incident creation, acknowledgement/resolve timeouts, urgency/support "
                "hours, grouping, dependencies, ownership, active incidents, and rollback.",
            )
        ]

    if resource_type in _ORCHESTRATION_RESOURCES:
        findings = ["route, transform, group, prioritize, suppress, or pause incoming events"]
        if _contains_text(desired, "suppress", "drop", "pause", "disabled"):
            findings.append("suppress or suspend alert delivery")
        if _contains_text(desired, "route_to", "route to", "escalation_policy"):
            findings.append("reroute incidents to a different service or escalation path")
        if _contains_text(desired, "automation_action", "webhook", "trigger"):
            findings.append("trigger downstream automation from event content")
        if _contains_text(desired, "cache_variable", "regex", "path"):
            findings.append("derive routing state from event fields or cached variables")
        return [
            RuleResult(
                "dangerous",
                f"This PagerDuty {label} can {'; '.join(findings)}. Review rule order and "
                "conditions, catch-all behavior, severity/priority changes, extraction and "
                "regex, suppression/pause duration, route targets, nested rules, active "
                "traffic, test events, and rollback.",
            )
        ]

    if resource_type in _AUTOMATION_RESOURCES:
        findings = ["execute an automation action during incident response"]
        if resource_type == "pagerduty_automation_actions_runner":
            findings.append("connect a runner with access to private infrastructure")
        if _contains_text(desired, "password", "secret", "token", "api_key", "credential"):
            findings.append("place credential-like runner/action inputs in Terraform state")
        if _plain_http(desired):
            findings.append("contact a runner or endpoint over plaintext HTTP")
        return [
            RuleResult(
                "dangerous",
                f"This PagerDuty {label} can {'; '.join(findings)}. Review executable action "
                "identity, runner network reach, credentials/state exposure, least privilege, "
                "team/service scope, invocation controls, audit evidence, timeout, and rollback.",
            )
        ]

    if resource_type in _INTEGRATION_RESOURCES:
        findings = ["send incident data to or accept events from an external integration"]
        if _plain_http(desired):
            findings.append("use a plaintext HTTP endpoint")
        if _contains_text(desired, "token", "secret", "password", "api_key", "integration_key"):
            findings.append("persist integration credentials or keys in Terraform state")
        if _any_true(desired, "active", "enabled", "enable"):
            findings.append("activate the integration immediately")
        return [
            RuleResult(
                "dangerous",
                f"This PagerDuty {label} can {'; '.join(findings)}. Review endpoint ownership, "
                "TLS and authentication, signing/secret rotation, payload sensitivity, event "
                "source trust, filters, scopes, delivery failures/retries, and revocation.",
            )
        ]

    if resource_type in _INCIDENT_AUTOMATION_RESOURCES:
        findings = ["change automated actions taken during an incident"]
        if resource_type == "pagerduty_maintenance_window":
            findings.append("suppress service alerts for a time window")
        if _contains_text(desired, "resolve", "acknowledge", "status_update", "conference"):
            findings.append("change incident status or communications automatically")
        if _contains_text(desired, "trigger", "condition", "priority"):
            findings.append("run from incident fields or trigger conditions")
        return [
            RuleResult(
                "dangerous",
                f"This PagerDuty {label} can {'; '.join(findings)}. Review trigger scope, "
                "step/action ordering, responders, services/teams, suppression interval, status "
                "changes, communications, idempotency, active incidents, and rollback.",
            )
        ]

    if resource_type in _CUSTOMIZATION_RESOURCES:
        return [
            RuleResult(
                "review",
                f"This PagerDuty {label} changes incident or service schema and operator "
                "workflow. Review field type/options, required/default behavior, incident-type "
                "associations, API/reporting consumers, migration of existing values, and "
                "rollback.",
            )
        ]

    # Add-ons, tags, assignments, and account-level enablement still affect the
    # operator surface or ownership model, but do not directly reroute alerts.
    return [
        RuleResult(
            "review",
            f"This PagerDuty {label} changes account UI, feature enablement, classification, "
            "or ownership metadata. Review target scope, URL/feature trust, reporting and "
            "automation consumers, permissions, rollout timing, and rollback.",
        )
    ]
