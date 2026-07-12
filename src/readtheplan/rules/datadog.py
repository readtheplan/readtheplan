from __future__ import annotations

from typing import Any

from readtheplan.rules._shared import RuleResult, register_rule


def _desired(change: dict[str, Any]) -> dict[str, Any]:
    after = change.get("after")
    return after if isinstance(after, dict) else {}


def _previous(change: dict[str, Any]) -> dict[str, Any]:
    before = change.get("before")
    return before if isinstance(before, dict) else {}


def _walk(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk(item)


def _values(value: Any, key: str) -> list[Any]:
    return [item for candidate, item in _walk(value) if candidate == key]


def _any_true(value: Any, *keys: str) -> bool:
    return any(item is True for key in keys for item in _values(value, key))


def _any_false(value: Any, *keys: str) -> bool:
    return any(item is False for key in keys for item in _values(value, key))


def _contains(value: Any, *needles: str) -> bool:
    expected = {needle.lower() for needle in needles}
    for _key, item in _walk(value):
        if isinstance(item, str) and item.lower() in expected:
            return True
        if isinstance(item, (list, tuple, set)) and any(
            isinstance(entry, str) and entry.lower() in expected for entry in item
        ):
            return True
    return False


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _label(resource_type: str) -> str:
    return resource_type.removeprefix("datadog_").replace("_", " ")


def _delete(
    label: str,
    action_set: set[str],
    consequence: str,
) -> RuleResult | None:
    if "delete" not in action_set:
        return None
    if "create" in action_set:
        return RuleResult(
            "dangerous",
            f"__TOOL__ will replace this Datadog {label}. {consequence} Review dependent "
            "collectors, identities, routing, migration order, rollback, and recovery.",
        )
    return RuleResult(
        "irreversible",
        f"__TOOL__ will delete this Datadog {label}. {consequence} Confirm ownership, "
        "exports or recovery, dependent automation, and an explicit rollback path.",
    )


_CREDENTIAL_RESOURCES = (
    "datadog_api_key",
    "datadog_app_key_registration",
    "datadog_application_key",
    "datadog_service_access_token",
    "datadog_service_account_application_key",
    "datadog_synthetics_global_variable",
    "datadog_webhook_custom_variable",
)


@register_rule(*_CREDENTIAL_RESOURCES)
def _datadog_credential_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = _label(resource_type)
    deleted = _delete(
        label,
        action_set,
        "Credential revocation or secret replacement can immediately break agents, CI/CD, "
        "Synthetics, webhooks, integrations, or service automation.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _contains(after, "*", "admin"):
        weaknesses.append("grant wildcard or administrative scope")
    if _any_false(after, "secure"):
        weaknesses.append("store or expose the value without the strongest available control")
    if resource_type == "datadog_synthetics_global_variable" and not after.get("secure", False):
        weaknesses.append("create a non-secure global Synthetics variable")
    return [
        RuleResult(
            "dangerous",
            f"This Datadog {label} change creates, rotates, scopes, or exposes a credential"
            + (f" and can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review least privilege, secret storage, state-file exposure, rotation order, "
            "consumers, auditability, and revocation recovery.",
        )
    ]


_IDENTITY_RESOURCES = (
    "datadog_authn_mapping",
    "datadog_child_organization",
    "datadog_domain_allowlist",
    "datadog_ip_allowlist",
    "datadog_org_connection",
    "datadog_org_group",
    "datadog_org_group_membership",
    "datadog_org_group_policy",
    "datadog_org_group_policy_override",
    "datadog_organization_settings",
    "datadog_restriction_policy",
    "datadog_role",
    "datadog_service_account",
    "datadog_team",
    "datadog_team_hierarchy_links",
    "datadog_team_link",
    "datadog_team_membership",
    "datadog_team_permission_setting",
    "datadog_team_sync",
    "datadog_user",
    "datadog_user_role",
)


@register_rule(*_IDENTITY_RESOURCES)
def _datadog_identity_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = _label(resource_type)
    deleted = _delete(
        label,
        action_set,
        "Users, roles, policies, SSO mappings, service identities, team ownership, or network "
        "access boundaries may be removed or reassigned.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _contains(after, "admin", "administrator", "standard"):
        weaknesses.append("grant a broad role or principal relationship")
    if _contains(after, "*", "0.0.0.0/0", "::/0"):
        weaknesses.append("open a wildcard identity or network boundary")
    if resource_type in {
        "datadog_authn_mapping",
        "datadog_domain_allowlist",
        "datadog_ip_allowlist",
        "datadog_organization_settings",
    } and _any_false(after, "enabled", "enforce", "mfa_enabled"):
        weaknesses.append("disable an identity or access guardrail")
    if resource_type in {
        "datadog_role",
        "datadog_user_role",
        "datadog_authn_mapping",
        "datadog_restriction_policy",
        "datadog_org_group_policy",
        "datadog_org_group_policy_override",
        "datadog_organization_settings",
        "datadog_domain_allowlist",
        "datadog_ip_allowlist",
    }:
        weaknesses.append("change an organization-wide authorization boundary")
    return [
        RuleResult(
            "dangerous" if weaknesses else "review",
            f"This Datadog {label} change affects organization identity, authorization, SSO, "
            "network access, ownership, or delegation"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review principal lifecycle, least privilege, break-glass access, group/role "
            "mapping, allowed networks and domains, and audit continuity.",
        )
    ]


_SECURITY_RESOURCES = (
    "datadog_agentless_scanning_aws_scan_options",
    "datadog_agentless_scanning_azure_scan_options",
    "datadog_agentless_scanning_gcp_scan_options",
    "datadog_appsec_waf_custom_rule",
    "datadog_appsec_waf_exclusion_filter",
    "datadog_cloud_configuration_rule",
    "datadog_cloud_inventory_sync_config",
    "datadog_cloud_workload_security_agent_rule",
    "datadog_compliance_custom_framework",
    "datadog_compliance_resource_evaluation_filter",
    "datadog_csm_threats_agent_rule",
    "datadog_csm_threats_policy",
    "datadog_security_findings_due_date_rule",
    "datadog_security_findings_due_date_rules_order",
    "datadog_security_findings_mute_rule",
    "datadog_security_findings_mute_rules_order",
    "datadog_security_findings_ticket_creation_rule",
    "datadog_security_findings_ticket_creation_rules_order",
    "datadog_security_monitoring_critical_asset",
    "datadog_security_monitoring_default_rule",
    "datadog_security_monitoring_filter",
    "datadog_security_monitoring_rule",
    "datadog_security_monitoring_rule_json",
    "datadog_security_monitoring_suppression",
    "datadog_sensitive_data_scanner_group",
    "datadog_sensitive_data_scanner_group_order",
    "datadog_sensitive_data_scanner_rule",
)


@register_rule(*_SECURITY_RESOURCES)
def _datadog_security_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = _label(resource_type)
    deleted = _delete(
        label,
        action_set,
        "Detection, prevention, scanning, compliance, evidence handling, or sensitive-data "
        "coverage may be lost or interrupted.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _any_false(after, "enabled", "is_enabled", "monitoring_enabled", "scanning_enabled"):
        weaknesses.append("disable security coverage")
    if "exclusion" in resource_type or "filter" in resource_type:
        weaknesses.append("exclude assets, events, or findings from evaluation")
    if "mute" in resource_type or "suppression" in resource_type:
        weaknesses.append("mute or suppress security findings")
    if any(
        token in resource_type
        for token in ("exclusion", "filter", "mute", "suppression")
    ) and _contains(after, "*", "all"):
        weaknesses.append("apply a wildcard security scope")
    if _any_true(after, "mute", "suppression", "skip", "exclude"):
        weaknesses.append("bypass normal detection or finding handling")
    if resource_type == "datadog_sensitive_data_scanner_rule":
        if _values(after, "suppressions"):
            weaknesses.append("suppress sensitive-data matches")
        if _any_true(after, "should_save_match"):
            weaknesses.append("retain matches that privileged users may unmask")
    return [
        RuleResult(
            "dangerous" if weaknesses else "review",
            f"This Datadog {label} change affects security detection, prevention, scanning, "
            "compliance, findings workflow, or sensitive-data handling"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review coverage gaps, rule queries, exclusions, suppression duration, asset "
            "scope, evidence retention, notification paths, and rollback.",
        )
    ]


_INTEGRATION_RESOURCES = (
    "datadog_action_connection",
    "datadog_integration_aws_account",
    "datadog_integration_aws_account_ccm_config",
    "datadog_integration_aws_event_bridge",
    "datadog_integration_aws_external_id",
    "datadog_integration_azure",
    "datadog_integration_cloudflare_account",
    "datadog_integration_confluent_account",
    "datadog_integration_confluent_resource",
    "datadog_integration_fastly_account",
    "datadog_integration_fastly_service",
    "datadog_integration_gcp",
    "datadog_integration_gcp_sts",
    "datadog_integration_ms_teams_tenant_based_handle",
    "datadog_integration_ms_teams_workflows_webhook_handle",
    "datadog_integration_opsgenie_service_object",
    "datadog_integration_pagerduty",
    "datadog_integration_pagerduty_service_object",
    "datadog_integration_slack_channel",
    "datadog_team_connection",
    "datadog_webhook",
)


@register_rule(*_INTEGRATION_RESOURCES)
def _datadog_integration_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = _label(resource_type)
    deleted = _delete(
        label,
        action_set,
        "Cloud telemetry, alert delivery, incident response, identity federation, or external "
        "automation may stop or move to a different trust boundary.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _any_false(after, "ssl_verify", "verify_tls", "tls_verify") or _any_true(
        after, "skip_ssl_validation", "ignore_tls"
    ):
        weaknesses.append("disable TLS verification")
    if _contains(after, "*", "0.0.0.0/0", "::/0"):
        weaknesses.append("grant or route a wildcard scope")
    if resource_type in {
        "datadog_integration_aws_account",
        "datadog_integration_azure",
        "datadog_integration_gcp",
        "datadog_integration_gcp_sts",
        "datadog_integration_cloudflare_account",
    }:
        weaknesses.append("establish a cloud-account trust and telemetry boundary")
    if resource_type in {
        "datadog_webhook",
        "datadog_action_connection",
        "datadog_team_connection",
    } and not any(after.get(key) for key in ("custom_headers", "auth", "token", "secret")):
        weaknesses.append("send automation to an endpoint without visible request authentication")
    return [
        RuleResult(
            "dangerous" if weaknesses else "review",
            f"This Datadog {label} change crosses an external service, cloud account, or "
            "notification boundary"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review credentials and state exposure, source permissions, TLS, destination "
            "ownership, event scope, redaction, delivery tests, and rollback.",
        )
    ]


_LOGS_DATA_RESOURCES = (
    "datadog_apm_retention_filter",
    "datadog_apm_retention_filter_order",
    "datadog_aws_cur_config",
    "datadog_azure_uc_config",
    "datadog_cost_budget",
    "datadog_custom_allocation_rule",
    "datadog_custom_allocation_rules",
    "datadog_gcp_uc_config",
    "datadog_logs_archive",
    "datadog_logs_archive_order",
    "datadog_logs_custom_destination",
    "datadog_logs_custom_pipeline",
    "datadog_logs_index",
    "datadog_logs_index_order",
    "datadog_logs_integration_pipeline",
    "datadog_logs_metric",
    "datadog_logs_pipeline_order",
    "datadog_logs_restriction_query",
    "datadog_observability_pipeline",
    "datadog_reference_table",
    "datadog_rum_retention_filter",
    "datadog_rum_retention_filters_order",
    "datadog_tag_pipeline_ruleset",
    "datadog_tag_pipeline_rulesets",
)


@register_rule(*_LOGS_DATA_RESOURCES)
def _datadog_logs_data_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = _label(resource_type)
    before = _previous(change)
    after = _desired(change)
    deleted = _delete(
        label,
        action_set,
        "Telemetry, retained traces/RUM sessions, cost attribution, archives, indexes, derived "
        "metrics, routing, or lookup data may become unavailable or unrecoverable.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    weaknesses: list[str] = []
    for key in (
        "retention_days",
        "flex_retention_days",
        "rate",
        "trace_rate",
        "sample_rate",
    ):
        previous = _number(before.get(key))
        desired = _number(after.get(key))
        if previous is not None and desired is not None and desired < previous:
            weaknesses.append(
                f"reduce {key.replace('_', ' ')} from {before[key]} to {after[key]}"
            )
    if _any_false(after, "enabled", "is_enabled"):
        weaknesses.append("disable telemetry processing or delivery")
    if _contains(after, "*", "all") and "restriction" in resource_type:
        weaknesses.append("broaden a log-access restriction to wildcard data")
    if resource_type in {
        "datadog_logs_archive",
        "datadog_logs_custom_destination",
        "datadog_observability_pipeline",
    }:
        weaknesses.append("redirect telemetry across a storage or processing boundary")
    return [
        RuleResult(
            "dangerous" if weaknesses else "review",
            f"This Datadog {label} change affects telemetry collection, processing, routing, "
            "retention, access, cost attribution, or archive recovery"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review data classification, filters and order, retention, encryption, regional "
            "residency, destination credentials, cost, rehydration, and rollback.",
        )
    ]


_OBSERVABILITY_RESOURCES = (
    "datadog_dashboard",
    "datadog_dashboard_json",
    "datadog_dashboard_list",
    "datadog_dashboard_v2",
    "datadog_downtime",
    "datadog_downtime_schedule",
    "datadog_metric_metadata",
    "datadog_metric_tag_configuration",
    "datadog_monitor",
    "datadog_monitor_config_policy",
    "datadog_monitor_json",
    "datadog_powerpack",
    "datadog_powerpack_v2",
    "datadog_rum_application",
    "datadog_rum_metric",
    "datadog_secure_embed_dashboard",
    "datadog_service_level_objective",
    "datadog_slo_correction",
    "datadog_spans_metric",
    "datadog_synthetics_concurrency_cap",
    "datadog_synthetics_private_location",
    "datadog_synthetics_suite",
    "datadog_synthetics_test",
    "datadog_tag_indexing_rule",
    "datadog_tag_indexing_rule_exemption",
    "datadog_tag_indexing_rule_order",
)


@register_rule(*_OBSERVABILITY_RESOURCES)
def _datadog_observability_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = _label(resource_type)
    deleted = _delete(
        label,
        action_set,
        "Alerting, SLO history, dashboards, RUM/APM visibility, Synthetics coverage, metric "
        "meaning, or tag-based cost and access behavior may be lost.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    before = _previous(change)
    after = _desired(change)
    weaknesses: list[str] = []
    if _any_false(after, "enabled"):
        weaknesses.append("weaken or disable an observability signal")
    if any(
        before.get(key) is True and after.get(key) is False
        for key in ("notify_no_data", "include_tags")
    ):
        weaknesses.append("weaken or disable an observability signal")
    if _any_true(after, "silenced", "mute_first_recovery_notification"):
        weaknesses.append("silence alert delivery or recovery notification")
    if resource_type in {"datadog_downtime", "datadog_downtime_schedule"}:
        weaknesses.append("suppress monitor notifications during a downtime window")
    if resource_type == "datadog_secure_embed_dashboard":
        weaknesses.append("create a public embed URL and store its HMAC credential in state")
    if resource_type == "datadog_synthetics_private_location":
        weaknesses.append("change private probe placement and network reachability")
    return [
        RuleResult(
            "dangerous" if weaknesses else "review",
            f"This Datadog {label} change affects monitoring, alerting, SLOs, dashboards, RUM, "
            "APM, Synthetics, metrics, or tag semantics"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review queries, thresholds, no-data behavior, recipients, mute windows, SLO "
            "math, access, cardinality/cost, probe reachability, and rollback.",
        )
    ]


_INCIDENT_AUTOMATION_RESOURCES = (
    "datadog_deployment_gate",
    "datadog_incident_notification_rule",
    "datadog_incident_notification_template",
    "datadog_incident_type",
    "datadog_monitor_notification_rule",
    "datadog_on_call_escalation_policy",
    "datadog_on_call_schedule",
    "datadog_on_call_team_routing_rules",
    "datadog_on_call_user_notification_channel",
    "datadog_on_call_user_notification_rule",
    "datadog_security_notification_rule",
    "datadog_team_notification_rule",
    "datadog_workflow_automation",
)


@register_rule(*_INCIDENT_AUTOMATION_RESOURCES)
def _datadog_incident_automation_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = _label(resource_type)
    deleted = _delete(
        label,
        action_set,
        "Deployments, incidents, security alerts, escalation, schedules, routing, or automated "
        "response may stop or reach different responders.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _any_false(after, "enabled", "is_enabled"):
        weaknesses.append("disable a response or notification path")
    if _contains(after, "*", "all"):
        weaknesses.append("apply automation or routing to a wildcard scope")
    if resource_type in {
        "datadog_deployment_gate",
        "datadog_workflow_automation",
        "datadog_on_call_escalation_policy",
        "datadog_on_call_team_routing_rules",
    }:
        weaknesses.append("change an automated production or responder decision path")
    return [
        RuleResult(
            "dangerous" if weaknesses else "review",
            f"This Datadog {label} change affects deployment decisions, incident workflow, "
            "security notification, on-call routing, escalation, or automated response"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review triggers, permissions, recipients, time zones, fallbacks, loops, secret "
            "access, dry-run evidence, and rollback.",
        )
    ]


_PLATFORM_RESOURCES = (
    "datadog_app_builder_app",
    "datadog_dataset",
    "datadog_datastore",
    "datadog_datastore_item",
    "datadog_openapi_api",
    "datadog_service_definition_yaml",
    "datadog_software_catalog",
)


@register_rule(*_PLATFORM_RESOURCES)
def _datadog_platform_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = _label(resource_type)
    deleted = _delete(
        label,
        action_set,
        "Application definitions, datasets, datastore state, API contracts, ownership, or "
        "service-catalog dependencies may be removed.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _contains(after, "public", "*", "anonymous"):
        weaknesses.append("publish or grant wildcard access to the asset")
    if resource_type in {"datadog_app_builder_app", "datadog_datastore_item"}:
        weaknesses.append("change executable application behavior or mutable hosted data")
    return [
        RuleResult(
            "dangerous" if weaknesses else "review",
            f"This Datadog {label} change affects an application, API contract, dataset, hosted "
            "state, ownership model, or service catalog"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review data classification, access, schema compatibility, ownership, downstream "
            "consumers, execution permissions, backup/export, and rollback.",
        )
    ]
