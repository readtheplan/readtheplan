from __future__ import annotations

from typing import Any

from readtheplan.rules._shared import RuleResult, register_rule

# Exact resource catalog published by newrelic/newrelic v3.94.0.
NEWRELIC_PROVIDER_RESOURCES = frozenset(
    {
        "newrelic_account_management",
        "newrelic_alert_channel",
        "newrelic_alert_compound_condition",
        "newrelic_alert_condition",
        "newrelic_alert_muting_rule",
        "newrelic_alert_policy",
        "newrelic_alert_policy_channel",
        "newrelic_api_access_key",
        "newrelic_application_settings",
        "newrelic_aws_connection",
        "newrelic_browser_application",
        "newrelic_cardinality_management",
        "newrelic_cloud_aws_eu_sovereign_integrations",
        "newrelic_cloud_aws_eu_sovereign_link_account",
        "newrelic_cloud_aws_govcloud_integrations",
        "newrelic_cloud_aws_govcloud_link_account",
        "newrelic_cloud_aws_integrations",
        "newrelic_cloud_aws_link_account",
        "newrelic_cloud_azure_integrations",
        "newrelic_cloud_azure_link_account",
        "newrelic_cloud_gcp_integrations",
        "newrelic_cloud_gcp_link_account",
        "newrelic_cloud_oci_link_account",
        "newrelic_data_partition_rule",
        "newrelic_entity_tags",
        "newrelic_events_to_metrics_rule",
        "newrelic_federated_logs_partition",
        "newrelic_federated_logs_setup",
        "newrelic_fleet",
        "newrelic_fleet_configuration",
        "newrelic_fleet_deployment",
        "newrelic_fleet_members",
        "newrelic_group",
        "newrelic_infra_alert_condition",
        "newrelic_insights_event",
        "newrelic_key_transaction",
        "newrelic_log_parsing_rule",
        "newrelic_metric_pruning_rule",
        "newrelic_monitor_downtime",
        "newrelic_notification_channel",
        "newrelic_notification_destination",
        "newrelic_nrql_alert_condition",
        "newrelic_nrql_drop_rule",
        "newrelic_obfuscation_expression",
        "newrelic_obfuscation_rule",
        "newrelic_one_dashboard",
        "newrelic_one_dashboard_json",
        "newrelic_one_dashboard_raw",
        "newrelic_pipeline_cloud_rule",
        "newrelic_service_level",
        "newrelic_synthetics_alert_condition",
        "newrelic_synthetics_broken_links_monitor",
        "newrelic_synthetics_cert_check_monitor",
        "newrelic_synthetics_monitor",
        "newrelic_synthetics_multilocation_alert_condition",
        "newrelic_synthetics_private_location",
        "newrelic_synthetics_script_monitor",
        "newrelic_synthetics_secure_credential",
        "newrelic_synthetics_step_monitor",
        "newrelic_user",
        "newrelic_workflow",
        "newrelic_workflow_automation",
        "newrelic_workload",
    }
)


_IDENTITY_RESOURCES = {
    "newrelic_account_management",
    "newrelic_group",
    "newrelic_user",
}

_CREDENTIAL_RESOURCES = {
    "newrelic_api_access_key",
    "newrelic_synthetics_secure_credential",
}

_ALERT_RESOURCES = {
    "newrelic_alert_channel",
    "newrelic_alert_compound_condition",
    "newrelic_alert_condition",
    "newrelic_alert_muting_rule",
    "newrelic_alert_policy",
    "newrelic_alert_policy_channel",
    "newrelic_infra_alert_condition",
    "newrelic_nrql_alert_condition",
    "newrelic_synthetics_alert_condition",
    "newrelic_synthetics_multilocation_alert_condition",
}

_NOTIFICATION_RESOURCES = {
    "newrelic_notification_channel",
    "newrelic_notification_destination",
    "newrelic_workflow",
    "newrelic_workflow_automation",
}

_SYNTHETICS_RESOURCES = {
    "newrelic_browser_application",
    "newrelic_synthetics_broken_links_monitor",
    "newrelic_synthetics_cert_check_monitor",
    "newrelic_synthetics_monitor",
    "newrelic_synthetics_private_location",
    "newrelic_synthetics_script_monitor",
    "newrelic_synthetics_step_monitor",
}

_CLOUD_RESOURCES = {
    "newrelic_aws_connection",
    "newrelic_cloud_aws_eu_sovereign_integrations",
    "newrelic_cloud_aws_eu_sovereign_link_account",
    "newrelic_cloud_aws_govcloud_integrations",
    "newrelic_cloud_aws_govcloud_link_account",
    "newrelic_cloud_aws_integrations",
    "newrelic_cloud_aws_link_account",
    "newrelic_cloud_azure_integrations",
    "newrelic_cloud_azure_link_account",
    "newrelic_cloud_gcp_integrations",
    "newrelic_cloud_gcp_link_account",
    "newrelic_cloud_oci_link_account",
}

_DATA_PIPELINE_RESOURCES = {
    "newrelic_cardinality_management",
    "newrelic_data_partition_rule",
    "newrelic_events_to_metrics_rule",
    "newrelic_federated_logs_partition",
    "newrelic_federated_logs_setup",
    "newrelic_log_parsing_rule",
    "newrelic_metric_pruning_rule",
    "newrelic_nrql_drop_rule",
    "newrelic_obfuscation_expression",
    "newrelic_obfuscation_rule",
    "newrelic_pipeline_cloud_rule",
}

_FLEET_RESOURCES = {
    "newrelic_fleet",
    "newrelic_fleet_configuration",
    "newrelic_fleet_deployment",
    "newrelic_fleet_members",
}

_OBSERVABILITY_MODEL_RESOURCES = {
    "newrelic_application_settings",
    "newrelic_key_transaction",
    "newrelic_monitor_downtime",
    "newrelic_service_level",
    "newrelic_workload",
}

_DASHBOARD_RESOURCES = {
    "newrelic_one_dashboard",
    "newrelic_one_dashboard_json",
    "newrelic_one_dashboard_raw",
}

_ASSOCIATION_OR_PRESENTATION_RESOURCES = {
    "newrelic_alert_policy_channel",
    "newrelic_entity_tags",
    "newrelic_fleet_members",
    "newrelic_one_dashboard",
    "newrelic_one_dashboard_json",
    "newrelic_one_dashboard_raw",
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


def _any_false(value: Any, *keys: str) -> bool:
    return any(item is False for item in _values(value, *keys))


def _plain_http(value: Any) -> bool:
    return any(
        isinstance(item, str) and item.lower().startswith("http://")
        for _key, item in _walk(value)
    )


def _label(resource_type: str) -> str:
    return resource_type.removeprefix("newrelic_").replace("_", " ")


def _delete(resource_type: str, action_set: set[str]) -> RuleResult | None:
    if "delete" not in action_set:
        return None
    label = _label(resource_type)
    if "create" in action_set:
        return RuleResult(
            "dangerous",
            f"__TOOL__ will replace this New Relic {label}. Monitoring identity, alerting, "
            "telemetry routing, automation, or historical continuity may be interrupted. "
            "Review stable IDs, dependent policies/workflows, migration order, and rollback.",
        )
    if resource_type == "newrelic_account_management":
        return RuleResult(
            "irreversible",
            "__TOOL__ will remove this New Relic sub-account resource from state, but the "
            "provider does not delete the upstream account. Confirm state ownership and use "
            "New Relic's separate account-deletion process only with explicit approval.",
        )
    if resource_type in _ASSOCIATION_OR_PRESENTATION_RESOURCES:
        return RuleResult(
            "dangerous",
            f"__TOOL__ will delete this New Relic {label}. Review affected alert delivery, "
            "fleet membership, dashboards/tags, API consumers, and rollback.",
        )
    return RuleResult(
        "irreversible",
        f"__TOOL__ will delete this New Relic {label}. Alert history/configuration, keys, "
        "telemetry controls, cloud links, monitors, or automation may not be recoverable. "
        "Verify exports, dependents, coverage continuity, and restoration steps.",
    )


@register_rule(*sorted(NEWRELIC_PROVIDER_RESOURCES))
def _newrelic_candidates(
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
        findings = ["change account or user identity and access scope"]
        if _contains_text(desired, "admin", "owner", "full_platform", "core_user"):
            findings.append("grant elevated platform access")
        if resource_type == "newrelic_account_management":
            findings.append("create or rename a billable sub-account in a selected data region")
        if resource_type == "newrelic_group":
            findings.append("change group membership or role assignments")
        return [
            RuleResult(
                "dangerous",
                f"This New Relic {label} can {'; '.join(findings)}. Review organization/account "
                "scope, least privilege, authentication domain, SSO/SCIM authority, billing, "
                "region/data residency, offboarding, and break-glass ownership.",
            )
        ]

    if resource_type in _CREDENTIAL_RESOURCES:
        key_type = str(
            desired.get(
                "key_type",
                "secure" if resource_type == "newrelic_synthetics_secure_credential" else "API",
            )
        )
        return [
            RuleResult(
                "dangerous",
                f"This New Relic {label} creates or changes a {key_type} credential whose "
                "value is supplied to or returned through Terraform plan/state. Review account "
                "and user scope, ingest versus administrative capability, secret storage, "
                "output/log exposure, rotation, expiry, consumers, and revocation.",
            )
        ]

    if resource_type in _ALERT_RESOURCES:
        findings = ["change detection, muting, thresholds, priority, or alert delivery"]
        if "muting_rule" in resource_type:
            findings.append("mute matching issues and create an observability blind spot")
        if _any_false(desired, "enabled", "active", "open_violation_on_expiration"):
            findings.append("disable alert evaluation or delivery")
        if _contains_text(desired, "critical", "threshold", "violation_time_limit"):
            findings.append("change when incidents open or close")
        if _contains_text(desired, "loss_of_signal", "signal_lost"):
            findings.append("change loss-of-signal handling")
        return [
            RuleResult(
                "dangerous",
                f"This New Relic {label} can {'; '.join(findings)}. Review NRQL/signal scope, "
                "threshold direction/duration/occurrences, aggregation and delay, loss of "
                "signal, runbook URL, policy/channel linkage, muting schedule, test evidence, "
                "notification coverage, and rollback.",
            )
        ]

    if resource_type in _NOTIFICATION_RESOURCES:
        findings = ["route issues or execute automation from New Relic"]
        if _plain_http(desired):
            findings.append("send notifications or automation traffic over plaintext HTTP")
        if _contains_text(
            desired, "password", "secret", "token", "api_key", "auth_custom_header"
        ):
            findings.append("persist destination credentials or headers in Terraform state")
        if _any_false(desired, "enabled", "destinations_enabled", "enrichments_enabled"):
            findings.append("disable workflow delivery or enrichment")
        if resource_type == "newrelic_workflow_automation":
            findings.append("execute YAML-defined query, loop, switch, wait, and action steps")
        return [
            RuleResult(
                "dangerous",
                f"This New Relic {label} can {'; '.join(findings)}. Review issue filters, muted "
                "issue handling, destination ownership, TLS/authentication and secret rotation, "
                "payload sensitivity, automation scope/steps, retries, idempotency, and rollback.",
            )
        ]

    if resource_type in _SYNTHETICS_RESOURCES:
        findings = ["run active probes against public or private endpoints"]
        if "script_monitor" in resource_type or "step_monitor" in resource_type:
            findings.append("execute user-controlled browser/API code or steps")
        if resource_type == "newrelic_synthetics_private_location":
            findings.append("create private-location authentication material for a minion")
        if _contains_text(desired, "password", "secret", "token", "vse_password"):
            findings.append("place monitor credentials or VSE passwords in Terraform state")
        if _any_true(desired, "enable_screenshot_on_failure_and_script"):
            findings.append("capture screenshots that may contain sensitive application data")
        if "script_monitor" in resource_type and not _values(
            desired, "runtime_type_version", "runtimeTypeVersion"
        ):
            findings.append("omit the explicit Synthetics runtime version and risk forced drift")
        return [
            RuleResult(
                "dangerous",
                f"This New Relic {label} can {'; '.join(findings)}. Review target authorization, "
                "script/code and dependency trust, frequency/load, public/private locations, "
                "network reach, credentials/state exposure, runtime pinning, screenshots, "
                "validation bypasses, and disable/rollback behavior.",
            )
        ]

    if resource_type in _CLOUD_RESOURCES:
        findings = ["link a cloud account and ingest infrastructure telemetry"]
        if _contains_text(desired, "role_arn", "service_account", "client_id", "tenant_id"):
            findings.append("trust a cross-account role or workload identity")
        if _contains_text(desired, "secret", "private_key", "credentials"):
            findings.append("persist cloud credentials in Terraform state")
        if _any_true(desired, "metrics_polling_interval", "inventory_polling_interval"):
            findings.append("change polling and cloud API load")
        return [
            RuleResult(
                "dangerous",
                f"This New Relic {label} can {'; '.join(findings)}. Review cloud account/project "
                "identity, role permissions and external IDs, regions/services, metric/log "
                "scope, secrets/state exposure, API cost/quotas, data residency, and unlinking.",
            )
        ]

    if resource_type in _DATA_PIPELINE_RESOURCES:
        findings = ["transform, route, retain, aggregate, obfuscate, prune, or drop telemetry"]
        if _contains_text(desired, "drop_data", "drop_attributes", "delete", "prune"):
            findings.append("permanently discard telemetry or attributes")
        if resource_type == "newrelic_nrql_drop_rule":
            findings.append("use a deprecated resource past its June 30, 2026 end-of-life")
        if resource_type == "newrelic_federated_logs_setup":
            findings.append("grant read/write access to external object storage and log catalogs")
        if _contains_text(desired, "password", "secret", "token", "connection"):
            findings.append("reference credentials or privileged cloud connections")
        if _any_false(desired, "active", "enabled"):
            findings.append("disable a telemetry pipeline or partition")
        return [
            RuleResult(
                "dangerous",
                f"This New Relic {label} can {'; '.join(findings)}. Review NRQL/OTTL and rule "
                "order, match breadth, irreversible data loss, PII handling, retention and "
                "queryability, storage/role trust, cost/cardinality impact, migration, and "
                "rollback with sample telemetry.",
            )
        ]

    if resource_type in _FLEET_RESOURCES:
        findings = ["change agents, versions, configurations, or fleet membership"]
        if resource_type == "newrelic_fleet_deployment":
            findings.append("roll observability agents and configurations onto managed hosts")
        if _contains_text(desired, "latest", "auto"):
            findings.append("follow a mutable latest configuration or version")
        if _contains_text(desired, "secret", "token", "password"):
            findings.append("embed secret-like agent configuration in Terraform state")
        return [
            RuleResult(
                "dangerous",
                f"This New Relic {label} can {'; '.join(findings)}. Review target entities, "
                "agent binary/version provenance, configuration contents and secrets, rollout "
                "phase, resource/network access, draining/removal, health checks, and rollback.",
            )
        ]

    if resource_type in _OBSERVABILITY_MODEL_RESOURCES:
        findings = ["change service health, downtime, application behavior, or SLO evaluation"]
        if resource_type == "newrelic_monitor_downtime":
            findings.append("suppress Synthetics execution or alerting during a schedule")
        if resource_type == "newrelic_service_level":
            findings.append("change SLI/SLO queries, target, and reporting window")
        if resource_type == "newrelic_application_settings":
            findings.append("change APM sampling, error collection, or transaction tracing")
        return [
            RuleResult(
                "dangerous",
                f"This New Relic {label} can {'; '.join(findings)}. Review entity scope, query "
                "and thresholds, suppression/downtime schedule, sampling and data collection, "
                "SLO math, dependencies, reporting consumers, and rollback.",
            )
        ]

    if resource_type in _DASHBOARD_RESOURCES:
        public = _contains_text(desired, "public", "share", "permalink")
        return [
            RuleResult(
                "dangerous" if public else "review",
                f"This New Relic {label} changes dashboard queries, variables, permissions, "
                "and presentation"
                + (" and may expose telemetry through public sharing" if public else "")
                + ". Review NRQL cost/scope, sensitive fields, account/entity permissions, "
                "variable defaults, public links, API consumers, and rollback.",
            )
        ]

    if resource_type == "newrelic_insights_event":
        sensitive = _contains_text(desired, "password", "token", "secret", "email", "customer")
        return [
            RuleResult(
                "dangerous" if sensitive else "review",
                "This insights event writes custom telemetry into New Relic"
                + (" and appears to contain sensitive attributes" if sensitive else "")
                + ". Review event type, attribute sensitivity, account/retention, cardinality, "
                "downstream alerts/dashboards, and duplication.",
            )
        ]

    # Entity tags affect ownership, filtering, automation, and cost attribution.
    return [
        RuleResult(
            "review",
            f"This New Relic {label} changes observability metadata used by dashboards, alerts, "
            "workloads, ownership, and automation. Review target GUIDs, tag semantics, policy "
            "selectors, reporting/cost consumers, overwrite behavior, and rollback.",
        )
    ]
