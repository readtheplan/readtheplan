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


def _values(value: Any, *keys: str) -> list[Any]:
    expected = set(keys)
    return [item for key, item in _walk(value) if key in expected]


def _any_true(value: Any, *keys: str) -> bool:
    return any(item is True for item in _values(value, *keys))


def _any_false(value: Any, *keys: str) -> bool:
    return any(item is False for item in _values(value, *keys))


def _contains(value: Any, *needles: str) -> bool:
    expected = {needle.lower() for needle in needles}
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str) and item.lower() in expected:
            return True
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, (list, tuple, set)):
            pending.extend(item)
    return False


def _text_contains(value: Any, *needles: str) -> bool:
    expected = tuple(needle.lower() for needle in needles)
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str) and any(needle in item.lower() for needle in expected):
            return True
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, (list, tuple, set)):
            pending.extend(item)
    return False


def _label(resource_type: str) -> str:
    return resource_type.removeprefix("grafana_").replace("_", " ")


def _delete(label: str, action_set: set[str], consequence: str) -> RuleResult | None:
    if "delete" not in action_set:
        return None
    if "create" in action_set:
        return RuleResult(
            "dangerous",
            f"__TOOL__ will replace this Grafana {label}. {consequence} Review stable identity, "
            "dependent dashboards/alerts/clients, migration order, rollback, and recovery.",
        )
    return RuleResult(
        "irreversible",
        f"__TOOL__ will delete this Grafana {label}. {consequence} Dashboards, alert history, "
        "tokens, integrations, or hosted state may not be reconstructable from Terraform.",
    )


_GRAFANA_RESOURCES = (
    "grafana_annotation",
    "grafana_apps_alertenrichment_alertenrichment_v1beta1",
    "grafana_apps_dashboard_dashboard_v1beta1",
    "grafana_apps_dashboard_dashboard_v2",
    "grafana_apps_dashboard_dashboard_v2beta1",
    "grafana_apps_generic_resource",
    "grafana_apps_notifications_inhibitionrule_v1beta1",
    "grafana_apps_playlist_playlist_v0alpha1",
    "grafana_apps_playlist_playlist_v1",
    "grafana_apps_productactivation_appo11yconfig_v1alpha1",
    "grafana_apps_productactivation_dbo11yconfig_v1alpha1",
    "grafana_apps_productactivation_k8so11yconfig_v1alpha1",
    "grafana_apps_provisioning_connection_v0alpha1",
    "grafana_apps_provisioning_repository_v0alpha1",
    "grafana_apps_rules_alertrule_v0alpha1",
    "grafana_apps_rules_recordingrule_v0alpha1",
    "grafana_apps_secret_keeper_activation_v1beta1",
    "grafana_apps_secret_keeper_v1beta1",
    "grafana_apps_secret_securevalue_v1beta1",
    "grafana_asserts_custom_model_rules",
    "grafana_asserts_log_config",
    "grafana_asserts_notification_alerts_config",
    "grafana_asserts_profile_config",
    "grafana_asserts_prom_rule_file",
    "grafana_asserts_stack",
    "grafana_asserts_suppressed_assertions_config",
    "grafana_asserts_thresholds",
    "grafana_asserts_trace_config",
    "grafana_assistant_mcp_server",
    "grafana_assistant_quickstart",
    "grafana_assistant_rule",
    "grafana_assistant_skill",
    "grafana_cloud_access_policy",
    "grafana_cloud_access_policy_rotating_token",
    "grafana_cloud_access_policy_token",
    "grafana_cloud_integration",
    "grafana_cloud_org_member",
    "grafana_cloud_plugin_installation",
    "grafana_cloud_private_data_source_connect_network",
    "grafana_cloud_private_data_source_connect_network_token",
    "grafana_cloud_provider_aws_account",
    "grafana_cloud_provider_aws_cloudwatch_scrape_job",
    "grafana_cloud_provider_aws_resource_metadata_scrape_job",
    "grafana_cloud_provider_azure_credential",
    "grafana_cloud_stack",
    "grafana_cloud_stack_service_account",
    "grafana_cloud_stack_service_account_rotating_token",
    "grafana_cloud_stack_service_account_token",
    "grafana_connections_metrics_endpoint_scrape_job",
    "grafana_contact_point",
    "grafana_dashboard",
    "grafana_dashboard_permission",
    "grafana_dashboard_permission_item",
    "grafana_dashboard_public",
    "grafana_data_source",
    "grafana_data_source_cache_config",
    "grafana_data_source_config",
    "grafana_data_source_config_lbac_rules",
    "grafana_data_source_permission",
    "grafana_data_source_permission_item",
    "grafana_fleet_management_collector",
    "grafana_fleet_management_pipeline",
    "grafana_folder",
    "grafana_folder_permission",
    "grafana_folder_permission_item",
    "grafana_frontend_o11y_app",
    "grafana_k6_installation",
    "grafana_k6_load_test",
    "grafana_k6_project",
    "grafana_k6_project_allowed_load_zones",
    "grafana_k6_project_limits",
    "grafana_k6_schedule",
    "grafana_library_panel",
    "grafana_machine_learning_alert",
    "grafana_machine_learning_holiday",
    "grafana_machine_learning_job",
    "grafana_machine_learning_outlier_detector",
    "grafana_message_template",
    "grafana_mute_timing",
    "grafana_notification_policy",
    "grafana_oncall_escalation",
    "grafana_oncall_escalation_chain",
    "grafana_oncall_integration",
    "grafana_oncall_on_call_shift",
    "grafana_oncall_outgoing_webhook",
    "grafana_oncall_route",
    "grafana_oncall_schedule",
    "grafana_oncall_user_notification_rule",
    "grafana_organization",
    "grafana_organization_preferences",
    "grafana_playlist",
    "grafana_report",
    "grafana_role",
    "grafana_role_assignment",
    "grafana_role_assignment_item",
    "grafana_rule_group",
    "grafana_scim_config",
    "grafana_service_account",
    "grafana_service_account_permission",
    "grafana_service_account_permission_item",
    "grafana_service_account_rotating_token",
    "grafana_service_account_token",
    "grafana_slo",
    "grafana_sso_settings",
    "grafana_synthetic_monitoring_check",
    "grafana_synthetic_monitoring_check_alerts",
    "grafana_synthetic_monitoring_installation",
    "grafana_synthetic_monitoring_probe",
    "grafana_team",
    "grafana_team_external_group",
    "grafana_user",
)


_SECRET_RESOURCES = {
    "grafana_apps_secret_keeper_activation_v1beta1",
    "grafana_apps_secret_keeper_v1beta1",
    "grafana_apps_secret_securevalue_v1beta1",
    "grafana_cloud_access_policy_rotating_token",
    "grafana_cloud_access_policy_token",
    "grafana_cloud_private_data_source_connect_network_token",
    "grafana_cloud_stack_service_account_rotating_token",
    "grafana_cloud_stack_service_account_token",
    "grafana_service_account_rotating_token",
    "grafana_service_account_token",
}

_IDENTITY_RESOURCES = {
    "grafana_cloud_access_policy",
    "grafana_cloud_org_member",
    "grafana_cloud_stack_service_account",
    "grafana_organization",
    "grafana_organization_preferences",
    "grafana_role",
    "grafana_role_assignment",
    "grafana_role_assignment_item",
    "grafana_scim_config",
    "grafana_service_account",
    "grafana_sso_settings",
    "grafana_team",
    "grafana_team_external_group",
    "grafana_user",
}

_PERMISSION_RESOURCES = {
    "grafana_dashboard_permission",
    "grafana_dashboard_permission_item",
    "grafana_data_source_config_lbac_rules",
    "grafana_data_source_permission",
    "grafana_data_source_permission_item",
    "grafana_folder_permission",
    "grafana_folder_permission_item",
    "grafana_service_account_permission",
    "grafana_service_account_permission_item",
}

_ALERTING_RESOURCES = {
    "grafana_apps_alertenrichment_alertenrichment_v1beta1",
    "grafana_apps_notifications_inhibitionrule_v1beta1",
    "grafana_apps_rules_alertrule_v0alpha1",
    "grafana_apps_rules_recordingrule_v0alpha1",
    "grafana_contact_point",
    "grafana_message_template",
    "grafana_mute_timing",
    "grafana_notification_policy",
    "grafana_rule_group",
    "grafana_slo",
}

_CONTENT_RESOURCES = {
    "grafana_annotation",
    "grafana_apps_dashboard_dashboard_v1beta1",
    "grafana_apps_dashboard_dashboard_v2",
    "grafana_apps_dashboard_dashboard_v2beta1",
    "grafana_apps_generic_resource",
    "grafana_apps_playlist_playlist_v0alpha1",
    "grafana_apps_playlist_playlist_v1",
    "grafana_dashboard",
    "grafana_dashboard_public",
    "grafana_folder",
    "grafana_library_panel",
    "grafana_playlist",
    "grafana_report",
}

_DATA_INTEGRATION_RESOURCES = {
    "grafana_cloud_integration",
    "grafana_cloud_private_data_source_connect_network",
    "grafana_cloud_provider_aws_account",
    "grafana_cloud_provider_aws_cloudwatch_scrape_job",
    "grafana_cloud_provider_aws_resource_metadata_scrape_job",
    "grafana_cloud_provider_azure_credential",
    "grafana_connections_metrics_endpoint_scrape_job",
    "grafana_data_source",
    "grafana_data_source_cache_config",
    "grafana_data_source_config",
    "grafana_fleet_management_collector",
    "grafana_fleet_management_pipeline",
    "grafana_frontend_o11y_app",
}

_ONCALL_RESOURCES = {
    "grafana_oncall_escalation",
    "grafana_oncall_escalation_chain",
    "grafana_oncall_integration",
    "grafana_oncall_on_call_shift",
    "grafana_oncall_outgoing_webhook",
    "grafana_oncall_route",
    "grafana_oncall_schedule",
    "grafana_oncall_user_notification_rule",
}

_SYNTHETIC_RESOURCES = {
    "grafana_synthetic_monitoring_check",
    "grafana_synthetic_monitoring_check_alerts",
    "grafana_synthetic_monitoring_installation",
    "grafana_synthetic_monitoring_probe",
}


@register_rule(*_GRAFANA_RESOURCES)
def _grafana_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = _label(resource_type)
    before = _previous(change)
    after = _desired(change)
    consequence = _delete_consequence(resource_type)
    deleted = _delete(label, action_set, consequence)
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []

    if resource_type in _SECRET_RESOURCES:
        return [_secret_result(label, resource_type, after)]
    if resource_type in _PERMISSION_RESOURCES:
        return [_permission_result(label, before, after)]
    if resource_type in _IDENTITY_RESOURCES:
        return [_identity_result(label, resource_type, after)]
    if resource_type in _ALERTING_RESOURCES:
        return [_alerting_result(label, resource_type, after)]
    if resource_type in _CONTENT_RESOURCES:
        return [_content_result(label, resource_type, after)]
    if resource_type in _DATA_INTEGRATION_RESOURCES:
        return [_data_integration_result(label, resource_type, after)]
    if resource_type in _ONCALL_RESOURCES:
        return [_oncall_result(label, resource_type, after)]
    if resource_type in _SYNTHETIC_RESOURCES:
        return [_synthetic_result(label, resource_type, after)]
    if resource_type.startswith("grafana_apps_provisioning_"):
        return [_git_sync_result(label, resource_type, after)]
    if resource_type.startswith("grafana_assistant_"):
        return [_assistant_result(label, resource_type, after)]
    if resource_type.startswith("grafana_k6_"):
        return [_k6_result(label, resource_type, after)]
    if resource_type.startswith("grafana_machine_learning_"):
        return [_machine_learning_result(label, resource_type, after)]
    if resource_type.startswith("grafana_asserts_"):
        return [_asserts_result(label, resource_type, after)]
    if resource_type.startswith("grafana_cloud_"):
        return [_cloud_platform_result(label, resource_type, after)]
    if resource_type.startswith("grafana_apps_productactivation_"):
        return [_cloud_platform_result(label, resource_type, after)]
    return [
        RuleResult(
            "review",
            f"This Grafana {label} change affects an observability control-plane resource. "
            "Review organization/stack scope, access, credentials in state, data egress, "
            "alerting dependencies, hosted-service cost, compatibility, and rollback.",
        )
    ]


def _delete_consequence(resource_type: str) -> str:
    if resource_type in _SECRET_RESOURCES:
        return "Credential revocation can immediately break agents, CI, APIs, or collectors."
    if resource_type in _PERMISSION_RESOURCES or resource_type in _IDENTITY_RESOURCES:
        return "Access, ownership, SSO/SCIM, or service identity may be removed."
    if resource_type in _ALERTING_RESOURCES or resource_type in _ONCALL_RESOURCES:
        return "Detection, notification, escalation, or responder routing may stop."
    if resource_type in _DATA_INTEGRATION_RESOURCES:
        return "Telemetry ingestion, queries, credentials, or external connectivity may stop."
    return "The managed observability, hosted, or automation capability will be removed."


def _secret_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    if resource_type.startswith("grafana_apps_secret_"):
        weaknesses = [
            "send write-only secret material and retain sensitive metadata or hashes in state"
        ]
    else:
        weaknesses = [
            "persist a token or service-account credential in Terraform plan/state"
        ]
    if _contains(after, "*", "admin"):
        weaknesses.append("grant wildcard or administrative scope")
    if "rotating_token" in resource_type:
        weaknesses.append("change automatic credential rotation and overlap behavior")
    if after.get("seconds_to_live") in {None, 0} and resource_type.endswith("_token"):
        weaknesses.append("create a token without a finite lifetime")
    return RuleResult(
        "dangerous",
        f"This Grafana {label} change can {'; '.join(weaknesses)}. Treat state, saved plans, CI "
        "artifacts, logs, and backups as secret-bearing; review scopes, expiry, rotation overlap, "
        "consumers, revocation order, and recovery.",
    )


def _permission_result(
    label: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _contains(after, "admin", "*", "edit"):
        weaknesses.append("grant administrative, wildcard, or edit access")
    before_permissions = _values(before, "permissions")
    after_permissions = _values(after, "permissions")
    if before_permissions and not after_permissions:
        weaknesses.append("remove the previously managed permission set")
    return RuleResult(
        "dangerous",
        f"This Grafana {label} change replaces or edits an authorization set"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Omitted principals may lose access. Review users, teams, service accounts, roles, "
        "LBAC expressions, inheritance, least privilege, break-glass access, and rollback.",
    )


def _identity_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _contains(after, "admin", "*", "grafanaadmin"):
        weaknesses.append("grant administrative or wildcard access")
    if _any_true(
        after,
        "allow_sign_up",
        "allow_assign_grafana_admin",
        "skip_org_role_sync",
        "ssl_skip_verify",
    ):
        weaknesses.append("allow signup/admin mapping or bypass organization-role synchronization")
    if _any_false(
        after,
        "enabled",
        "enforce_sync",
        "enable_group_sync",
        "enable_user_sync",
        "reject_non_provisioned_users",
    ):
        weaknesses.append("disable an identity or synchronization guardrail")
    if any(
        after.get(key)
        for key in (
            "password",
            "password_wo",
            "bind_password",
            "client_secret",
            "client_key_value",
        )
    ):
        weaknesses.append("persist or rotate an identity credential through Terraform")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Grafana {label} change affects identity, organization membership, RBAC, SSO, "
        "SCIM, service accounts, or team synchronization"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review issuer/domain trust, role mapping, principal lifecycle, least privilege, "
        "credential state exposure, break-glass access, and deprovisioning.",
    )


def _alerting_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _any_true(after, "is_paused", "disable_provenance"):
        weaknesses.append("pause evaluation or allow out-of-band mutation")
    if _any_false(after, "enabled"):
        weaknesses.append("disable alert evaluation or delivery")
    if resource_type in {
        "grafana_mute_timing",
        "grafana_apps_notifications_inhibitionrule_v1beta1",
    }:
        weaknesses.append("suppress alert notifications")
    if resource_type in {"grafana_contact_point", "grafana_notification_policy"}:
        weaknesses.append("redirect alert payloads and responder notifications")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Grafana {label} change affects alert/recording rules, SLOs, routing, contact "
        "points, templates, enrichment, or suppression"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review queries and thresholds, evaluation interval, no-data/error behavior, "
        "recipients, secret fields, grouping, mute windows, provenance, and rollback.",
    )


def _content_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if resource_type == "grafana_dashboard_public":
        weaknesses.append("publish dashboard data outside normal authenticated access")
    if _contains(after, "public", "*", "anonymous"):
        weaknesses.append("broaden content visibility to public, anonymous, or wildcard access")
    if _any_true(after, "disable_deletion", "overwrite"):
        weaknesses.append("change deletion or overwrite ownership semantics")
    if resource_type == "grafana_report":
        weaknesses.append("send rendered dashboard data to configured recipients")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Grafana {label} change affects dashboards, folders, panels, playlists, annotations, "
        "reports, or Kubernetes-style app content"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review embedded queries and links, folder placement, visibility, recipient/data "
        "classification, stable UID, overwrite/delete behavior, and recovery.",
    )


def _data_integration_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _text_contains(after, "http://"):
        weaknesses.append("send telemetry or credentials over plaintext HTTP")
    if _any_true(after, "tls_skip_verify", "skip_tls_verify", "disable_tls") or _text_contains(
        after, '"tlsskipverify":true', '"tls_skip_verify":true'
    ):
        weaknesses.append("disable TLS verification")
    if _contains(after, "*", "0.0.0.0/0", "::/0", "admin"):
        weaknesses.append("use wildcard network, tenant, or administrative scope")
    if any(
        after.get(key)
        for key in (
            "secure_json_data_encoded",
            "basic_auth_password",
            "password",
            "access_key",
            "secret_key",
        )
    ):
        weaknesses.append("persist external service credentials in Terraform state")
    if resource_type.startswith("grafana_cloud_provider_"):
        weaknesses.append("establish a cloud-account telemetry and permission boundary")
    if resource_type in {
        "grafana_data_source",
        "grafana_data_source_config",
        "grafana_cloud_integration",
    }:
        weaknesses.append("change server-side data access or external telemetry egress")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Grafana {label} change affects a data source, collector, pipeline, scrape job, "
        "private network, frontend telemetry, or cloud integration"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review endpoint ownership, TLS/auth, credential state exposure, tenant and metric "
        "scope, query permissions, LBAC, cardinality/cost, data residency, and rollback.",
    )


def _oncall_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _any_false(after, "enabled"):
        weaknesses.append("disable a responder path")
    if _contains(after, "*", "all"):
        weaknesses.append("route a wildcard incident scope")
    if resource_type == "grafana_oncall_outgoing_webhook":
        weaknesses.append("send incident payloads to an external automation endpoint")
        if _text_contains(after, "http://"):
            weaknesses.append("send incident payloads over plaintext HTTP")
        if not any(after.get(key) for key in ("authorization_header", "password", "headers")):
            weaknesses.append("call the webhook without visible request authentication")
    if resource_type in {
        "grafana_oncall_escalation",
        "grafana_oncall_escalation_chain",
        "grafana_oncall_route",
    }:
        weaknesses.append("change escalation or responder routing")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Grafana {label} change affects OnCall ingestion, schedules, escalation, routing, "
        "webhooks, shifts, or user notification"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review trigger scope, responders, time zones, fallbacks, loops, payload secrets, "
        "delivery tests, and rollback.",
    )


def _synthetic_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _text_contains(after, "http://"):
        weaknesses.append("probe a plaintext endpoint")
    if _any_true(after, "skip_tls_verification", "insecure"):
        weaknesses.append("disable probe TLS verification")
    if resource_type == "grafana_synthetic_monitoring_probe":
        weaknesses.append("create private-probe credentials and network reachability")
    if resource_type == "grafana_synthetic_monitoring_installation":
        weaknesses.append("install organization-wide synthetic monitoring components")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Grafana {label} change affects Synthetic Monitoring checks, alerts, installation, "
        "or private probes"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review target authorization, TLS, probe placement, credentials in state, request "
        "payloads, frequency/cost, alert linkage, and rollback.",
    )


def _git_sync_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = ["connect Grafana content to an external Git repository"]
    if _contains(after, "*", "admin"):
        weaknesses.append("grant wildcard or administrative repository scope")
    if _values(after, "token", "password", "private_key", "commit_signing_key"):
        weaknesses.append("send write-only repository credentials through Terraform")
    return RuleResult(
        "dangerous",
        f"This Grafana {label} change can {'; '.join(weaknesses)}. Review repository and branch "
        "ownership, credentials, signature/review policy, sync direction, overwrite/deletion "
        "behavior, path scope, conflict recovery, and rollback.",
    )


def _assistant_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if resource_type == "grafana_assistant_mcp_server":
        weaknesses.append("connect an AI assistant to an MCP tool and data boundary")
        if _contains(after, "auto_approve"):
            weaknesses.append("auto-approve one or more MCP tool calls")
    if _contains(after, "*", "admin"):
        weaknesses.append("grant wildcard or administrative assistant scope")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Grafana {label} change affects assistant rules, skills, quickstarts, or MCP "
        "connectivity"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review instructions and tool authority, data access, prompt-injection boundaries, "
        "credentials, external endpoints, auditability, and rollback.",
    )


def _k6_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if resource_type in {"grafana_k6_load_test", "grafana_k6_schedule"}:
        weaknesses.append("execute or schedule load against configured targets")
    if _contains(after, "*", "all"):
        weaknesses.append("use a wildcard load zone or target scope")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Grafana {label} change affects k6 projects, tests, schedules, load zones, limits, "
        "or installation"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review target authorization, script provenance, secrets, load intensity, allowed "
        "zones, schedule, quotas/cost, abort controls, and rollback.",
    )


def _machine_learning_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _any_false(after, "enabled"):
        weaknesses.append("disable an ML detection or alert")
    if "alert" in resource_type:
        weaknesses.append("change automated anomaly notification")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Grafana {label} change affects ML training, anomaly/outlier detection, holidays, "
        "or alerting"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review query/data scope, training window, sensitivity, seasonality, suppression, "
        "recipients, compute cost, drift, and rollback.",
    )


def _asserts_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if "suppressed" in resource_type:
        weaknesses.append("suppress assertion detections")
    if "notification" in resource_type:
        weaknesses.append("change assertion alert delivery")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Grafana {label} change affects Asserts models, signal sources, thresholds, rules, "
        "profiles, or notifications"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review telemetry scope, rule provenance, thresholds, suppression, recipients, "
        "cardinality/cost, and rollback.",
    )


def _cloud_platform_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if resource_type == "grafana_cloud_stack":
        weaknesses.append("create, replace, or re-region a hosted observability stack")
    if resource_type == "grafana_cloud_plugin_installation":
        weaknesses.append("install executable plugin code into a hosted stack")
        if after.get("version") in {None, "", "latest"}:
            weaknesses.append("track an unpinned latest plugin version")
    if _contains(after, "*", "admin", "public"):
        weaknesses.append("grant wildcard/admin scope or public exposure")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Grafana {label} change affects a hosted stack, plugin, application activation, "
        "or organization capability"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review tenant/region, access policy, plugin provenance, data residency, service "
        "dependencies, quota/cost, migration, and rollback.",
    )
