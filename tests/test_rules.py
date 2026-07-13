from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from readtheplan.plan import analyze_plan_file
from readtheplan.rules import aws as aws_rules
from readtheplan.rules._shared import _CROSS_CUTTING, _RULE_REGISTRY

_EXPECTED_RULE_FUNCTIONS = {
    "aws_db_instance": "_rds_candidates",
    "aws_rds_cluster": "_rds_candidates",
    "aws_s3_bucket": "_s3_candidates",
    "aws_s3_bucket_acl": "_s3_candidates",
    "aws_s3_bucket_policy": "_s3_candidates",
    "aws_kms_key": "_kms_candidates",
    "aws_iam_role": "_iam_candidates",
    "aws_iam_policy": "_iam_candidates",
    "aws_iam_role_policy": "_iam_candidates",
    "aws_route53_zone": "_route53_candidates",
    "aws_eks_node_group": "_eks_node_group_candidates",
    "aws_ecs_service": "_ecs_service_candidates",
    "aws_lb": "_lb_candidates",
    "aws_elb": "_lb_candidates",
    "aws_alb": "_lb_candidates",
    "aws_lb_listener": "_lb_candidates",
    "aws_lb_listener_rule": "_lb_candidates",
    "aws_lb_target_group": "_lb_candidates",
    "aws_lb_target_group_attachment": "_lb_candidates",
    "aws_lambda_function": "_lambda_candidates",
    "aws_lambda_alias": "_lambda_candidates",
    "aws_lambda_event_source_mapping": "_lambda_candidates",
    "aws_security_group": "_security_group_candidates",
    "aws_security_group_rule": "_security_group_candidates",
    "aws_vpc_security_group_ingress_rule": "_security_group_candidates",
    "aws_vpc_security_group_egress_rule": "_security_group_candidates",
    "google_compute_instance": "_gcp_compute_instance_candidates",
    "google_container_cluster": "_gcp_container_cluster_candidates",
    "google_sql_database_instance": "_gcp_sql_database_instance_candidates",
    "google_storage_bucket": "_gcp_storage_bucket_candidates",
    "google_compute_firewall": "_gcp_compute_firewall_candidates",
    "azurerm_virtual_machine": "_azurerm_virtual_machine_candidates",
    "azurerm_kubernetes_cluster": "_azurerm_kubernetes_cluster_candidates",
    "azurerm_storage_account": "_azurerm_storage_account_candidates",
    "azurerm_role_assignment": "_azurerm_role_assignment_candidates",
    "azurerm_network_security_group": "_azurerm_network_security_candidates",
    "azurerm_network_security_rule": "_azurerm_network_security_candidates",
    "cloudflare_access_application": "_cloudflare_zero_trust_policy_candidates",
    "cloudflare_access_policy": "_cloudflare_zero_trust_policy_candidates",
    "cloudflare_account_member": "_cloudflare_identity_candidates",
    "cloudflare_api_shield_mtls_certificate": "_cloudflare_tls_candidates",
    "cloudflare_api_token": "_cloudflare_identity_candidates",
    "cloudflare_authenticated_origin_pulls_certificate": "_cloudflare_tls_candidates",
    "cloudflare_custom_ssl": "_cloudflare_tls_candidates",
    "cloudflare_d1_database": "_cloudflare_data_candidates",
    "cloudflare_dns_record": "_cloudflare_dns_candidates",
    "cloudflare_healthcheck": "_cloudflare_traffic_candidates",
    "cloudflare_hostname_tls_setting": "_cloudflare_tls_candidates",
    "cloudflare_list": "_cloudflare_edge_policy_candidates",
    "cloudflare_list_item": "_cloudflare_edge_policy_candidates",
    "cloudflare_load_balancer": "_cloudflare_traffic_candidates",
    "cloudflare_load_balancer_pool": "_cloudflare_traffic_candidates",
    "cloudflare_logpush_job": "_cloudflare_logpush_candidates",
    "cloudflare_origin_ca_certificate": "_cloudflare_tls_candidates",
    "cloudflare_page_rule": "_cloudflare_edge_policy_candidates",
    "cloudflare_pages_domain": "_cloudflare_pages_candidates",
    "cloudflare_pages_project": "_cloudflare_pages_candidates",
    "cloudflare_queue": "_cloudflare_data_candidates",
    "cloudflare_r2_bucket": "_cloudflare_data_candidates",
    "cloudflare_record": "_cloudflare_dns_candidates",
    "cloudflare_ruleset": "_cloudflare_edge_policy_candidates",
    "cloudflare_teams_rules": "_cloudflare_zero_trust_policy_candidates",
    "cloudflare_tunnel": "_cloudflare_tunnel_candidates",
    "cloudflare_tunnel_config": "_cloudflare_tunnel_candidates",
    "cloudflare_worker_route": "_cloudflare_worker_route_candidates",
    "cloudflare_worker_script": "_cloudflare_worker_script_candidates",
    "cloudflare_workers_kv": "_cloudflare_data_candidates",
    "cloudflare_workers_kv_namespace": "_cloudflare_data_candidates",
    "cloudflare_workers_route": "_cloudflare_worker_route_candidates",
    "cloudflare_workers_script": "_cloudflare_worker_script_candidates",
    "cloudflare_zero_trust_access_application": "_cloudflare_zero_trust_policy_candidates",
    "cloudflare_zero_trust_access_group": "_cloudflare_zero_trust_policy_candidates",
    "cloudflare_zero_trust_access_policy": "_cloudflare_zero_trust_policy_candidates",
    "cloudflare_zero_trust_gateway_policy": "_cloudflare_zero_trust_policy_candidates",
    "cloudflare_zero_trust_tunnel_cloudflared": "_cloudflare_tunnel_candidates",
    "cloudflare_zero_trust_tunnel_cloudflared_config": "_cloudflare_tunnel_candidates",
    "cloudflare_zero_trust_tunnel_cloudflared_route": "_cloudflare_tunnel_candidates",
    "cloudflare_zone": "_cloudflare_zone_candidates",
    "cloudflare_zone_dnssec": "_cloudflare_dns_candidates",
    "cloudflare_zone_setting": "_cloudflare_zone_setting_candidates",
    "cloudflare_zone_settings_override": "_cloudflare_zone_setting_candidates",
    "datadog_action_connection": "_datadog_integration_candidates",
    "datadog_agentless_scanning_aws_scan_options": "_datadog_security_candidates",
    "datadog_agentless_scanning_azure_scan_options": "_datadog_security_candidates",
    "datadog_agentless_scanning_gcp_scan_options": "_datadog_security_candidates",
    "datadog_api_key": "_datadog_credential_candidates",
    "datadog_apm_retention_filter": "_datadog_logs_data_candidates",
    "datadog_apm_retention_filter_order": "_datadog_logs_data_candidates",
    "datadog_app_builder_app": "_datadog_platform_candidates",
    "datadog_app_key_registration": "_datadog_credential_candidates",
    "datadog_application_key": "_datadog_credential_candidates",
    "datadog_appsec_waf_custom_rule": "_datadog_security_candidates",
    "datadog_appsec_waf_exclusion_filter": "_datadog_security_candidates",
    "datadog_authn_mapping": "_datadog_identity_candidates",
    "datadog_aws_cur_config": "_datadog_logs_data_candidates",
    "datadog_azure_uc_config": "_datadog_logs_data_candidates",
    "datadog_child_organization": "_datadog_identity_candidates",
    "datadog_cloud_configuration_rule": "_datadog_security_candidates",
    "datadog_cloud_inventory_sync_config": "_datadog_security_candidates",
    "datadog_cloud_workload_security_agent_rule": "_datadog_security_candidates",
    "datadog_compliance_custom_framework": "_datadog_security_candidates",
    "datadog_compliance_resource_evaluation_filter": "_datadog_security_candidates",
    "datadog_cost_budget": "_datadog_logs_data_candidates",
    "datadog_csm_threats_agent_rule": "_datadog_security_candidates",
    "datadog_csm_threats_policy": "_datadog_security_candidates",
    "datadog_custom_allocation_rule": "_datadog_logs_data_candidates",
    "datadog_custom_allocation_rules": "_datadog_logs_data_candidates",
    "datadog_dashboard": "_datadog_observability_candidates",
    "datadog_dashboard_json": "_datadog_observability_candidates",
    "datadog_dashboard_list": "_datadog_observability_candidates",
    "datadog_dashboard_v2": "_datadog_observability_candidates",
    "datadog_dataset": "_datadog_platform_candidates",
    "datadog_datastore": "_datadog_platform_candidates",
    "datadog_datastore_item": "_datadog_platform_candidates",
    "datadog_deployment_gate": "_datadog_incident_automation_candidates",
    "datadog_domain_allowlist": "_datadog_identity_candidates",
    "datadog_downtime": "_datadog_observability_candidates",
    "datadog_downtime_schedule": "_datadog_observability_candidates",
    "datadog_gcp_uc_config": "_datadog_logs_data_candidates",
    "datadog_incident_notification_rule": "_datadog_incident_automation_candidates",
    "datadog_incident_notification_template": "_datadog_incident_automation_candidates",
    "datadog_incident_type": "_datadog_incident_automation_candidates",
    "datadog_integration_aws_account": "_datadog_integration_candidates",
    "datadog_integration_aws_account_ccm_config": "_datadog_integration_candidates",
    "datadog_integration_aws_event_bridge": "_datadog_integration_candidates",
    "datadog_integration_aws_external_id": "_datadog_integration_candidates",
    "datadog_integration_azure": "_datadog_integration_candidates",
    "datadog_integration_cloudflare_account": "_datadog_integration_candidates",
    "datadog_integration_confluent_account": "_datadog_integration_candidates",
    "datadog_integration_confluent_resource": "_datadog_integration_candidates",
    "datadog_integration_fastly_account": "_datadog_integration_candidates",
    "datadog_integration_fastly_service": "_datadog_integration_candidates",
    "datadog_integration_gcp": "_datadog_integration_candidates",
    "datadog_integration_gcp_sts": "_datadog_integration_candidates",
    "datadog_integration_ms_teams_tenant_based_handle": "_datadog_integration_candidates",
    "datadog_integration_ms_teams_workflows_webhook_handle": "_datadog_integration_candidates",
    "datadog_integration_opsgenie_service_object": "_datadog_integration_candidates",
    "datadog_integration_pagerduty": "_datadog_integration_candidates",
    "datadog_integration_pagerduty_service_object": "_datadog_integration_candidates",
    "datadog_integration_slack_channel": "_datadog_integration_candidates",
    "datadog_ip_allowlist": "_datadog_identity_candidates",
    "datadog_logs_archive": "_datadog_logs_data_candidates",
    "datadog_logs_archive_order": "_datadog_logs_data_candidates",
    "datadog_logs_custom_destination": "_datadog_logs_data_candidates",
    "datadog_logs_custom_pipeline": "_datadog_logs_data_candidates",
    "datadog_logs_index": "_datadog_logs_data_candidates",
    "datadog_logs_index_order": "_datadog_logs_data_candidates",
    "datadog_logs_integration_pipeline": "_datadog_logs_data_candidates",
    "datadog_logs_metric": "_datadog_logs_data_candidates",
    "datadog_logs_pipeline_order": "_datadog_logs_data_candidates",
    "datadog_logs_restriction_query": "_datadog_logs_data_candidates",
    "datadog_metric_metadata": "_datadog_observability_candidates",
    "datadog_metric_tag_configuration": "_datadog_observability_candidates",
    "datadog_monitor": "_datadog_observability_candidates",
    "datadog_monitor_config_policy": "_datadog_observability_candidates",
    "datadog_monitor_json": "_datadog_observability_candidates",
    "datadog_monitor_notification_rule": "_datadog_incident_automation_candidates",
    "datadog_observability_pipeline": "_datadog_logs_data_candidates",
    "datadog_on_call_escalation_policy": "_datadog_incident_automation_candidates",
    "datadog_on_call_schedule": "_datadog_incident_automation_candidates",
    "datadog_on_call_team_routing_rules": "_datadog_incident_automation_candidates",
    "datadog_on_call_user_notification_channel": "_datadog_incident_automation_candidates",
    "datadog_on_call_user_notification_rule": "_datadog_incident_automation_candidates",
    "datadog_openapi_api": "_datadog_platform_candidates",
    "datadog_org_connection": "_datadog_identity_candidates",
    "datadog_org_group": "_datadog_identity_candidates",
    "datadog_org_group_membership": "_datadog_identity_candidates",
    "datadog_org_group_policy": "_datadog_identity_candidates",
    "datadog_org_group_policy_override": "_datadog_identity_candidates",
    "datadog_organization_settings": "_datadog_identity_candidates",
    "datadog_powerpack": "_datadog_observability_candidates",
    "datadog_powerpack_v2": "_datadog_observability_candidates",
    "datadog_reference_table": "_datadog_logs_data_candidates",
    "datadog_restriction_policy": "_datadog_identity_candidates",
    "datadog_role": "_datadog_identity_candidates",
    "datadog_rum_application": "_datadog_observability_candidates",
    "datadog_rum_metric": "_datadog_observability_candidates",
    "datadog_rum_retention_filter": "_datadog_logs_data_candidates",
    "datadog_rum_retention_filters_order": "_datadog_logs_data_candidates",
    "datadog_secure_embed_dashboard": "_datadog_observability_candidates",
    "datadog_security_findings_due_date_rule": "_datadog_security_candidates",
    "datadog_security_findings_due_date_rules_order": "_datadog_security_candidates",
    "datadog_security_findings_mute_rule": "_datadog_security_candidates",
    "datadog_security_findings_mute_rules_order": "_datadog_security_candidates",
    "datadog_security_findings_ticket_creation_rule": "_datadog_security_candidates",
    "datadog_security_findings_ticket_creation_rules_order": "_datadog_security_candidates",
    "datadog_security_monitoring_critical_asset": "_datadog_security_candidates",
    "datadog_security_monitoring_default_rule": "_datadog_security_candidates",
    "datadog_security_monitoring_filter": "_datadog_security_candidates",
    "datadog_security_monitoring_rule": "_datadog_security_candidates",
    "datadog_security_monitoring_rule_json": "_datadog_security_candidates",
    "datadog_security_monitoring_suppression": "_datadog_security_candidates",
    "datadog_security_notification_rule": "_datadog_incident_automation_candidates",
    "datadog_sensitive_data_scanner_group": "_datadog_security_candidates",
    "datadog_sensitive_data_scanner_group_order": "_datadog_security_candidates",
    "datadog_sensitive_data_scanner_rule": "_datadog_security_candidates",
    "datadog_service_access_token": "_datadog_credential_candidates",
    "datadog_service_account": "_datadog_identity_candidates",
    "datadog_service_account_application_key": "_datadog_credential_candidates",
    "datadog_service_definition_yaml": "_datadog_platform_candidates",
    "datadog_service_level_objective": "_datadog_observability_candidates",
    "datadog_slo_correction": "_datadog_observability_candidates",
    "datadog_software_catalog": "_datadog_platform_candidates",
    "datadog_spans_metric": "_datadog_observability_candidates",
    "datadog_synthetics_concurrency_cap": "_datadog_observability_candidates",
    "datadog_synthetics_global_variable": "_datadog_credential_candidates",
    "datadog_synthetics_private_location": "_datadog_observability_candidates",
    "datadog_synthetics_suite": "_datadog_observability_candidates",
    "datadog_synthetics_test": "_datadog_observability_candidates",
    "datadog_tag_indexing_rule": "_datadog_observability_candidates",
    "datadog_tag_indexing_rule_exemption": "_datadog_observability_candidates",
    "datadog_tag_indexing_rule_order": "_datadog_observability_candidates",
    "datadog_tag_pipeline_ruleset": "_datadog_logs_data_candidates",
    "datadog_tag_pipeline_rulesets": "_datadog_logs_data_candidates",
    "datadog_team": "_datadog_identity_candidates",
    "datadog_team_connection": "_datadog_integration_candidates",
    "datadog_team_hierarchy_links": "_datadog_identity_candidates",
    "datadog_team_link": "_datadog_identity_candidates",
    "datadog_team_membership": "_datadog_identity_candidates",
    "datadog_team_notification_rule": "_datadog_incident_automation_candidates",
    "datadog_team_permission_setting": "_datadog_identity_candidates",
    "datadog_team_sync": "_datadog_identity_candidates",
    "datadog_user": "_datadog_identity_candidates",
    "datadog_user_role": "_datadog_identity_candidates",
    "datadog_webhook": "_datadog_integration_candidates",
    "datadog_webhook_custom_variable": "_datadog_credential_candidates",
    "datadog_workflow_automation": "_datadog_incident_automation_candidates",
    "grafana_annotation": "_grafana_candidates",
    "grafana_apps_alertenrichment_alertenrichment_v1beta1": "_grafana_candidates",
    "grafana_apps_dashboard_dashboard_v1beta1": "_grafana_candidates",
    "grafana_apps_dashboard_dashboard_v2": "_grafana_candidates",
    "grafana_apps_dashboard_dashboard_v2beta1": "_grafana_candidates",
    "grafana_apps_generic_resource": "_grafana_candidates",
    "grafana_apps_notifications_inhibitionrule_v1beta1": "_grafana_candidates",
    "grafana_apps_playlist_playlist_v0alpha1": "_grafana_candidates",
    "grafana_apps_playlist_playlist_v1": "_grafana_candidates",
    "grafana_apps_productactivation_appo11yconfig_v1alpha1": "_grafana_candidates",
    "grafana_apps_productactivation_dbo11yconfig_v1alpha1": "_grafana_candidates",
    "grafana_apps_productactivation_k8so11yconfig_v1alpha1": "_grafana_candidates",
    "grafana_apps_provisioning_connection_v0alpha1": "_grafana_candidates",
    "grafana_apps_provisioning_repository_v0alpha1": "_grafana_candidates",
    "grafana_apps_rules_alertrule_v0alpha1": "_grafana_candidates",
    "grafana_apps_rules_recordingrule_v0alpha1": "_grafana_candidates",
    "grafana_apps_secret_keeper_activation_v1beta1": "_grafana_candidates",
    "grafana_apps_secret_keeper_v1beta1": "_grafana_candidates",
    "grafana_apps_secret_securevalue_v1beta1": "_grafana_candidates",
    "grafana_asserts_custom_model_rules": "_grafana_candidates",
    "grafana_asserts_log_config": "_grafana_candidates",
    "grafana_asserts_notification_alerts_config": "_grafana_candidates",
    "grafana_asserts_profile_config": "_grafana_candidates",
    "grafana_asserts_prom_rule_file": "_grafana_candidates",
    "grafana_asserts_stack": "_grafana_candidates",
    "grafana_asserts_suppressed_assertions_config": "_grafana_candidates",
    "grafana_asserts_thresholds": "_grafana_candidates",
    "grafana_asserts_trace_config": "_grafana_candidates",
    "grafana_assistant_mcp_server": "_grafana_candidates",
    "grafana_assistant_quickstart": "_grafana_candidates",
    "grafana_assistant_rule": "_grafana_candidates",
    "grafana_assistant_skill": "_grafana_candidates",
    "grafana_cloud_access_policy": "_grafana_candidates",
    "grafana_cloud_access_policy_rotating_token": "_grafana_candidates",
    "grafana_cloud_access_policy_token": "_grafana_candidates",
    "grafana_cloud_integration": "_grafana_candidates",
    "grafana_cloud_org_member": "_grafana_candidates",
    "grafana_cloud_plugin_installation": "_grafana_candidates",
    "grafana_cloud_private_data_source_connect_network": "_grafana_candidates",
    "grafana_cloud_private_data_source_connect_network_token": "_grafana_candidates",
    "grafana_cloud_provider_aws_account": "_grafana_candidates",
    "grafana_cloud_provider_aws_cloudwatch_scrape_job": "_grafana_candidates",
    "grafana_cloud_provider_aws_resource_metadata_scrape_job": "_grafana_candidates",
    "grafana_cloud_provider_azure_credential": "_grafana_candidates",
    "grafana_cloud_stack": "_grafana_candidates",
    "grafana_cloud_stack_service_account": "_grafana_candidates",
    "grafana_cloud_stack_service_account_rotating_token": "_grafana_candidates",
    "grafana_cloud_stack_service_account_token": "_grafana_candidates",
    "grafana_connections_metrics_endpoint_scrape_job": "_grafana_candidates",
    "grafana_contact_point": "_grafana_candidates",
    "grafana_dashboard": "_grafana_candidates",
    "grafana_dashboard_permission": "_grafana_candidates",
    "grafana_dashboard_permission_item": "_grafana_candidates",
    "grafana_dashboard_public": "_grafana_candidates",
    "grafana_data_source": "_grafana_candidates",
    "grafana_data_source_cache_config": "_grafana_candidates",
    "grafana_data_source_config": "_grafana_candidates",
    "grafana_data_source_config_lbac_rules": "_grafana_candidates",
    "grafana_data_source_permission": "_grafana_candidates",
    "grafana_data_source_permission_item": "_grafana_candidates",
    "grafana_fleet_management_collector": "_grafana_candidates",
    "grafana_fleet_management_pipeline": "_grafana_candidates",
    "grafana_folder": "_grafana_candidates",
    "grafana_folder_permission": "_grafana_candidates",
    "grafana_folder_permission_item": "_grafana_candidates",
    "grafana_frontend_o11y_app": "_grafana_candidates",
    "grafana_k6_installation": "_grafana_candidates",
    "grafana_k6_load_test": "_grafana_candidates",
    "grafana_k6_project": "_grafana_candidates",
    "grafana_k6_project_allowed_load_zones": "_grafana_candidates",
    "grafana_k6_project_limits": "_grafana_candidates",
    "grafana_k6_schedule": "_grafana_candidates",
    "grafana_library_panel": "_grafana_candidates",
    "grafana_machine_learning_alert": "_grafana_candidates",
    "grafana_machine_learning_holiday": "_grafana_candidates",
    "grafana_machine_learning_job": "_grafana_candidates",
    "grafana_machine_learning_outlier_detector": "_grafana_candidates",
    "grafana_message_template": "_grafana_candidates",
    "grafana_mute_timing": "_grafana_candidates",
    "grafana_notification_policy": "_grafana_candidates",
    "grafana_oncall_escalation": "_grafana_candidates",
    "grafana_oncall_escalation_chain": "_grafana_candidates",
    "grafana_oncall_integration": "_grafana_candidates",
    "grafana_oncall_on_call_shift": "_grafana_candidates",
    "grafana_oncall_outgoing_webhook": "_grafana_candidates",
    "grafana_oncall_route": "_grafana_candidates",
    "grafana_oncall_schedule": "_grafana_candidates",
    "grafana_oncall_user_notification_rule": "_grafana_candidates",
    "grafana_organization": "_grafana_candidates",
    "grafana_organization_preferences": "_grafana_candidates",
    "grafana_playlist": "_grafana_candidates",
    "grafana_report": "_grafana_candidates",
    "grafana_role": "_grafana_candidates",
    "grafana_role_assignment": "_grafana_candidates",
    "grafana_role_assignment_item": "_grafana_candidates",
    "grafana_rule_group": "_grafana_candidates",
    "grafana_scim_config": "_grafana_candidates",
    "grafana_service_account": "_grafana_candidates",
    "grafana_service_account_permission": "_grafana_candidates",
    "grafana_service_account_permission_item": "_grafana_candidates",
    "grafana_service_account_rotating_token": "_grafana_candidates",
    "grafana_service_account_token": "_grafana_candidates",
    "grafana_slo": "_grafana_candidates",
    "grafana_sso_settings": "_grafana_candidates",
    "grafana_synthetic_monitoring_check": "_grafana_candidates",
    "grafana_synthetic_monitoring_check_alerts": "_grafana_candidates",
    "grafana_synthetic_monitoring_installation": "_grafana_candidates",
    "grafana_synthetic_monitoring_probe": "_grafana_candidates",
    "grafana_team": "_grafana_candidates",
    "grafana_team_external_group": "_grafana_candidates",
    "grafana_user": "_grafana_candidates",
    "github_repository": "_github_repository_candidates",
    "github_branch": "_github_repository_routing_candidates",
    "github_branch_default": "_github_repository_routing_candidates",
    "github_repository_pages": "_github_repository_routing_candidates",
    "github_branch_protection": "_github_governance_candidates",
    "github_branch_protection_v3": "_github_governance_candidates",
    "github_repository_ruleset": "_github_governance_candidates",
    "github_organization_ruleset": "_github_governance_candidates",
    "github_membership": "_github_identity_candidates",
    "github_emu_group_mapping": "_github_identity_candidates",
    "github_team": "_github_identity_candidates",
    "github_team_members": "_github_identity_candidates",
    "github_team_membership": "_github_identity_candidates",
    "github_team_repository": "_github_identity_candidates",
    "github_team_settings": "_github_identity_candidates",
    "github_team_sync_group_mapping": "_github_identity_candidates",
    "github_repository_collaborator": "_github_identity_candidates",
    "github_repository_collaborators": "_github_identity_candidates",
    "github_organization_security_manager": "_github_identity_candidates",
    "github_organization_custom_role": "_github_identity_candidates",
    "github_organization_repository_role": "_github_identity_candidates",
    "github_organization_role": "_github_identity_candidates",
    "github_organization_role_team": "_github_identity_candidates",
    "github_organization_role_team_assignment": "_github_identity_candidates",
    "github_organization_role_user": "_github_identity_candidates",
    "github_user_invitation_accepter": "_github_identity_candidates",
    "github_organization_settings": "_github_organization_settings_candidates",
    "github_enterprise_organization": "_github_organization_settings_candidates",
    "github_enterprise_ip_allow_list_entry": "_github_enterprise_network_candidates",
    "github_organization_block": "_github_organization_block_candidates",
    "github_organization_custom_properties": "_github_custom_property_candidates",
    "github_repository_custom_property": "_github_custom_property_candidates",
    "github_release": "_github_release_candidates",
    "github_issue": "_github_collaboration_candidates",
    "github_issue_label": "_github_collaboration_candidates",
    "github_issue_labels": "_github_collaboration_candidates",
    "github_organization_project": "_github_collaboration_candidates",
    "github_project_card": "_github_collaboration_candidates",
    "github_project_column": "_github_collaboration_candidates",
    "github_repository_autolink_reference": "_github_collaboration_candidates",
    "github_repository_milestone": "_github_collaboration_candidates",
    "github_repository_project": "_github_collaboration_candidates",
    "github_repository_pull_request": "_github_collaboration_candidates",
    "github_repository_topics": "_github_collaboration_candidates",
    "github_actions_repository_permissions": "_github_actions_policy_candidates",
    "github_actions_organization_permissions": "_github_actions_policy_candidates",
    "github_enterprise_actions_permissions": "_github_actions_policy_candidates",
    "github_actions_repository_access_level": "_github_actions_policy_candidates",
    "github_workflow_repository_permissions": "_github_actions_policy_candidates",
    "github_actions_organization_workflow_permissions": "_github_workflow_token_candidates",
    "github_enterprise_actions_workflow_permissions": "_github_workflow_token_candidates",
    "github_actions_secret": "_github_secret_candidates",
    "github_actions_environment_secret": "_github_secret_candidates",
    "github_actions_organization_secret": "_github_secret_candidates",
    "github_actions_organization_secret_repositories": "_github_secret_candidates",
    "github_actions_organization_secret_repository": "_github_secret_candidates",
    "github_codespaces_secret": "_github_secret_candidates",
    "github_codespaces_organization_secret": "_github_secret_candidates",
    "github_codespaces_organization_secret_repositories": "_github_secret_candidates",
    "github_codespaces_user_secret": "_github_secret_candidates",
    "github_dependabot_secret": "_github_secret_candidates",
    "github_dependabot_organization_secret": "_github_secret_candidates",
    "github_dependabot_organization_secret_repositories": "_github_secret_candidates",
    "github_dependabot_organization_secret_repository": "_github_secret_candidates",
    "github_actions_variable": "_github_actions_variable_candidates",
    "github_actions_environment_variable": "_github_actions_variable_candidates",
    "github_actions_organization_variable": "_github_actions_variable_candidates",
    "github_actions_organization_variable_repositories": "_github_actions_variable_candidates",
    "github_actions_organization_variable_repository": "_github_actions_variable_candidates",
    "github_repository_environment": "_github_environment_candidates",
    "github_repository_deployment_branch_policy": "_github_environment_candidates",
    "github_repository_environment_deployment_policy": "_github_environment_candidates",
    "github_repository_deploy_key": "_github_key_candidates",
    "github_user_ssh_key": "_github_key_candidates",
    "github_user_gpg_key": "_github_key_candidates",
    "github_repository_webhook": "_github_webhook_candidates",
    "github_organization_webhook": "_github_webhook_candidates",
    "github_actions_runner_group": "_github_runner_candidates",
    "github_enterprise_actions_runner_group": "_github_runner_candidates",
    "github_actions_hosted_runner": "_github_runner_candidates",
    "github_actions_repository_oidc_subject_claim_customization_template": (
        "_github_oidc_candidates"
    ),
    "github_actions_organization_oidc_subject_claim_customization_template": (
        "_github_oidc_candidates"
    ),
    "github_app_installation_repository": "_github_app_installation_candidates",
    "github_app_installation_repositories": "_github_app_installation_candidates",
    "github_repository_file": "_github_repository_file_candidates",
    "github_repository_vulnerability_alerts": "_github_security_feature_candidates",
    "github_repository_dependabot_security_updates": "_github_security_feature_candidates",
    "github_enterprise_security_analysis_settings": "_github_security_feature_candidates",
    "gitlab_application": "_gitlab_instance_candidates",
    "gitlab_application_appearance": "_gitlab_instance_candidates",
    "gitlab_application_settings": "_gitlab_instance_candidates",
    "gitlab_branch": "_gitlab_protection_candidates",
    "gitlab_branch_protection": "_gitlab_protection_candidates",
    "gitlab_cluster_agent": "_gitlab_runner_cluster_candidates",
    "gitlab_cluster_agent_token": "_gitlab_credential_candidates",
    "gitlab_compliance_framework": "_gitlab_security_compliance_candidates",
    "gitlab_deploy_key": "_gitlab_credential_candidates",
    "gitlab_deploy_key_enable": "_gitlab_credential_candidates",
    "gitlab_global_level_notifications": "_gitlab_collaboration_candidates",
    "gitlab_group": "_gitlab_lifecycle_candidates",
    "gitlab_group_access_token": "_gitlab_credential_candidates",
    "gitlab_group_badge": "_gitlab_collaboration_candidates",
    "gitlab_group_branch_protection": "_gitlab_protection_candidates",
    "gitlab_group_cluster": "_gitlab_runner_cluster_candidates",
    "gitlab_group_custom_attribute": "_gitlab_collaboration_candidates",
    "gitlab_group_dependency_proxy": "_gitlab_mirror_delivery_candidates",
    "gitlab_group_deploy_token": "_gitlab_credential_candidates",
    "gitlab_group_epic_board": "_gitlab_collaboration_candidates",
    "gitlab_group_hook": "_gitlab_hook_integration_candidates",
    "gitlab_group_integration_harbor": "_gitlab_hook_integration_candidates",
    "gitlab_group_integration_mattermost": "_gitlab_hook_integration_candidates",
    "gitlab_group_integration_microsoft_teams": "_gitlab_hook_integration_candidates",
    "gitlab_group_issue_board": "_gitlab_collaboration_candidates",
    "gitlab_group_label": "_gitlab_collaboration_candidates",
    "gitlab_group_ldap_link": "_gitlab_identity_candidates",
    "gitlab_group_level_mr_approvals": "_gitlab_protection_candidates",
    "gitlab_group_membership": "_gitlab_identity_candidates",
    "gitlab_group_project_file_template": "_gitlab_ci_automation_candidates",
    "gitlab_group_protected_environment": "_gitlab_protection_candidates",
    "gitlab_group_saml_link": "_gitlab_identity_candidates",
    "gitlab_group_saved_reply": "_gitlab_collaboration_candidates",
    "gitlab_group_security_policy_attachment": "_gitlab_security_compliance_candidates",
    "gitlab_group_service_account": "_gitlab_identity_candidates",
    "gitlab_group_service_account_access_token": "_gitlab_credential_candidates",
    "gitlab_group_share_group": "_gitlab_identity_candidates",
    "gitlab_group_variable": "_gitlab_credential_candidates",
    "gitlab_instance_cluster": "_gitlab_runner_cluster_candidates",
    "gitlab_instance_service_account": "_gitlab_identity_candidates",
    "gitlab_instance_variable": "_gitlab_credential_candidates",
    "gitlab_integration_slack": "_gitlab_hook_integration_candidates",
    "gitlab_member_role": "_gitlab_identity_candidates",
    "gitlab_pages_domain": "_gitlab_mirror_delivery_candidates",
    "gitlab_personal_access_token": "_gitlab_credential_candidates",
    "gitlab_pipeline_schedule": "_gitlab_ci_automation_candidates",
    "gitlab_pipeline_schedule_variable": "_gitlab_credential_candidates",
    "gitlab_pipeline_trigger": "_gitlab_ci_automation_candidates",
    "gitlab_project": "_gitlab_lifecycle_candidates",
    "gitlab_project_access_token": "_gitlab_credential_candidates",
    "gitlab_project_approval_rule": "_gitlab_protection_candidates",
    "gitlab_project_badge": "_gitlab_collaboration_candidates",
    "gitlab_project_cicd_catalog": "_gitlab_ci_automation_candidates",
    "gitlab_project_cluster": "_gitlab_runner_cluster_candidates",
    "gitlab_project_compliance_frameworks": "_gitlab_security_compliance_candidates",
    "gitlab_project_container_repository_protection": "_gitlab_supply_chain_candidates",
    "gitlab_project_container_tag_protection": "_gitlab_supply_chain_candidates",
    "gitlab_project_custom_attribute": "_gitlab_collaboration_candidates",
    "gitlab_project_deploy_token": "_gitlab_credential_candidates",
    "gitlab_project_environment": "_gitlab_mirror_delivery_candidates",
    "gitlab_project_error_tracking_client_key": "_gitlab_credential_candidates",
    "gitlab_project_error_tracking_settings": "_gitlab_hook_integration_candidates",
    "gitlab_project_external_status_check": "_gitlab_protection_candidates",
    "gitlab_project_freeze_period": "_gitlab_protection_candidates",
    "gitlab_project_hook": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_custom_issue_tracker": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_datadog": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_emails_on_push": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_external_wiki": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_github": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_google_chat": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_harbor": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_jenkins": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_jira": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_matrix": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_mattermost": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_microsoft_teams": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_pipelines_email": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_redmine": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_telegram": "_gitlab_hook_integration_candidates",
    "gitlab_project_integration_youtrack": "_gitlab_hook_integration_candidates",
    "gitlab_project_issue": "_gitlab_collaboration_candidates",
    "gitlab_project_issue_board": "_gitlab_collaboration_candidates",
    "gitlab_project_issue_link": "_gitlab_collaboration_candidates",
    "gitlab_project_job_token_scope": "_gitlab_ci_automation_candidates",
    "gitlab_project_job_token_scopes": "_gitlab_ci_automation_candidates",
    "gitlab_project_label": "_gitlab_collaboration_candidates",
    "gitlab_project_level_mr_approvals": "_gitlab_protection_candidates",
    "gitlab_project_level_notifications": "_gitlab_collaboration_candidates",
    "gitlab_project_membership": "_gitlab_identity_candidates",
    "gitlab_project_merge_request_note": "_gitlab_collaboration_candidates",
    "gitlab_project_milestone": "_gitlab_collaboration_candidates",
    "gitlab_project_package_dependency_proxy": "_gitlab_mirror_delivery_candidates",
    "gitlab_project_package_protection_rule": "_gitlab_supply_chain_candidates",
    "gitlab_project_pages_settings": "_gitlab_mirror_delivery_candidates",
    "gitlab_project_protected_environment": "_gitlab_protection_candidates",
    "gitlab_project_pull_mirror": "_gitlab_mirror_delivery_candidates",
    "gitlab_project_push_mirror": "_gitlab_mirror_delivery_candidates",
    "gitlab_project_push_rules": "_gitlab_protection_candidates",
    "gitlab_project_runner_enablement": "_gitlab_runner_cluster_candidates",
    "gitlab_project_saved_reply": "_gitlab_collaboration_candidates",
    "gitlab_project_secret_detection_validity_checks": "_gitlab_security_compliance_candidates",
    "gitlab_project_secure_file": "_gitlab_credential_candidates",
    "gitlab_project_security_policy_attachment": "_gitlab_security_compliance_candidates",
    "gitlab_project_service_account": "_gitlab_identity_candidates",
    "gitlab_project_share_group": "_gitlab_identity_candidates",
    "gitlab_project_tag": "_gitlab_protection_candidates",
    "gitlab_project_target_branch_rule": "_gitlab_protection_candidates",
    "gitlab_project_variable": "_gitlab_credential_candidates",
    "gitlab_project_wiki_page": "_gitlab_collaboration_candidates",
    "gitlab_release": "_gitlab_supply_chain_candidates",
    "gitlab_release_link": "_gitlab_supply_chain_candidates",
    "gitlab_repository_file": "_gitlab_ci_automation_candidates",
    "gitlab_runner_controller": "_gitlab_runner_cluster_candidates",
    "gitlab_runner_controller_instance_scope": "_gitlab_runner_cluster_candidates",
    "gitlab_runner_controller_runner_scope": "_gitlab_runner_cluster_candidates",
    "gitlab_runner_controller_token": "_gitlab_credential_candidates",
    "gitlab_system_hook": "_gitlab_hook_integration_candidates",
    "gitlab_tag_protection": "_gitlab_protection_candidates",
    "gitlab_topic": "_gitlab_collaboration_candidates",
    "gitlab_user": "_gitlab_identity_candidates",
    "gitlab_user_avatar": "_gitlab_collaboration_candidates",
    "gitlab_user_custom_attribute": "_gitlab_collaboration_candidates",
    "gitlab_user_gpgkey": "_gitlab_credential_candidates",
    "gitlab_user_identity": "_gitlab_identity_candidates",
    "gitlab_user_impersonation_token": "_gitlab_credential_candidates",
    "gitlab_user_runner": "_gitlab_runner_cluster_candidates",
    "gitlab_user_saved_reply": "_gitlab_collaboration_candidates",
    "gitlab_user_sshkey": "_gitlab_credential_candidates",
    "gitlab_value_stream_analytics": "_gitlab_collaboration_candidates",
    "helm_release": "_helm_provider_release_candidates",
    "kubernetes_annotations": "_kubernetes_provider_candidates",
    "kubernetes_api_service": "_kubernetes_provider_candidates",
    "kubernetes_api_service_v1": "_kubernetes_provider_candidates",
    "kubernetes_certificate_signing_request": "_kubernetes_provider_candidates",
    "kubernetes_certificate_signing_request_v1": "_kubernetes_provider_candidates",
    "kubernetes_cluster_role": "_k8s_rbac_candidates",
    "kubernetes_cluster_role_binding": "_k8s_rbac_candidates",
    "kubernetes_cluster_role_binding_v1": "_k8s_rbac_candidates",
    "kubernetes_cluster_role_v1": "_k8s_rbac_candidates",
    "kubernetes_config_map": "_kubernetes_provider_candidates",
    "kubernetes_config_map_v1": "_kubernetes_provider_candidates",
    "kubernetes_config_map_v1_data": "_kubernetes_provider_candidates",
    "kubernetes_cron_job": "_kubernetes_provider_candidates",
    "kubernetes_cron_job_v1": "_kubernetes_provider_candidates",
    "kubernetes_csi_driver": "_kubernetes_provider_candidates",
    "kubernetes_csi_driver_v1": "_kubernetes_provider_candidates",
    "kubernetes_daemon_set_v1": "_kubernetes_provider_candidates",
    "kubernetes_daemonset": "_kubernetes_provider_candidates",
    "kubernetes_default_service_account": "_kubernetes_provider_candidates",
    "kubernetes_default_service_account_v1": "_kubernetes_provider_candidates",
    "kubernetes_deployment": "_k8s_deployment_candidates",
    "kubernetes_deployment_v1": "_k8s_deployment_candidates",
    "kubernetes_endpoint_slice_v1": "_kubernetes_provider_candidates",
    "kubernetes_endpoints": "_kubernetes_provider_candidates",
    "kubernetes_endpoints_v1": "_kubernetes_provider_candidates",
    "kubernetes_env": "_kubernetes_provider_candidates",
    "kubernetes_horizontal_pod_autoscaler": "_kubernetes_provider_candidates",
    "kubernetes_horizontal_pod_autoscaler_v1": "_kubernetes_provider_candidates",
    "kubernetes_horizontal_pod_autoscaler_v2": "_kubernetes_provider_candidates",
    "kubernetes_horizontal_pod_autoscaler_v2beta2": "_kubernetes_provider_candidates",
    "kubernetes_ingress": "_k8s_service_candidates",
    "kubernetes_ingress_class": "_kubernetes_provider_candidates",
    "kubernetes_ingress_class_v1": "_kubernetes_provider_candidates",
    "kubernetes_ingress_v1": "_k8s_service_candidates",
    "kubernetes_job": "_kubernetes_provider_candidates",
    "kubernetes_job_v1": "_kubernetes_provider_candidates",
    "kubernetes_labels": "_kubernetes_provider_candidates",
    "kubernetes_limit_range": "_kubernetes_provider_candidates",
    "kubernetes_limit_range_v1": "_kubernetes_provider_candidates",
    "kubernetes_manifest": "_kubernetes_provider_candidates",
    "kubernetes_mutating_webhook_configuration": "_kubernetes_provider_candidates",
    "kubernetes_mutating_webhook_configuration_v1": "_kubernetes_provider_candidates",
    "kubernetes_namespace": "_k8s_namespace_candidates",
    "kubernetes_namespace_v1": "_k8s_namespace_candidates",
    "kubernetes_network_policy": "_k8s_network_policy_candidates",
    "kubernetes_network_policy_v1": "_k8s_network_policy_candidates",
    "kubernetes_node_taint": "_kubernetes_provider_candidates",
    "kubernetes_persistent_volume": "_kubernetes_provider_candidates",
    "kubernetes_persistent_volume_claim": "_kubernetes_provider_candidates",
    "kubernetes_persistent_volume_claim_v1": "_kubernetes_provider_candidates",
    "kubernetes_persistent_volume_v1": "_kubernetes_provider_candidates",
    "kubernetes_pod": "_kubernetes_provider_candidates",
    "kubernetes_pod_disruption_budget": "_kubernetes_provider_candidates",
    "kubernetes_pod_disruption_budget_v1": "_kubernetes_provider_candidates",
    "kubernetes_pod_security_policy": "_kubernetes_provider_candidates",
    "kubernetes_pod_security_policy_v1beta1": "_kubernetes_provider_candidates",
    "kubernetes_pod_v1": "_kubernetes_provider_candidates",
    "kubernetes_priority_class": "_kubernetes_provider_candidates",
    "kubernetes_priority_class_v1": "_kubernetes_provider_candidates",
    "kubernetes_replication_controller": "_kubernetes_provider_candidates",
    "kubernetes_replication_controller_v1": "_kubernetes_provider_candidates",
    "kubernetes_resource_quota": "_kubernetes_provider_candidates",
    "kubernetes_resource_quota_v1": "_kubernetes_provider_candidates",
    "kubernetes_role": "_k8s_rbac_candidates",
    "kubernetes_role_binding": "_k8s_rbac_candidates",
    "kubernetes_role_binding_v1": "_k8s_rbac_candidates",
    "kubernetes_role_v1": "_k8s_rbac_candidates",
    "kubernetes_runtime_class_v1": "_kubernetes_provider_candidates",
    "kubernetes_secret": "_k8s_secret_candidates",
    "kubernetes_secret_v1": "_k8s_secret_candidates",
    "kubernetes_secret_v1_data": "_k8s_secret_candidates",
    "kubernetes_service": "_k8s_service_candidates",
    "kubernetes_service_account": "_kubernetes_provider_candidates",
    "kubernetes_service_account_v1": "_kubernetes_provider_candidates",
    "kubernetes_service_v1": "_k8s_service_candidates",
    "kubernetes_stateful_set": "_kubernetes_provider_candidates",
    "kubernetes_stateful_set_v1": "_kubernetes_provider_candidates",
    "kubernetes_storage_class": "_kubernetes_provider_candidates",
    "kubernetes_storage_class_v1": "_kubernetes_provider_candidates",
    "kubernetes_token_request_v1": "_kubernetes_provider_candidates",
    "kubernetes_validating_admission_policy": "_kubernetes_provider_candidates",
    "kubernetes_validating_webhook_configuration": "_kubernetes_provider_candidates",
    "kubernetes_validating_webhook_configuration_v1": "_kubernetes_provider_candidates",
    "kubernetes_argocd_application": "_argocd_application_candidates",
    "kubernetes_argocd_application_set": "_argocd_application_set_candidates",
    "kubernetes_argocd_project": "_argocd_project_candidates",
    "kubernetes_flux_git_repository": "_flux_git_repository_candidates",
    "kubernetes_flux_oci_repository": "_flux_oci_repository_candidates",
    "kubernetes_flux_kustomization": "_flux_kustomization_candidates",
    "kubernetes_flux_helm_release": "_flux_helm_release_candidates",
    "kubernetes_flux_image_update_automation": "_flux_image_update_automation_candidates",
    "kubernetes_flux_receiver": "_flux_receiver_candidates",
    "kubernetes_tekton_task": "_tekton_task_candidates",
    "kubernetes_tekton_cluster_task": "_tekton_task_candidates",
    "kubernetes_tekton_step_action": "_tekton_task_candidates",
    "kubernetes_tekton_pipeline": "_tekton_pipeline_candidates",
    "kubernetes_tekton_task_run": "_tekton_run_candidates",
    "kubernetes_tekton_pipeline_run": "_tekton_run_candidates",
    "kubernetes_tekton_run": "_tekton_run_candidates",
    "kubernetes_tekton_custom_run": "_tekton_run_candidates",
    "kubernetes_tekton_event_listener": "_tekton_event_listener_candidates",
    "kubernetes_tekton_trigger_template": "_tekton_trigger_template_candidates",
    "kubernetes_tekton_trigger": "_tekton_trigger_candidates",
    "kubernetes_tekton_trigger_binding": "_tekton_trigger_binding_candidates",
    "kubernetes_tekton_cluster_trigger_binding": "_tekton_trigger_binding_candidates",
    "kubernetes_tekton_pipeline_resource": "_tekton_pipeline_resource_candidates",
    "kubernetes_tekton_cluster_interceptor": "_tekton_cluster_interceptor_candidates",
    "kubernetes_tekton_resolution_request": "_tekton_resolution_request_candidates",
    "kubernetes_argo_workflow": "_argo_workflow_candidates",
    "kubernetes_argo_workflow_template": "_argo_workflow_candidates",
    "kubernetes_argo_cluster_workflow_template": "_argo_workflow_candidates",
    "kubernetes_argo_cron_workflow": "_argo_workflow_candidates",
    "kubernetes_argo_workflow_task_set": "_argo_workflow_candidates",
    "kubernetes_argo_workflow_event_binding": "_argo_workflow_event_binding_candidates",
    "kubernetes_argo_event_source": "_argo_event_source_candidates",
    "kubernetes_argo_sensor": "_argo_sensor_candidates",
    "kubernetes_argo_event_bus": "_argo_event_bus_candidates",
    "kubernetes_gateway_class": "_gateway_class_candidates",
    "kubernetes_gateway": "_gateway_candidates",
    "kubernetes_gateway_listener_set": "_gateway_candidates",
    "kubernetes_gateway_http_route": "_gateway_route_candidates",
    "kubernetes_gateway_grpc_route": "_gateway_route_candidates",
    "kubernetes_gateway_tls_route": "_gateway_route_candidates",
    "kubernetes_gateway_tcp_route": "_gateway_route_candidates",
    "kubernetes_gateway_udp_route": "_gateway_route_candidates",
    "kubernetes_gateway_reference_grant": "_gateway_reference_grant_candidates",
    "kubernetes_gateway_backend_tls_policy": "_gateway_backend_tls_policy_candidates",
    "kubernetes_cert_manager_certificate": "_cert_manager_certificate_candidates",
    "kubernetes_cert_manager_issuer": "_cert_manager_issuer_candidates",
    "kubernetes_cert_manager_cluster_issuer": "_cert_manager_issuer_candidates",
    "kubernetes_cert_manager_certificate_request": "_cert_manager_request_candidates",
    "kubernetes_cert_manager_acme_order": "_cert_manager_acme_candidates",
    "kubernetes_cert_manager_acme_challenge": "_cert_manager_acme_candidates",
    "kubernetes_cert_manager_trust_bundle": "_cert_manager_bundle_candidates",
    "kubernetes_external_secrets_secret_store": "_external_secrets_store_candidates",
    "kubernetes_external_secrets_cluster_secret_store": "_external_secrets_store_candidates",
    "kubernetes_external_secrets_external_secret": "_external_secret_candidates",
    "kubernetes_external_secrets_cluster_external_secret": "_external_secret_candidates",
    "kubernetes_external_secrets_push_secret": "_external_secrets_push_candidates",
    "kubernetes_external_secrets_cluster_push_secret": "_external_secrets_push_candidates",
    "kubernetes_external_secrets_generator": "_external_secrets_generator_candidates",
    "kubernetes_istio_virtual_service": "_istio_networking_candidates",
    "kubernetes_istio_destination_rule": "_istio_networking_candidates",
    "kubernetes_istio_gateway": "_istio_networking_candidates",
    "kubernetes_istio_service_entry": "_istio_networking_candidates",
    "kubernetes_istio_sidecar": "_istio_networking_candidates",
    "kubernetes_istio_workload_entry": "_istio_networking_candidates",
    "kubernetes_istio_workload_group": "_istio_networking_candidates",
    "kubernetes_istio_proxy_config": "_istio_networking_candidates",
    "kubernetes_istio_envoy_filter": "_istio_extension_candidates",
    "kubernetes_istio_wasm_plugin": "_istio_extension_candidates",
    "kubernetes_istio_authorization_policy": "_istio_authorization_policy_candidates",
    "kubernetes_istio_peer_authentication": "_istio_authentication_candidates",
    "kubernetes_istio_request_authentication": "_istio_authentication_candidates",
    "kubernetes_istio_telemetry": "_istio_telemetry_candidates",
    "kubernetes_kyverno_cluster_policy": "_kyverno_legacy_policy_candidates",
    "kubernetes_kyverno_policy": "_kyverno_legacy_policy_candidates",
    "kubernetes_kyverno_validating_policy": "_kyverno_cel_policy_candidates",
    "kubernetes_kyverno_namespaced_validating_policy": "_kyverno_cel_policy_candidates",
    "kubernetes_kyverno_mutating_policy": "_kyverno_cel_policy_candidates",
    "kubernetes_kyverno_namespaced_mutating_policy": "_kyverno_cel_policy_candidates",
    "kubernetes_kyverno_generating_policy": "_kyverno_cel_policy_candidates",
    "kubernetes_kyverno_namespaced_generating_policy": "_kyverno_cel_policy_candidates",
    "kubernetes_kyverno_deleting_policy": "_kyverno_cel_policy_candidates",
    "kubernetes_kyverno_namespaced_deleting_policy": "_kyverno_cel_policy_candidates",
    "kubernetes_kyverno_image_validating_policy": "_kyverno_cel_policy_candidates",
    "kubernetes_kyverno_namespaced_image_validating_policy": "_kyverno_cel_policy_candidates",
    "kubernetes_kyverno_cleanup_policy": "_kyverno_cleanup_candidates",
    "kubernetes_kyverno_cluster_cleanup_policy": "_kyverno_cleanup_candidates",
    "kubernetes_kyverno_policy_exception": "_kyverno_exception_candidates",
    "kubernetes_gatekeeper_constraint_template": "_gatekeeper_template_candidates",
    "kubernetes_gatekeeper_constraint": "_gatekeeper_constraint_candidates",
    "kubernetes_gatekeeper_assign": "_gatekeeper_mutation_candidates",
    "kubernetes_gatekeeper_assign_metadata": "_gatekeeper_mutation_candidates",
    "kubernetes_gatekeeper_modify_set": "_gatekeeper_mutation_candidates",
    "kubernetes_gatekeeper_assign_image": "_gatekeeper_mutation_candidates",
    "kubernetes_gatekeeper_config": "_gatekeeper_control_candidates",
    "kubernetes_gatekeeper_expansion_template": "_gatekeeper_control_candidates",
    "kubernetes_gatekeeper_sync_set": "_gatekeeper_control_candidates",
    "kubernetes_gatekeeper_external_data_provider": "_gatekeeper_control_candidates",
    "kubernetes_keda_scaled_object": "_keda_scaled_object_candidates",
    "kubernetes_keda_scaled_job": "_keda_scaled_job_candidates",
    "kubernetes_keda_trigger_authentication": "_keda_authentication_candidates",
    "kubernetes_keda_cluster_trigger_authentication": "_keda_authentication_candidates",
    "kubernetes_keda_cloud_event_source": "_keda_cloud_event_source_candidates",
    "kubernetes_knative_service": "_knative_serving_candidates",
    "kubernetes_knative_configuration": "_knative_serving_candidates",
    "kubernetes_knative_revision": "_knative_serving_candidates",
    "kubernetes_knative_route": "_knative_route_candidates",
    "kubernetes_knative_broker": "_knative_eventing_candidates",
    "kubernetes_knative_trigger": "_knative_eventing_candidates",
    "kubernetes_knative_channel": "_knative_eventing_candidates",
    "kubernetes_knative_in_memory_channel": "_knative_eventing_candidates",
    "kubernetes_knative_subscription": "_knative_eventing_candidates",
    "kubernetes_knative_sequence": "_knative_eventing_candidates",
    "kubernetes_knative_parallel": "_knative_eventing_candidates",
    "kubernetes_knative_event_source": "_knative_eventing_candidates",
    "kubernetes_knative_event_transform": "_knative_eventing_candidates",
    "kubernetes_knative_request_reply": "_knative_eventing_candidates",
    "kubernetes_knative_event_policy": "_knative_event_policy_candidates",
    "kubernetes_capi_cluster": "_capi_cluster_candidates",
    "kubernetes_capi_cluster_class": "_capi_cluster_class_candidates",
    "kubernetes_capi_machine": "_capi_machine_candidates",
    "kubernetes_capi_machine_set": "_capi_machine_candidates",
    "kubernetes_capi_machine_deployment": "_capi_machine_candidates",
    "kubernetes_capi_machine_pool": "_capi_machine_candidates",
    "kubernetes_capi_machine_health_check": "_capi_machine_health_check_candidates",
    "kubernetes_capi_kubeadm_control_plane": "_capi_control_plane_candidates",
    "kubernetes_capi_kubeadm_control_plane_template": "_capi_control_plane_candidates",
    "kubernetes_capi_kubeadm_config": "_capi_kubeadm_config_candidates",
    "kubernetes_capi_kubeadm_config_template": "_capi_kubeadm_config_candidates",
    "kubernetes_capi_extension_config": "_capi_extension_config_candidates",
    "kubernetes_capi_cluster_resource_set": "_capi_cluster_resource_set_candidates",
    "kubernetes_capi_machine_drain_rule": "_capi_machine_drain_rule_candidates",
    "kubernetes_capi_ip_address": "_capi_supporting_resource_candidates",
    "kubernetes_capi_ip_address_claim": "_capi_supporting_resource_candidates",
    "kubernetes_capi_cluster_resource_set_binding": "_capi_supporting_resource_candidates",
    "kubernetes_karpenter_node_pool": "_karpenter_node_pool_candidates",
    "kubernetes_karpenter_legacy_provisioner": "_karpenter_node_pool_candidates",
    "kubernetes_karpenter_node_claim": "_karpenter_node_claim_candidates",
    "kubernetes_karpenter_node_class": "_karpenter_node_class_candidates",
    "kubernetes_karpenter_legacy_node_template": "_karpenter_node_class_candidates",
    "newrelic_account_management": "_newrelic_candidates",
    "newrelic_alert_channel": "_newrelic_candidates",
    "newrelic_alert_compound_condition": "_newrelic_candidates",
    "newrelic_alert_condition": "_newrelic_candidates",
    "newrelic_alert_muting_rule": "_newrelic_candidates",
    "newrelic_alert_policy": "_newrelic_candidates",
    "newrelic_alert_policy_channel": "_newrelic_candidates",
    "newrelic_api_access_key": "_newrelic_candidates",
    "newrelic_application_settings": "_newrelic_candidates",
    "newrelic_aws_connection": "_newrelic_candidates",
    "newrelic_browser_application": "_newrelic_candidates",
    "newrelic_cardinality_management": "_newrelic_candidates",
    "newrelic_cloud_aws_eu_sovereign_integrations": "_newrelic_candidates",
    "newrelic_cloud_aws_eu_sovereign_link_account": "_newrelic_candidates",
    "newrelic_cloud_aws_govcloud_integrations": "_newrelic_candidates",
    "newrelic_cloud_aws_govcloud_link_account": "_newrelic_candidates",
    "newrelic_cloud_aws_integrations": "_newrelic_candidates",
    "newrelic_cloud_aws_link_account": "_newrelic_candidates",
    "newrelic_cloud_azure_integrations": "_newrelic_candidates",
    "newrelic_cloud_azure_link_account": "_newrelic_candidates",
    "newrelic_cloud_gcp_integrations": "_newrelic_candidates",
    "newrelic_cloud_gcp_link_account": "_newrelic_candidates",
    "newrelic_cloud_oci_link_account": "_newrelic_candidates",
    "newrelic_data_partition_rule": "_newrelic_candidates",
    "newrelic_entity_tags": "_newrelic_candidates",
    "newrelic_events_to_metrics_rule": "_newrelic_candidates",
    "newrelic_federated_logs_partition": "_newrelic_candidates",
    "newrelic_federated_logs_setup": "_newrelic_candidates",
    "newrelic_fleet": "_newrelic_candidates",
    "newrelic_fleet_configuration": "_newrelic_candidates",
    "newrelic_fleet_deployment": "_newrelic_candidates",
    "newrelic_fleet_members": "_newrelic_candidates",
    "newrelic_group": "_newrelic_candidates",
    "newrelic_infra_alert_condition": "_newrelic_candidates",
    "newrelic_insights_event": "_newrelic_candidates",
    "newrelic_key_transaction": "_newrelic_candidates",
    "newrelic_log_parsing_rule": "_newrelic_candidates",
    "newrelic_metric_pruning_rule": "_newrelic_candidates",
    "newrelic_monitor_downtime": "_newrelic_candidates",
    "newrelic_notification_channel": "_newrelic_candidates",
    "newrelic_notification_destination": "_newrelic_candidates",
    "newrelic_nrql_alert_condition": "_newrelic_candidates",
    "newrelic_nrql_drop_rule": "_newrelic_candidates",
    "newrelic_obfuscation_expression": "_newrelic_candidates",
    "newrelic_obfuscation_rule": "_newrelic_candidates",
    "newrelic_one_dashboard": "_newrelic_candidates",
    "newrelic_one_dashboard_json": "_newrelic_candidates",
    "newrelic_one_dashboard_raw": "_newrelic_candidates",
    "newrelic_pipeline_cloud_rule": "_newrelic_candidates",
    "newrelic_service_level": "_newrelic_candidates",
    "newrelic_synthetics_alert_condition": "_newrelic_candidates",
    "newrelic_synthetics_broken_links_monitor": "_newrelic_candidates",
    "newrelic_synthetics_cert_check_monitor": "_newrelic_candidates",
    "newrelic_synthetics_monitor": "_newrelic_candidates",
    "newrelic_synthetics_multilocation_alert_condition": "_newrelic_candidates",
    "newrelic_synthetics_private_location": "_newrelic_candidates",
    "newrelic_synthetics_script_monitor": "_newrelic_candidates",
    "newrelic_synthetics_secure_credential": "_newrelic_candidates",
    "newrelic_synthetics_step_monitor": "_newrelic_candidates",
    "newrelic_user": "_newrelic_candidates",
    "newrelic_workflow": "_newrelic_candidates",
    "newrelic_workflow_automation": "_newrelic_candidates",
    "newrelic_workload": "_newrelic_candidates",
    "pagerduty_addon": "_pagerduty_candidates",
    "pagerduty_alert_grouping_setting": "_pagerduty_candidates",
    "pagerduty_automation_actions_action": "_pagerduty_candidates",
    "pagerduty_automation_actions_action_service_association": "_pagerduty_candidates",
    "pagerduty_automation_actions_action_team_association": "_pagerduty_candidates",
    "pagerduty_automation_actions_runner": "_pagerduty_candidates",
    "pagerduty_automation_actions_runner_team_association": "_pagerduty_candidates",
    "pagerduty_business_service": "_pagerduty_candidates",
    "pagerduty_business_service_subscriber": "_pagerduty_candidates",
    "pagerduty_enablement": "_pagerduty_candidates",
    "pagerduty_escalation_policy": "_pagerduty_candidates",
    "pagerduty_event_orchestration": "_pagerduty_candidates",
    "pagerduty_event_orchestration_global": "_pagerduty_candidates",
    "pagerduty_event_orchestration_global_cache_variable": "_pagerduty_candidates",
    "pagerduty_event_orchestration_integration": "_pagerduty_candidates",
    "pagerduty_event_orchestration_router": "_pagerduty_candidates",
    "pagerduty_event_orchestration_service": "_pagerduty_candidates",
    "pagerduty_event_orchestration_service_cache_variable": "_pagerduty_candidates",
    "pagerduty_event_orchestration_unrouted": "_pagerduty_candidates",
    "pagerduty_event_rule": "_pagerduty_candidates",
    "pagerduty_extension": "_pagerduty_candidates",
    "pagerduty_extension_servicenow": "_pagerduty_candidates",
    "pagerduty_incident_custom_field": "_pagerduty_candidates",
    "pagerduty_incident_custom_field_option": "_pagerduty_candidates",
    "pagerduty_incident_type": "_pagerduty_candidates",
    "pagerduty_incident_type_custom_field": "_pagerduty_candidates",
    "pagerduty_incident_workflow": "_pagerduty_candidates",
    "pagerduty_incident_workflow_trigger": "_pagerduty_candidates",
    "pagerduty_jira_cloud_account_mapping_rule": "_pagerduty_candidates",
    "pagerduty_maintenance_window": "_pagerduty_candidates",
    "pagerduty_response_play": "_pagerduty_candidates",
    "pagerduty_ruleset": "_pagerduty_candidates",
    "pagerduty_ruleset_rule": "_pagerduty_candidates",
    "pagerduty_schedule": "_pagerduty_candidates",
    "pagerduty_schedulev2": "_pagerduty_candidates",
    "pagerduty_service": "_pagerduty_candidates",
    "pagerduty_service_custom_field": "_pagerduty_candidates",
    "pagerduty_service_custom_field_value": "_pagerduty_candidates",
    "pagerduty_service_dependency": "_pagerduty_candidates",
    "pagerduty_service_event_rule": "_pagerduty_candidates",
    "pagerduty_service_integration": "_pagerduty_candidates",
    "pagerduty_slack_connection": "_pagerduty_candidates",
    "pagerduty_tag": "_pagerduty_candidates",
    "pagerduty_tag_assignment": "_pagerduty_candidates",
    "pagerduty_team": "_pagerduty_candidates",
    "pagerduty_team_membership": "_pagerduty_candidates",
    "pagerduty_user": "_pagerduty_candidates",
    "pagerduty_user_contact_method": "_pagerduty_candidates",
    "pagerduty_user_handoff_notification_rule": "_pagerduty_candidates",
    "pagerduty_user_notification_rule": "_pagerduty_candidates",
    "pagerduty_webhook_subscription": "_pagerduty_candidates",
    "tfe_admin_organization_settings": "_tfe_candidates",
    "tfe_admin_smtp_settings": "_tfe_candidates",
    "tfe_agent_pool": "_tfe_candidates",
    "tfe_agent_pool_allowed_projects": "_tfe_candidates",
    "tfe_agent_pool_allowed_workspaces": "_tfe_candidates",
    "tfe_agent_pool_excluded_workspaces": "_tfe_candidates",
    "tfe_agent_token": "_tfe_candidates",
    "tfe_audit_trail_token": "_tfe_candidates",
    "tfe_aws_oidc_configuration": "_tfe_candidates",
    "tfe_azure_oidc_configuration": "_tfe_candidates",
    "tfe_data_retention_policy": "_tfe_candidates",
    "tfe_gcp_oidc_configuration": "_tfe_candidates",
    "tfe_hyok_configuration": "_tfe_candidates",
    "tfe_no_code_module": "_tfe_candidates",
    "tfe_notification_configuration": "_tfe_candidates",
    "tfe_oauth_client": "_tfe_candidates",
    "tfe_opa_version": "_tfe_candidates",
    "tfe_org_max_token_ttl_policy": "_tfe_candidates",
    "tfe_organization": "_tfe_candidates",
    "tfe_organization_default_settings": "_tfe_candidates",
    "tfe_organization_membership": "_tfe_candidates",
    "tfe_organization_module_sharing": "_tfe_candidates",
    "tfe_organization_run_task": "_tfe_candidates",
    "tfe_organization_run_task_global_settings": "_tfe_candidates",
    "tfe_organization_token": "_tfe_candidates",
    "tfe_policy": "_tfe_candidates",
    "tfe_policy_set": "_tfe_candidates",
    "tfe_policy_set_parameter": "_tfe_candidates",
    "tfe_project": "_tfe_candidates",
    "tfe_project_notification_configuration": "_tfe_candidates",
    "tfe_project_oauth_client": "_tfe_candidates",
    "tfe_project_policy_set": "_tfe_candidates",
    "tfe_project_policy_set_exclusion": "_tfe_candidates",
    "tfe_project_settings": "_tfe_candidates",
    "tfe_project_variable_set": "_tfe_candidates",
    "tfe_provider_set": "_tfe_candidates",
    "tfe_registry_gpg_key": "_tfe_candidates",
    "tfe_registry_module": "_tfe_candidates",
    "tfe_registry_provider": "_tfe_candidates",
    "tfe_registry_provider_version": "_tfe_candidates",
    "tfe_registry_provider_version_platform": "_tfe_candidates",
    "tfe_run_trigger": "_tfe_candidates",
    "tfe_saml_settings": "_tfe_candidates",
    "tfe_scim_group_mapping": "_tfe_candidates",
    "tfe_scim_settings": "_tfe_candidates",
    "tfe_scim_token": "_tfe_candidates",
    "tfe_sentinel_policy": "_tfe_candidates",
    "tfe_sentinel_version": "_tfe_candidates",
    "tfe_ssh_key": "_tfe_candidates",
    "tfe_stack": "_tfe_candidates",
    "tfe_stack_variable_set": "_tfe_candidates",
    "tfe_team": "_tfe_candidates",
    "tfe_team_access": "_tfe_candidates",
    "tfe_team_member": "_tfe_candidates",
    "tfe_team_members": "_tfe_candidates",
    "tfe_team_notification_configuration": "_tfe_candidates",
    "tfe_team_organization_member": "_tfe_candidates",
    "tfe_team_organization_members": "_tfe_candidates",
    "tfe_team_project_access": "_tfe_candidates",
    "tfe_team_token": "_tfe_candidates",
    "tfe_terraform_version": "_tfe_candidates",
    "tfe_tfe_test_variable": "_tfe_candidates",
    "tfe_variable": "_tfe_candidates",
    "tfe_variable_set": "_tfe_candidates",
    "tfe_vault_oidc_configuration": "_tfe_candidates",
    "tfe_workspace": "_tfe_candidates",
    "tfe_workspace_policy_set": "_tfe_candidates",
    "tfe_workspace_policy_set_exclusion": "_tfe_candidates",
    "tfe_workspace_run": "_tfe_candidates",
    "tfe_workspace_run_task": "_tfe_candidates",
    "tfe_workspace_settings": "_tfe_candidates",
    "tfe_workspace_variable_set": "_tfe_candidates",
    "vault_activation_flags": "_vault_candidates",
    "vault_ad_secret_backend": "_vault_candidates",
    "vault_ad_secret_backend_library": "_vault_candidates",
    "vault_ad_secret_role": "_vault_candidates",
    "vault_agent_registration": "_vault_candidates",
    "vault_alicloud_auth_backend_role": "_vault_candidates",
    "vault_alicloud_secret_backend": "_vault_candidates",
    "vault_alicloud_secret_backend_role": "_vault_candidates",
    "vault_approle_auth_backend_login": "_vault_candidates",
    "vault_approle_auth_backend_role": "_vault_candidates",
    "vault_approle_auth_backend_role_secret_id": "_vault_candidates",
    "vault_audit": "_vault_candidates",
    "vault_audit_request_header": "_vault_candidates",
    "vault_auth_backend": "_vault_candidates",
    "vault_aws_auth_backend_cert": "_vault_candidates",
    "vault_aws_auth_backend_client": "_vault_candidates",
    "vault_aws_auth_backend_config_identity": "_vault_candidates",
    "vault_aws_auth_backend_identity_whitelist": "_vault_candidates",
    "vault_aws_auth_backend_login": "_vault_candidates",
    "vault_aws_auth_backend_role": "_vault_candidates",
    "vault_aws_auth_backend_role_tag": "_vault_candidates",
    "vault_aws_auth_backend_roletag_blacklist": "_vault_candidates",
    "vault_aws_auth_backend_sts_role": "_vault_candidates",
    "vault_aws_secret_backend": "_vault_candidates",
    "vault_aws_secret_backend_role": "_vault_candidates",
    "vault_aws_secret_backend_static_role": "_vault_candidates",
    "vault_azure_auth_backend_config": "_vault_candidates",
    "vault_azure_auth_backend_role": "_vault_candidates",
    "vault_azure_secret_backend": "_vault_candidates",
    "vault_azure_secret_backend_role": "_vault_candidates",
    "vault_azure_secret_backend_static_role": "_vault_candidates",
    "vault_cert_auth_backend_role": "_vault_candidates",
    "vault_cf_auth_backend_config": "_vault_candidates",
    "vault_cf_auth_backend_role": "_vault_candidates",
    "vault_config_control_group": "_vault_candidates",
    "vault_config_group_policy_application": "_vault_candidates",
    "vault_config_ui_custom_messages": "_vault_candidates",
    "vault_config_ui_default_auth": "_vault_candidates",
    "vault_config_ui_header": "_vault_candidates",
    "vault_consul_secret_backend": "_vault_candidates",
    "vault_consul_secret_backend_role": "_vault_candidates",
    "vault_database_secret_backend_connection": "_vault_candidates",
    "vault_database_secret_backend_role": "_vault_candidates",
    "vault_database_secret_backend_static_role": "_vault_candidates",
    "vault_database_secrets_mount": "_vault_candidates",
    "vault_egp_policy": "_vault_candidates",
    "vault_gcp_auth_backend": "_vault_candidates",
    "vault_gcp_auth_backend_role": "_vault_candidates",
    "vault_gcp_secret_backend": "_vault_candidates",
    "vault_gcp_secret_impersonated_account": "_vault_candidates",
    "vault_gcp_secret_roleset": "_vault_candidates",
    "vault_gcp_secret_static_account": "_vault_candidates",
    "vault_generic_endpoint": "_vault_candidates",
    "vault_generic_secret": "_vault_candidates",
    "vault_github_auth_backend": "_vault_candidates",
    "vault_github_team": "_vault_candidates",
    "vault_github_user": "_vault_candidates",
    "vault_identity_entity": "_vault_candidates",
    "vault_identity_entity_alias": "_vault_candidates",
    "vault_identity_entity_policies": "_vault_candidates",
    "vault_identity_group": "_vault_candidates",
    "vault_identity_group_alias": "_vault_candidates",
    "vault_identity_group_member_entity_ids": "_vault_candidates",
    "vault_identity_group_member_group_ids": "_vault_candidates",
    "vault_identity_group_policies": "_vault_candidates",
    "vault_identity_mfa_duo": "_vault_candidates",
    "vault_identity_mfa_login_enforcement": "_vault_candidates",
    "vault_identity_mfa_okta": "_vault_candidates",
    "vault_identity_mfa_pingid": "_vault_candidates",
    "vault_identity_mfa_totp": "_vault_candidates",
    "vault_identity_oidc": "_vault_candidates",
    "vault_identity_oidc_assignment": "_vault_candidates",
    "vault_identity_oidc_client": "_vault_candidates",
    "vault_identity_oidc_key": "_vault_candidates",
    "vault_identity_oidc_key_allowed_client_id": "_vault_candidates",
    "vault_identity_oidc_provider": "_vault_candidates",
    "vault_identity_oidc_role": "_vault_candidates",
    "vault_identity_oidc_scope": "_vault_candidates",
    "vault_jwt_auth_backend": "_vault_candidates",
    "vault_jwt_auth_backend_role": "_vault_candidates",
    "vault_keymgmt_aws_kms": "_vault_candidates",
    "vault_keymgmt_azure_kms": "_vault_candidates",
    "vault_keymgmt_distribute_key": "_vault_candidates",
    "vault_keymgmt_gcp_kms": "_vault_candidates",
    "vault_keymgmt_key": "_vault_candidates",
    "vault_keymgmt_key_rotate": "_vault_candidates",
    "vault_keymgmt_replicate_key": "_vault_candidates",
    "vault_kmip_secret_backend": "_vault_candidates",
    "vault_kmip_secret_ca_generated": "_vault_candidates",
    "vault_kmip_secret_ca_imported": "_vault_candidates",
    "vault_kmip_secret_listener": "_vault_candidates",
    "vault_kmip_secret_role": "_vault_candidates",
    "vault_kmip_secret_scope": "_vault_candidates",
    "vault_kubernetes_auth_backend_config": "_vault_candidates",
    "vault_kubernetes_auth_backend_role": "_vault_candidates",
    "vault_kubernetes_secret_backend": "_vault_candidates",
    "vault_kubernetes_secret_backend_role": "_vault_candidates",
    "vault_kv_secret": "_vault_candidates",
    "vault_kv_secret_backend_v2": "_vault_candidates",
    "vault_kv_secret_v2": "_vault_candidates",
    "vault_ldap_auth_backend": "_vault_candidates",
    "vault_ldap_auth_backend_group": "_vault_candidates",
    "vault_ldap_auth_backend_user": "_vault_candidates",
    "vault_ldap_secret_backend": "_vault_candidates",
    "vault_ldap_secret_backend_dynamic_role": "_vault_candidates",
    "vault_ldap_secret_backend_library_set": "_vault_candidates",
    "vault_ldap_secret_backend_static_role": "_vault_candidates",
    "vault_managed_keys": "_vault_candidates",
    "vault_mfa_duo": "_vault_candidates",
    "vault_mfa_okta": "_vault_candidates",
    "vault_mfa_pingid": "_vault_candidates",
    "vault_mfa_totp": "_vault_candidates",
    "vault_mongodbatlas_secret_backend": "_vault_candidates",
    "vault_mongodbatlas_secret_role": "_vault_candidates",
    "vault_mount": "_vault_candidates",
    "vault_namespace": "_vault_candidates",
    "vault_nomad_secret_backend": "_vault_candidates",
    "vault_nomad_secret_role": "_vault_candidates",
    "vault_oauth_resource_server_config_profile": "_vault_candidates",
    "vault_oci_auth_backend": "_vault_candidates",
    "vault_oci_auth_backend_role": "_vault_candidates",
    "vault_okta_auth_backend": "_vault_candidates",
    "vault_okta_auth_backend_group": "_vault_candidates",
    "vault_okta_auth_backend_user": "_vault_candidates",
    "vault_os_secret_backend": "_vault_candidates",
    "vault_os_secret_backend_account": "_vault_candidates",
    "vault_os_secret_backend_host": "_vault_candidates",
    "vault_password_policy": "_vault_candidates",
    "vault_pki_external_ca_secret_backend_acme_account": "_vault_candidates",
    "vault_pki_external_ca_secret_backend_order": "_vault_candidates",
    "vault_pki_external_ca_secret_backend_order_certificate": "_vault_candidates",
    "vault_pki_external_ca_secret_backend_order_challenge_fulfilled": "_vault_candidates",
    "vault_pki_external_ca_secret_backend_role": "_vault_candidates",
    "vault_pki_secret_backend_acme_eab": "_vault_candidates",
    "vault_pki_secret_backend_cert": "_vault_candidates",
    "vault_pki_secret_backend_config_acme": "_vault_candidates",
    "vault_pki_secret_backend_config_auto_tidy": "_vault_candidates",
    "vault_pki_secret_backend_config_ca": "_vault_candidates",
    "vault_pki_secret_backend_config_cluster": "_vault_candidates",
    "vault_pki_secret_backend_config_cmpv2": "_vault_candidates",
    "vault_pki_secret_backend_config_est": "_vault_candidates",
    "vault_pki_secret_backend_config_issuers": "_vault_candidates",
    "vault_pki_secret_backend_config_scep": "_vault_candidates",
    "vault_pki_secret_backend_config_urls": "_vault_candidates",
    "vault_pki_secret_backend_crl_config": "_vault_candidates",
    "vault_pki_secret_backend_intermediate_cert_request": "_vault_candidates",
    "vault_pki_secret_backend_intermediate_set_signed": "_vault_candidates",
    "vault_pki_secret_backend_issuer": "_vault_candidates",
    "vault_pki_secret_backend_key": "_vault_candidates",
    "vault_pki_secret_backend_role": "_vault_candidates",
    "vault_pki_secret_backend_root_cert": "_vault_candidates",
    "vault_pki_secret_backend_root_sign_intermediate": "_vault_candidates",
    "vault_pki_secret_backend_sign": "_vault_candidates",
    "vault_plugin": "_vault_candidates",
    "vault_plugin_pinned_version": "_vault_candidates",
    "vault_plugin_runtime": "_vault_candidates",
    "vault_policy": "_vault_candidates",
    "vault_quota_config": "_vault_candidates",
    "vault_quota_lease_count": "_vault_candidates",
    "vault_quota_rate_limit": "_vault_candidates",
    "vault_rabbitmq_secret_backend": "_vault_candidates",
    "vault_rabbitmq_secret_backend_role": "_vault_candidates",
    "vault_radius_auth_backend": "_vault_candidates",
    "vault_radius_auth_backend_user": "_vault_candidates",
    "vault_raft_autopilot": "_vault_candidates",
    "vault_raft_snapshot_agent_config": "_vault_candidates",
    "vault_rgp_policy": "_vault_candidates",
    "vault_rotation_policy": "_vault_candidates",
    "vault_saml_auth_backend": "_vault_candidates",
    "vault_saml_auth_backend_role": "_vault_candidates",
    "vault_scep_auth_backend_role": "_vault_candidates",
    "vault_secrets_sync_association": "_vault_candidates",
    "vault_secrets_sync_aws_destination": "_vault_candidates",
    "vault_secrets_sync_azure_destination": "_vault_candidates",
    "vault_secrets_sync_config": "_vault_candidates",
    "vault_secrets_sync_gcp_destination": "_vault_candidates",
    "vault_secrets_sync_gh_destination": "_vault_candidates",
    "vault_secrets_sync_github_apps": "_vault_candidates",
    "vault_secrets_sync_vercel_destination": "_vault_candidates",
    "vault_spiffe_auth_backend_config": "_vault_candidates",
    "vault_spiffe_auth_backend_role": "_vault_candidates",
    "vault_spiffe_secret_backend_config": "_vault_candidates",
    "vault_spiffe_secret_backend_role": "_vault_candidates",
    "vault_ssh_secret_backend_ca": "_vault_candidates",
    "vault_ssh_secret_backend_role": "_vault_candidates",
    "vault_sys_config_cors": "_vault_candidates",
    "vault_terraform_cloud_secret_backend": "_vault_candidates",
    "vault_terraform_cloud_secret_creds": "_vault_candidates",
    "vault_terraform_cloud_secret_role": "_vault_candidates",
    "vault_token": "_vault_candidates",
    "vault_token_auth_backend_role": "_vault_candidates",
    "vault_transform_alphabet": "_vault_candidates",
    "vault_transform_role": "_vault_candidates",
    "vault_transform_template": "_vault_candidates",
    "vault_transform_transformation": "_vault_candidates",
    "vault_transit_secret_backend_cache_config": "_vault_candidates",
    "vault_transit_secret_backend_key": "_vault_candidates",
    "vault_userpass_auth_backend_user": "_vault_candidates",
}


def test_rule_registry_has_complete_provider_coverage() -> None:
    """The registry contains every covered, real IaC provider resource type."""
    assert set(_RULE_REGISTRY) == set(_EXPECTED_RULE_FUNCTIONS)

    for resource_type, expected_function in _EXPECTED_RULE_FUNCTIONS.items():
        registered = _RULE_REGISTRY[resource_type]
        assert registered, f"{resource_type} has no registered rule functions"
        assert expected_function in {function.__name__ for function in registered}

    expected_cross_cutting = {
        aws_rules._platform_service_candidates,
        aws_rules._network_topology_candidates,
        aws_rules._observability_candidates,
    }
    assert expected_cross_cutting <= set(_CROSS_CUTTING)


def _write_plan(tmp_path: Path, resource_change: dict[str, Any]) -> Path:
    path = tmp_path / "plan.json"
    path.write_text(
        json.dumps(
            {
                "format_version": "1.2",
                "terraform_version": "1.6.6",
                "resource_changes": [resource_change],
            }
        ),
        encoding="utf-8",
    )
    return path


def _change(
    resource_type: str,
    actions: list[str],
    *,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> dict[str, Any]:
    change: dict[str, Any] = {"actions": actions}
    if before is not None:
        change["before"] = before
    if after is not None:
        change["after"] = after
    return {
        "address": f"{resource_type}.example",
        "type": resource_type,
        "name": "example",
        "change": change,
    }


def _policy(statements: list[dict[str, Any]]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def test_tier_a_resource_rules_add_explainers(tmp_path: Path) -> None:
    cases = [
        (
            _change("aws_db_instance", ["delete", "create"]),
            "dangerous",
            "RDS instance",
        ),
        (
            _change(
                "aws_rds_cluster",
                ["update"],
                before={"engine_version": "13.8"},
                after={"engine_version": "14.1"},
            ),
            "dangerous",
            "major version",
        ),
        (
            _change(
                "aws_s3_bucket",
                ["delete"],
                before={"force_destroy": True},
            ),
            "irreversible",
            "force_destroy",
        ),
        (
            _change(
                "aws_s3_bucket_policy",
                ["update"],
                before={"policy": _policy([])},
                after={
                    "policy": _policy(
                        [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]
                    )
                },
            ),
            "dangerous",
            "public access",
        ),
        (
            _change("aws_kms_key", ["delete"]),
            "irreversible",
            "KMS key",
        ),
        (
            _change(
                "aws_iam_role",
                ["update"],
                before={"assume_role_policy": _policy([])},
                after={
                    "assume_role_policy": _policy([{"Effect": "Allow", "Principal": {"AWS": "*"}}])
                },
            ),
            "dangerous",
            "trust policy",
        ),
        (
            _change("aws_route53_zone", ["delete"]),
            "irreversible",
            "Route53 hosted zone",
        ),
        (
            _change("aws_eks_node_group", ["delete", "create"]),
            "dangerous",
            "EKS node group",
        ),
    ]

    for resource_change, expected_risk, expected_explanation in cases:
        summary = analyze_plan_file(_write_plan(tmp_path, resource_change))
        change = summary.resource_changes[0]

        assert change.risk == expected_risk
        assert expected_explanation in change.explanation


def test_iam_removed_deny_escalates_to_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_iam_policy",
            ["update"],
            before={"policy": _policy([{"Effect": "Deny", "Action": "iam:*"}])},
            after={"policy": _policy([{"Effect": "Allow", "Action": "s3:GetObject"}])},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "remove deny statements" in summary.resource_changes[0].explanation


def test_lb_listener_default_action_change_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb_listener",
            ["update"],
            before={"default_action": [{"type": "forward", "target_group_arn": "old"}]},
            after={"default_action": [{"type": "forward", "target_group_arn": "new"}]},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "default_action" in summary.resource_changes[0].explanation


def test_lb_listener_port_change_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb_listener",
            ["update"],
            before={"port": 80, "protocol": "HTTP"},
            after={"port": 443, "protocol": "HTTPS"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "port or protocol" in summary.resource_changes[0].explanation


def test_lb_scheme_change_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb",
            ["update"],
            before={"internal": True},
            after={"internal": False},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "irreversible"
    assert "scheme" in summary.resource_changes[0].explanation


def test_lb_target_group_health_check_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb_target_group",
            ["update"],
            before={"health_check": {"interval": 30, "threshold": 3}},
            after={"health_check": {"interval": 5, "threshold": 2}},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "health check" in summary.resource_changes[0].explanation


def test_lb_listener_rule_priority_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb_listener_rule",
            ["update"],
            before={"priority": 100},
            after={"priority": 50},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "priority" in summary.resource_changes[0].explanation


def test_lb_target_group_target_type_change_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb_target_group",
            ["delete", "create"],
            before={"target_type": "instance"},
            after={"target_type": "ip"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "target_type" in summary.resource_changes[0].explanation


def test_lb_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("aws_lb", ["delete"]),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this load balancer" in summary.resource_changes[0].explanation


def test_lambda_package_type_change_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"package_type": "Zip"},
            after={"package_type": "Image"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "package_type" in summary.resource_changes[0].explanation


def test_lambda_code_signing_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"code_signing_config_arn": "arn:aws:lambda:us-east-1:123:csc/old"},
            after={"code_signing_config_arn": "arn:aws:lambda:us-east-1:123:csc/new"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "code_signing_config_arn" in summary.resource_changes[0].explanation


def test_lambda_vpc_config_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"vpc_config": None},
            after={"vpc_config": {"subnet_ids": ["subnet-123"], "security_group_ids": ["sg-123"]}},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "vpc_config" in summary.resource_changes[0].explanation


def test_lambda_runtime_major_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"runtime": "nodejs20.x"},
            after={"runtime": "nodejs22.x"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "runtime" in summary.resource_changes[0].explanation


def test_lambda_role_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"role": "arn:aws:iam::123:role/old"},
            after={"role": "arn:aws:iam::123:role/new"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "role" in summary.resource_changes[0].explanation


def test_lambda_runtime_minor_change_not_flagged(tmp_path: Path) -> None:
    """Same major runtime (python3.11 -> python3.12) should not trigger runtime rule."""
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"runtime": "python3.11"},
            after={"runtime": "python3.12"},
        ),
    )

    summary = analyze_plan_file(plan)

    # Should still be review from generic update, but not from runtime rule
    assert "runtime" not in summary.resource_changes[0].explanation


def test_platform_service_rules_cover_ecr_sqs_and_glue(tmp_path: Path) -> None:
    cases = [
        (
            _change("aws_ecr_repository", ["delete"]),
            "irreversible",
            "ECR repository",
        ),
        (
            _change(
                "aws_sqs_queue_policy",
                ["update"],
                before={"policy": _policy([])},
                after={
                    "policy": _policy(
                        [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "sqs:SendMessage",
                            }
                        ]
                    )
                },
            ),
            "dangerous",
            "public access",
        ),
        (
            _change("aws_glue_job", ["delete"]),
            "irreversible",
            "Glue job",
        ),
    ]

    for resource_change, expected_risk, expected_explanation in cases:
        summary = analyze_plan_file(_write_plan(tmp_path, resource_change))
        change = summary.resource_changes[0]

        assert change.risk == expected_risk
        assert expected_explanation in change.explanation


def test_network_topology_route_to_internet_gateway_is_dangerous(
    tmp_path: Path,
) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_route",
            ["create"],
            after={
                "destination_cidr_block": "0.0.0.0/0",
                "gateway_id": "igw-example",
            },
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "default route to an internet gateway" in summary.resource_changes[0].explanation


def test_security_group_open_ingress_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_security_group",
            ["update"],
            before={
                "ingress": [
                    {
                        "from_port": 443,
                        "to_port": 443,
                        "protocol": "tcp",
                        "cidr_blocks": ["10.0.0.0/16"],
                    }
                ]
            },
            after={
                "ingress": [
                    {
                        "from_port": 443,
                        "to_port": 443,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ]
            },
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "internet-wide access" in summary.resource_changes[0].explanation


def test_vpc_security_group_ingress_rule_open_ipv4_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_vpc_security_group_ingress_rule",
            ["create"],
            after={
                "from_port": 22,
                "to_port": 22,
                "ip_protocol": "tcp",
                "cidr_ipv4": "0.0.0.0/0",
            },
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "internet-wide access" in summary.resource_changes[0].explanation


def test_vpc_security_group_egress_rule_non_public_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_vpc_security_group_egress_rule",
            ["update"],
            before={"cidr_ipv4": "10.0.0.0/16"},
            after={"cidr_ipv4": "172.16.0.0/12"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "change security group rules" in summary.resource_changes[0].explanation


def test_cloudwatch_log_group_retention_decrease_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_cloudwatch_log_group",
            ["update"],
            before={"retention_in_days": 365},
            after={"retention_in_days": 30},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "retention is decreasing" in summary.resource_changes[0].explanation


def test_resource_rules_can_be_disabled(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_rds_cluster",
            ["update"],
            before={"engine_version": "13.8"},
            after={"engine_version": "14.1"},
        ),
    )

    summary = analyze_plan_file(plan, use_rules=False)

    assert summary.resource_changes[0].risk == "review"
    assert "update this resource in place" in summary.resource_changes[0].explanation


# ---------------------------------------------------------------------------
# google_* (GCP) provider tests
# ---------------------------------------------------------------------------


def test_gcp_compute_instance_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("google_compute_instance", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this Compute Engine instance" in summary.resource_changes[0].explanation


def test_gcp_compute_instance_replace_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("google_compute_instance", ["delete", "create"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "dangerous"
    assert "replace" in summary.resource_changes[0].explanation


def test_gcp_compute_instance_machine_type_change_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "google_compute_instance",
            ["update"],
            before={"machine_type": "n1-standard-1"},
            after={"machine_type": "n1-standard-4"},
        ),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "dangerous"
    assert "machine_type" in summary.resource_changes[0].explanation


def test_gcp_compute_instance_tags_change_is_safe(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "google_compute_instance",
            ["update"],
            before={"tags": ["http-server"]},
            after={"tags": ["http-server", "https-server"]},
        ),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "review"
    assert "tags" in summary.resource_changes[0].explanation


def test_gcp_container_cluster_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("google_container_cluster", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this GKE cluster" in summary.resource_changes[0].explanation


def test_gcp_container_cluster_replace_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("google_container_cluster", ["delete", "create"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "dangerous"
    assert "replace" in summary.resource_changes[0].explanation


def test_gcp_sql_database_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("google_sql_database_instance", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this Cloud SQL instance" in summary.resource_changes[0].explanation


def test_gcp_sql_database_version_major_change_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "google_sql_database_instance",
            ["update"],
            before={"database_version": "13"},
            after={"database_version": "15"},
        ),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "dangerous"
    assert "database_version" in summary.resource_changes[0].explanation


def test_gcp_storage_bucket_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("google_storage_bucket", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete a GCS bucket" in summary.resource_changes[0].explanation


def test_gcp_storage_bucket_delete_with_force_destroy_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "google_storage_bucket",
            ["delete"],
            before={"force_destroy": True},
        ),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "force_destroy" in summary.resource_changes[0].explanation


def test_gcp_storage_bucket_create_is_safe(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("google_storage_bucket", ["create"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "safe"
    assert "create a GCS bucket" in summary.resource_changes[0].explanation


def test_gcp_compute_firewall_delete_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("google_compute_firewall", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "firewall" in summary.resource_changes[0].explanation


# ---------------------------------------------------------------------------
# azurerm_* (Azure) provider tests
# ---------------------------------------------------------------------------


def test_azurerm_virtual_machine_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("azurerm_virtual_machine", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this Azure VM" in summary.resource_changes[0].explanation


def test_azurerm_virtual_machine_size_change_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "azurerm_virtual_machine",
            ["update"],
            before={"vm_size": "Standard_DS1_v2"},
            after={"vm_size": "Standard_DS3_v2"},
        ),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "dangerous"
    assert "size" in summary.resource_changes[0].explanation


def test_azurerm_kubernetes_cluster_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("azurerm_kubernetes_cluster", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this AKS cluster" in summary.resource_changes[0].explanation


def test_azurerm_storage_account_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("azurerm_storage_account", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this storage account" in summary.resource_changes[0].explanation


def test_azurerm_storage_account_update_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("azurerm_storage_account", ["update"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "review"
    assert "update this storage account" in summary.resource_changes[0].explanation


def test_azurerm_role_assignment_delete_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("azurerm_role_assignment", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete a role assignment" in summary.resource_changes[0].explanation


def test_azurerm_role_assignment_replace_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("azurerm_role_assignment", ["delete", "create"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "dangerous"
    assert "replace a role assignment" in summary.resource_changes[0].explanation


def test_azurerm_network_security_group_delete_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("azurerm_network_security_group", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "NSG" in summary.resource_changes[0].explanation


def test_azurerm_network_security_rule_update_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("azurerm_network_security_rule", ["update"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "review"
    assert "change a NSG rule" in summary.resource_changes[0].explanation


# ---------------------------------------------------------------------------
# kubernetes_* (K8s) provider tests
# ---------------------------------------------------------------------------


def test_k8s_deployment_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_deployment", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this Deployment" in summary.resource_changes[0].explanation


def test_k8s_deployment_replace_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_deployment", ["delete", "create"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "dangerous"
    assert "replace this Deployment" in summary.resource_changes[0].explanation


def test_k8s_deployment_update_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_deployment", ["update"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "review"
    assert "update this Deployment" in summary.resource_changes[0].explanation


def test_k8s_service_delete_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_service", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "Traffic routing" in summary.resource_changes[0].explanation


def test_k8s_ingress_delete_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_ingress", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this Ingress" in summary.resource_changes[0].explanation


def test_k8s_secret_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_secret", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this Secret" in summary.resource_changes[0].explanation


def test_k8s_secret_update_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_secret", ["update"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "dangerous"
    assert "change this Secret" in summary.resource_changes[0].explanation


def test_k8s_secret_create_is_dangerous(tmp_path: Path) -> None:
    """K8s Secret create should risk 'dangerous' with 'create this'."""
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_secret", ["create"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "dangerous"
    assert "create this Secret" in summary.resource_changes[0].explanation


def test_k8s_namespace_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_namespace", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this Namespace" in summary.resource_changes[0].explanation


def test_k8s_namespace_replace_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_namespace", ["delete", "create"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "dangerous"
    assert "replace this Namespace" in summary.resource_changes[0].explanation


def test_k8s_cluster_role_delete_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_cluster_role", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete a ClusterRole" in summary.resource_changes[0].explanation


def test_k8s_cluster_role_binding_update_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_cluster_role_binding", ["update"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "review"
    assert "change a ClusterRoleBinding" in summary.resource_changes[0].explanation


def test_k8s_role_binding_create_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_role_binding", ["create"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "review"
    assert "change a RoleBinding" in summary.resource_changes[0].explanation


def test_k8s_network_policy_delete_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_network_policy", ["delete"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete a NetworkPolicy" in summary.resource_changes[0].explanation


def test_k8s_network_policy_create_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("kubernetes_network_policy", ["create"]),
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].risk == "review"
    assert "change a NetworkPolicy" in summary.resource_changes[0].explanation


def test_registry_all_expected_rules_registered() -> None:
    """Verify every expected resource type has a registered rule function."""
    for rt, expected_func in _EXPECTED_RULE_FUNCTIONS.items():
        assert rt in _RULE_REGISTRY, (
            f"Resource type {rt!r} expected rule function {expected_func} "
            f"but is missing from _RULE_REGISTRY"
        )
        funcs = _RULE_REGISTRY[rt]
        names = [f.__name__ for f in funcs]
        assert expected_func in names, (
            f"Resource type {rt!r} has {names} but expected {expected_func}"
        )


def test_cross_cutting_rules_registered() -> None:
    """Verify the three cross-cutting rule functions are in _CROSS_CUTTING."""
    expected = {
        "_platform_service_candidates",
        "_network_topology_candidates",
        "_observability_candidates",
    }
    actual = {f.__name__ for f in _CROSS_CUTTING}
    missing = expected - actual
    assert not missing, f"Cross-cutting rules missing from _CROSS_CUTTING: {missing}"
