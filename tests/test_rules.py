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
    "kubernetes_deployment": "_k8s_deployment_candidates",
    "kubernetes_service": "_k8s_service_candidates",
    "kubernetes_ingress": "_k8s_service_candidates",
    "kubernetes_secret": "_k8s_secret_candidates",
    "kubernetes_namespace": "_k8s_namespace_candidates",
    "kubernetes_cluster_role": "_k8s_rbac_candidates",
    "kubernetes_role": "_k8s_rbac_candidates",
    "kubernetes_cluster_role_binding": "_k8s_rbac_candidates",
    "kubernetes_role_binding": "_k8s_rbac_candidates",
    "kubernetes_network_policy": "_k8s_network_policy_candidates",
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
