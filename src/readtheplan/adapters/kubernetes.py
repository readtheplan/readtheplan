from __future__ import annotations

import json
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.plan import ResourceChange

_K8S_KIND_MAP: dict[str, str] = {
    "Deployment": "kubernetes_deployment",
    "Service": "kubernetes_service",
    "Ingress": "kubernetes_ingress",
    "Secret": "kubernetes_secret",
    "ConfigMap": "kubernetes_config_map",
    "Namespace": "kubernetes_namespace",
    "ClusterRole": "kubernetes_cluster_role",
    "ClusterRoleBinding": "kubernetes_cluster_role_binding",
    "RoleBinding": "kubernetes_role_binding",
    "Role": "kubernetes_role",
    "NetworkPolicy": "kubernetes_network_policy",
    "PersistentVolumeClaim": "kubernetes_persistent_volume_claim",
    "StatefulSet": "kubernetes_stateful_set",
    "DaemonSet": "kubernetes_daemon_set",
    "Job": "kubernetes_job",
    "CronJob": "kubernetes_cron_job",
    "HorizontalPodAutoscaler": "kubernetes_horizontal_pod_autoscaler",
    "Pod": "kubernetes_pod",
    "Node": "kubernetes_node",
    "StorageClass": "kubernetes_storage_class",
    "PersistentVolume": "kubernetes_persistent_volume",
    "ServiceAccount": "kubernetes_service_account",
    "PriorityClass": "kubernetes_priority_class",
    "CustomResourceDefinition": "kubernetes_custom_resource_definition",
    "MutatingWebhookConfiguration": "kubernetes_mutating_webhook_configuration",
    "ValidatingWebhookConfiguration": "kubernetes_validating_webhook_configuration",
    "APIService": "kubernetes_api_service",
}

_SENSITIVE_CONTROL_PLANE_KINDS = frozenset(
    {
        "APIService",
        "CustomResourceDefinition",
        "MutatingWebhookConfiguration",
        "ValidatingWebhookConfiguration",
    }
)

_ARGO_KIND_MAP: dict[str, str] = {
    "Application": "kubernetes_argocd_application",
    "ApplicationSet": "kubernetes_argocd_application_set",
    "AppProject": "kubernetes_argocd_project",
    "Rollout": "kubernetes_deployment",
    "AnalysisTemplate": "kubernetes_argocd_analysis_template",
    "ClusterAnalysisTemplate": "kubernetes_argocd_cluster_analysis_template",
    "Workflow": "kubernetes_argo_workflow",
    "WorkflowTemplate": "kubernetes_argo_workflow_template",
    "ClusterWorkflowTemplate": "kubernetes_argo_cluster_workflow_template",
    "CronWorkflow": "kubernetes_argo_cron_workflow",
    "WorkflowEventBinding": "kubernetes_argo_workflow_event_binding",
    "WorkflowTaskSet": "kubernetes_argo_workflow_task_set",
    "EventSource": "kubernetes_argo_event_source",
    "Sensor": "kubernetes_argo_sensor",
    "EventBus": "kubernetes_argo_event_bus",
}

_GATEWAY_API_KIND_MAP: dict[str, str] = {
    "GatewayClass": "kubernetes_gateway_class",
    "Gateway": "kubernetes_gateway",
    "HTTPRoute": "kubernetes_gateway_http_route",
    "GRPCRoute": "kubernetes_gateway_grpc_route",
    "TLSRoute": "kubernetes_gateway_tls_route",
    "TCPRoute": "kubernetes_gateway_tcp_route",
    "UDPRoute": "kubernetes_gateway_udp_route",
    "ReferenceGrant": "kubernetes_gateway_reference_grant",
    "BackendTLSPolicy": "kubernetes_gateway_backend_tls_policy",
    "ListenerSet": "kubernetes_gateway_listener_set",
}

_CERT_MANAGER_KIND_MAP: dict[tuple[str, str], str] = {
    ("cert-manager.io", "Certificate"): "kubernetes_cert_manager_certificate",
    ("cert-manager.io", "Issuer"): "kubernetes_cert_manager_issuer",
    ("cert-manager.io", "ClusterIssuer"): "kubernetes_cert_manager_cluster_issuer",
    ("cert-manager.io", "CertificateRequest"): "kubernetes_cert_manager_certificate_request",
    ("acme.cert-manager.io", "Order"): "kubernetes_cert_manager_acme_order",
    ("acme.cert-manager.io", "Challenge"): "kubernetes_cert_manager_acme_challenge",
    ("trust.cert-manager.io", "Bundle"): "kubernetes_cert_manager_trust_bundle",
}

_EXTERNAL_SECRETS_KIND_MAP: dict[str, str] = {
    "ExternalSecret": "kubernetes_external_secrets_external_secret",
    "SecretStore": "kubernetes_external_secrets_secret_store",
    "ClusterSecretStore": "kubernetes_external_secrets_cluster_secret_store",
    "ClusterExternalSecret": "kubernetes_external_secrets_cluster_external_secret",
    "PushSecret": "kubernetes_external_secrets_push_secret",
    "ClusterPushSecret": "kubernetes_external_secrets_cluster_push_secret",
}

_FLUX_KIND_MAP: dict[tuple[str, str], str] = {
    ("source.toolkit.fluxcd.io", "GitRepository"): "kubernetes_flux_git_repository",
    ("source.toolkit.fluxcd.io", "OCIRepository"): "kubernetes_flux_oci_repository",
    ("source.toolkit.fluxcd.io", "Bucket"): "kubernetes_flux_bucket",
    ("source.toolkit.fluxcd.io", "HelmRepository"): "kubernetes_flux_helm_repository",
    ("source.toolkit.fluxcd.io", "HelmChart"): "kubernetes_flux_helm_chart",
    ("kustomize.toolkit.fluxcd.io", "Kustomization"): "kubernetes_flux_kustomization",
    ("helm.toolkit.fluxcd.io", "HelmRelease"): "kubernetes_flux_helm_release",
    ("image.toolkit.fluxcd.io", "ImageRepository"): "kubernetes_flux_image_repository",
    ("image.toolkit.fluxcd.io", "ImagePolicy"): "kubernetes_flux_image_policy",
    (
        "image.toolkit.fluxcd.io",
        "ImageUpdateAutomation",
    ): "kubernetes_flux_image_update_automation",
    ("notification.toolkit.fluxcd.io", "Receiver"): "kubernetes_flux_receiver",
    ("notification.toolkit.fluxcd.io", "Provider"): "kubernetes_flux_provider",
    ("notification.toolkit.fluxcd.io", "Alert"): "kubernetes_flux_alert",
}

_TEKTON_KIND_MAP: dict[tuple[str, str], str] = {
    ("tekton.dev", "Task"): "kubernetes_tekton_task",
    ("tekton.dev", "ClusterTask"): "kubernetes_tekton_cluster_task",
    ("tekton.dev", "Pipeline"): "kubernetes_tekton_pipeline",
    ("tekton.dev", "TaskRun"): "kubernetes_tekton_task_run",
    ("tekton.dev", "PipelineRun"): "kubernetes_tekton_pipeline_run",
    ("tekton.dev", "Run"): "kubernetes_tekton_run",
    ("tekton.dev", "CustomRun"): "kubernetes_tekton_custom_run",
    ("tekton.dev", "StepAction"): "kubernetes_tekton_step_action",
    ("tekton.dev", "PipelineResource"): "kubernetes_tekton_pipeline_resource",
    ("triggers.tekton.dev", "EventListener"): "kubernetes_tekton_event_listener",
    ("triggers.tekton.dev", "Trigger"): "kubernetes_tekton_trigger",
    ("triggers.tekton.dev", "TriggerTemplate"): "kubernetes_tekton_trigger_template",
    ("triggers.tekton.dev", "TriggerBinding"): "kubernetes_tekton_trigger_binding",
    (
        "triggers.tekton.dev",
        "ClusterTriggerBinding",
    ): "kubernetes_tekton_cluster_trigger_binding",
    (
        "triggers.tekton.dev",
        "ClusterInterceptor",
    ): "kubernetes_tekton_cluster_interceptor",
    (
        "resolution.tekton.dev",
        "ResolutionRequest",
    ): "kubernetes_tekton_resolution_request",
}

_CLUSTER_SCOPED_KINDS = frozenset(
    {
        "ClusterRole",
        "ClusterRoleBinding",
        "Namespace",
        "Node",
        "StorageClass",
        "PersistentVolume",
        "PriorityClass",
        *_SENSITIVE_CONTROL_PLANE_KINDS,
        "ClusterAnalysisTemplate",
        "ClusterTask",
        "ClusterTriggerBinding",
        "ClusterInterceptor",
        "ClusterWorkflowTemplate",
        "GatewayClass",
        "ClusterIssuer",
        "Bundle",
        "ClusterSecretStore",
        "ClusterExternalSecret",
        "ClusterPushSecret",
        "ClusterGenerator",
    }
)


class KubernetesInputError(ValueError):
    """Raised when text is not a supported Kubernetes JSON or YAML artifact."""


def _manifest_resources(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict) and "kind" in item]
    if not isinstance(value, dict) or "kind" not in value:
        return []
    if value.get("kind") == "List" and isinstance(value.get("items"), list):
        return [item for item in value["items"] if isinstance(item, dict) and "kind" in item]
    return [value]


def parse_kubernetes_input(source: str) -> dict[str, Any]:
    """Parse wrapper JSON/YAML, a manifest list, or multi-document YAML."""
    try:
        data = json.loads(source)
    except json.JSONDecodeError:
        try:
            documents = list(yaml.safe_load_all(source))
        except yaml.YAMLError as exc:
            raise KubernetesInputError(f"invalid YAML: {exc}") from exc
        if not any(document is not None for document in documents):
            raise KubernetesInputError("manifest input is empty")
        if len(documents) == 1 and isinstance(documents[0], dict):
            document = documents[0]
            if "old_manifests" in document or "new_manifests" in document:
                return document
        resources = [
            resource for document in documents for resource in _manifest_resources(document)
        ]
        if not resources:
            raise KubernetesInputError("no Kubernetes resources were found")
        return {"resources": resources}

    if isinstance(data, dict):
        resources = _manifest_resources(data)
        return {"resources": resources} if resources else data
    resources = _manifest_resources(data)
    if resources:
        return {"resources": resources}
    raise KubernetesInputError("input must be a manifest, resource list, or diff object")


def _resource_identity(kind: str, name: str, namespace: str | None) -> tuple[str, str, str]:
    """Build a stable identity key for matching resources across diff manifests."""
    ns = namespace or ""
    return (kind, name, ns)


def _kind_from_resource(r: dict[str, Any]) -> str:
    return r.get("kind", "Unknown")


def _api_version_from_resource(r: dict[str, Any]) -> str:
    return str(r.get("apiVersion", ""))


def _name_from_resource(r: dict[str, Any]) -> str:
    return r.get("metadata", {}).get("name", "<unnamed>")


def _namespace_from_resource(r: dict[str, Any]) -> str | None:
    kind = _kind_from_resource(r)
    if kind in _CLUSTER_SCOPED_KINDS:
        return None
    return r.get("metadata", {}).get("namespace", None)


def _get_properties_for_rules(r: dict[str, Any]) -> dict[str, Any]:
    """Extract the properties subset that the rules engine cares about."""
    meta = r.get("metadata", {})
    return {
        "metadata": {
            "labels": meta.get("labels", {}),
            "annotations": meta.get("annotations", {}),
        },
        "spec": r.get("spec", {}),
        "data": r.get("data", {}),
        "rules": r.get("rules", []),
        "roleRef": r.get("roleRef", {}),
        "subjects": r.get("subjects", []),
        "stringData": r.get("stringData", {}),
        "binaryData": r.get("binaryData", {}),
        "aggregationRule": r.get("aggregationRule", {}),
        "type": r.get("type"),
    }


class KubernetesAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "kubernetes"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        # Format 1: old_manifests / new_manifests diff
        if "old_manifests" in input_data and "new_manifests" in input_data:
            if isinstance(input_data["old_manifests"], list) or isinstance(
                input_data["new_manifests"], list
            ):  # noqa: E501
                return True
        # Format 2: single resources array
        if "resources" in input_data and isinstance(input_data["resources"], list):
            for r in input_data["resources"]:
                if "kind" in r:
                    return True
        return False

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        if "old_manifests" in input_data and "new_manifests" in input_data:
            return self._extract_from_diff(input_data)
        if "resources" in input_data:
            return self._extract_from_single(input_data)
        return []

    def _extract_from_diff(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        old_manifests = data.get("old_manifests", []) or []
        new_manifests = data.get("new_manifests", []) or []

        # Build identity maps
        old_by_id: dict[tuple[str, str, str], dict[str, Any]] = {}
        for r in old_manifests:
            if not isinstance(r, dict) or "kind" not in r:
                continue
            kid = _kind_from_resource(r)
            name = _name_from_resource(r)
            ns = _namespace_from_resource(r)
            key = _resource_identity(kid, name, ns)
            old_by_id[key] = r

        new_by_id: dict[tuple[str, str, str], dict[str, Any]] = {}
        for r in new_manifests:
            if not isinstance(r, dict) or "kind" not in r:
                continue
            kid = _kind_from_resource(r)
            name = _name_from_resource(r)
            ns = _namespace_from_resource(r)
            key = _resource_identity(kid, name, ns)
            new_by_id[key] = r

        changes: list[dict[str, Any]] = []

        # Added resources (in new but not in old)
        added_ids = set(new_by_id.keys()) - set(old_by_id.keys())
        for key in added_ids:
            r = new_by_id[key]
            properties = _get_properties_for_rules(r)
            changes.append(
                {
                    "Action": "Add",
                    "Kind": _kind_from_resource(r),
                    "ApiVersion": _api_version_from_resource(r),
                    "ResourceType": _kind_from_resource(r),
                    "LogicalResourceId": _name_from_resource(r),
                    "Namespace": _namespace_from_resource(r),
                    "Replacement": "False",
                    "Spec": r.get("spec", {}),
                    "Data": r.get("data", {}),
                    "_metadata": {
                        "before": {},
                        "after": properties,
                    },
                }
            )

        # Removed resources (in old but not in new)
        removed_ids = set(old_by_id.keys()) - set(new_by_id.keys())
        for key in removed_ids:
            r = old_by_id[key]
            properties = _get_properties_for_rules(r)
            changes.append(
                {
                    "Action": "Remove",
                    "Kind": _kind_from_resource(r),
                    "ApiVersion": _api_version_from_resource(r),
                    "ResourceType": _kind_from_resource(r),
                    "LogicalResourceId": _name_from_resource(r),
                    "Namespace": _namespace_from_resource(r),
                    "Replacement": "False",
                    "Spec": r.get("spec", {}),
                    "Data": r.get("data", {}),
                    "_metadata": {
                        "before": properties,
                        "after": {},
                    },
                }
            )

        # Modified resources (in both — check for spec/data changes)
        common_ids = set(old_by_id.keys()) & set(new_by_id.keys())
        for key in common_ids:
            old_r = old_by_id[key]
            new_r = new_by_id[key]
            old_props = _get_properties_for_rules(old_r)
            new_props = _get_properties_for_rules(new_r)

            if old_props != new_props:
                changes.append(
                    {
                        "Action": "Modify",
                        "Kind": _kind_from_resource(new_r),
                        "ApiVersion": _api_version_from_resource(new_r),
                        "ResourceType": _kind_from_resource(new_r),
                        "LogicalResourceId": _name_from_resource(new_r),
                        "Namespace": _namespace_from_resource(new_r),
                        "Replacement": "Conditional",
                        "_metadata": {
                            "before": old_props,
                            "after": new_props,
                        },
                    }
                )

        return changes

    def _extract_from_single(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        changes = []
        for r in data.get("resources", []):
            if not isinstance(r, dict) or "kind" not in r:
                continue
            properties = _get_properties_for_rules(r)
            changes.append(
                {
                    "Action": "Add",
                    "Kind": _kind_from_resource(r),
                    "ApiVersion": _api_version_from_resource(r),
                    "ResourceType": _kind_from_resource(r),
                    "LogicalResourceId": _name_from_resource(r),
                    "Namespace": _namespace_from_resource(r),
                    "Replacement": "False",
                    "Spec": r.get("spec", {}),
                    "Data": r.get("data", {}),
                    "_metadata": {
                        "before": {},
                        "after": properties,
                    },
                }
            )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        action = raw.get("Action", "Unknown")
        replacement = str(raw.get("Replacement", "False"))
        kind = raw.get("Kind", "Unknown")
        api_version = str(raw.get("ApiVersion", ""))
        logical_id = raw.get("LogicalResourceId", "<unknown>")
        namespace = raw.get("Namespace")
        address = f"{namespace}/{logical_id}" if namespace else logical_id

        risk = "review"
        actions = ("unknown",)
        explanation = f"Kubernetes action '{action}' on {kind} requires review."

        if action == "Add":
            actions = ("create",)
            if kind in _SENSITIVE_CONTROL_PLANE_KINDS:
                risk = "dangerous"
                explanation = (
                    f"Kubernetes will create control-plane extension {kind} "
                    f"'{logical_id}'. Review API and admission impact."
                )
            elif kind not in _K8S_KIND_MAP:
                risk = "review"
                explanation = (
                    f"Kubernetes will create custom resource {kind} '{logical_id}'. "
                    "Review the owning controller and reconciliation effects."
                )
            else:
                risk = "safe"
                explanation = f"Kubernetes will create {kind} '{logical_id}'."
        elif action == "Modify":
            if replacement == "True":
                risk = "dangerous"
                actions = ("delete", "create")
                explanation = (
                    f"Kubernetes will replace {kind} '{logical_id}' (destroy and recreate)."  # noqa: E501
                )
            elif replacement == "Conditional":
                risk = "review"
                actions = ("update",)
                explanation = f"Kubernetes will update {kind} '{logical_id}'. Review the spec changes before applying."  # noqa: E501
            else:
                risk = "review"
                actions = ("update",)
                explanation = f"Kubernetes will update {kind} '{logical_id}' in place."
            if kind in _SENSITIVE_CONTROL_PLANE_KINDS:
                risk = "dangerous"
                explanation = (
                    f"Kubernetes will update control-plane extension {kind} "
                    f"'{logical_id}'. Review API and admission impact."
                )
        elif action == "Remove":
            risk = "irreversible"
            actions = ("delete",)
            explanation = f"Kubernetes will delete {kind} '{logical_id}'."

        normalized_type = self._normalize_resource_type(kind, api_version)

        return ResourceChange(
            address=address,
            resource_type=normalized_type,
            actions=actions,
            risk=risk,
            explanation=explanation,
        )

    def _normalize_resource_type(self, kind: str, api_version: str = "") -> str:
        api_group, separator, _version = api_version.partition("/")
        if separator and api_group == "argoproj.io" and kind in _ARGO_KIND_MAP:
            return _ARGO_KIND_MAP[kind]
        flux_type = _FLUX_KIND_MAP.get((api_group, kind)) if separator else None
        if flux_type:
            return flux_type
        tekton_type = _TEKTON_KIND_MAP.get((api_group, kind)) if separator else None
        if tekton_type:
            return tekton_type
        if separator and api_group in {
            "gateway.networking.k8s.io",
            "gateway.networking.x-k8s.io",
        }:
            gateway_type = _GATEWAY_API_KIND_MAP.get(kind)
            if gateway_type:
                return gateway_type
        cert_manager_type = _CERT_MANAGER_KIND_MAP.get((api_group, kind)) if separator else None
        if cert_manager_type:
            return cert_manager_type
        if separator and api_group == "external-secrets.io":
            external_secrets_type = _EXTERNAL_SECRETS_KIND_MAP.get(kind)
            if external_secrets_type:
                return external_secrets_type
        if separator and api_group == "generators.external-secrets.io":
            return "kubernetes_external_secrets_generator"
        mapped = _K8S_KIND_MAP.get(kind)
        if mapped:
            return mapped
        if not kind or not isinstance(kind, str):
            return "unknown"
        return f"kubernetes_{kind.lower()}"


def analyze_kubernetes(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    """Analyze a Kubernetes manifest diff via the shared rtp-agent-gate-v1 contract.

    Accepts:
      - {"old_manifests": [...], "new_manifests": [...]} — diff format
      - {"resources": [...]} — single manifest format

    Returns the full agent-gate dict (schema, decision, risk, required_checks,
    allowed_next_actions, prohibited_next_actions, reason, pr_comment,
    evidence_checklist, auditor_summary, risk_counts).
    """
    from pathlib import Path

    from readtheplan.agent_gate import agent_gate_to_dict
    from readtheplan.plan import PlanSummary

    adapter = KubernetesAdapter()
    changes = adapter.analyze(data, tool_name="Kubernetes")

    summary = PlanSummary(
        path=Path("kubernetes://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )

    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Kubernetes")
    gate["adapter"] = "kubernetes"
    gate["total_changes"] = len(changes)

    return gate
