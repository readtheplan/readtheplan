from __future__ import annotations

import json
import re
from collections.abc import Mapping
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

_ISTIO_KIND_MAP: dict[tuple[str, str], str] = {
    ("networking.istio.io", "VirtualService"): "kubernetes_istio_virtual_service",
    ("networking.istio.io", "DestinationRule"): "kubernetes_istio_destination_rule",
    ("networking.istio.io", "Gateway"): "kubernetes_istio_gateway",
    ("networking.istio.io", "ServiceEntry"): "kubernetes_istio_service_entry",
    ("networking.istio.io", "Sidecar"): "kubernetes_istio_sidecar",
    ("networking.istio.io", "EnvoyFilter"): "kubernetes_istio_envoy_filter",
    ("networking.istio.io", "WorkloadEntry"): "kubernetes_istio_workload_entry",
    ("networking.istio.io", "WorkloadGroup"): "kubernetes_istio_workload_group",
    ("networking.istio.io", "ProxyConfig"): "kubernetes_istio_proxy_config",
    ("security.istio.io", "AuthorizationPolicy"): "kubernetes_istio_authorization_policy",
    ("security.istio.io", "PeerAuthentication"): "kubernetes_istio_peer_authentication",
    ("security.istio.io", "RequestAuthentication"): "kubernetes_istio_request_authentication",
    ("telemetry.istio.io", "Telemetry"): "kubernetes_istio_telemetry",
    ("extensions.istio.io", "WasmPlugin"): "kubernetes_istio_wasm_plugin",
}

_KYVERNO_KIND_MAP: dict[str, str] = {
    "ClusterPolicy": "kubernetes_kyverno_cluster_policy",
    "Policy": "kubernetes_kyverno_policy",
    "ValidatingPolicy": "kubernetes_kyverno_validating_policy",
    "NamespacedValidatingPolicy": "kubernetes_kyverno_namespaced_validating_policy",
    "MutatingPolicy": "kubernetes_kyverno_mutating_policy",
    "NamespacedMutatingPolicy": "kubernetes_kyverno_namespaced_mutating_policy",
    "GeneratingPolicy": "kubernetes_kyverno_generating_policy",
    "NamespacedGeneratingPolicy": "kubernetes_kyverno_namespaced_generating_policy",
    "DeletingPolicy": "kubernetes_kyverno_deleting_policy",
    "NamespacedDeletingPolicy": "kubernetes_kyverno_namespaced_deleting_policy",
    "ImageValidatingPolicy": "kubernetes_kyverno_image_validating_policy",
    "NamespacedImageValidatingPolicy": "kubernetes_kyverno_namespaced_image_validating_policy",
    "CleanupPolicy": "kubernetes_kyverno_cleanup_policy",
    "ClusterCleanupPolicy": "kubernetes_kyverno_cluster_cleanup_policy",
    "PolicyException": "kubernetes_kyverno_policy_exception",
}

_GATEKEEPER_KIND_MAP: dict[tuple[str, str], str] = {
    ("templates.gatekeeper.sh", "ConstraintTemplate"): "kubernetes_gatekeeper_constraint_template",
    ("config.gatekeeper.sh", "Config"): "kubernetes_gatekeeper_config",
    ("mutations.gatekeeper.sh", "Assign"): "kubernetes_gatekeeper_assign",
    ("mutations.gatekeeper.sh", "AssignMetadata"): "kubernetes_gatekeeper_assign_metadata",
    ("mutations.gatekeeper.sh", "ModifySet"): "kubernetes_gatekeeper_modify_set",
    ("mutations.gatekeeper.sh", "AssignImage"): "kubernetes_gatekeeper_assign_image",
    ("expansion.gatekeeper.sh", "ExpansionTemplate"): "kubernetes_gatekeeper_expansion_template",
    ("syncset.gatekeeper.sh", "SyncSet"): "kubernetes_gatekeeper_sync_set",
    ("externaldata.gatekeeper.sh", "Provider"): "kubernetes_gatekeeper_external_data_provider",
}

_KEDA_KIND_MAP: dict[str, str] = {
    "ScaledObject": "kubernetes_keda_scaled_object",
    "ScaledJob": "kubernetes_keda_scaled_job",
    "TriggerAuthentication": "kubernetes_keda_trigger_authentication",
    "ClusterTriggerAuthentication": "kubernetes_keda_cluster_trigger_authentication",
    "CloudEventSource": "kubernetes_keda_cloud_event_source",
}

_KNATIVE_KIND_MAP: dict[tuple[str, str], str] = {
    ("serving.knative.dev", "Service"): "kubernetes_knative_service",
    ("serving.knative.dev", "Route"): "kubernetes_knative_route",
    ("serving.knative.dev", "Configuration"): "kubernetes_knative_configuration",
    ("serving.knative.dev", "Revision"): "kubernetes_knative_revision",
    ("eventing.knative.dev", "Broker"): "kubernetes_knative_broker",
    ("eventing.knative.dev", "Trigger"): "kubernetes_knative_trigger",
    ("eventing.knative.dev", "EventPolicy"): "kubernetes_knative_event_policy",
    ("eventing.knative.dev", "EventTransform"): "kubernetes_knative_event_transform",
    ("eventing.knative.dev", "RequestReply"): "kubernetes_knative_request_reply",
    ("messaging.knative.dev", "Channel"): "kubernetes_knative_channel",
    ("messaging.knative.dev", "InMemoryChannel"): "kubernetes_knative_in_memory_channel",
    ("messaging.knative.dev", "Subscription"): "kubernetes_knative_subscription",
    ("flows.knative.dev", "Sequence"): "kubernetes_knative_sequence",
    ("flows.knative.dev", "Parallel"): "kubernetes_knative_parallel",
}

_CLUSTER_API_KIND_MAP: dict[tuple[str, str], str] = {
    ("cluster.x-k8s.io", "Cluster"): "kubernetes_capi_cluster",
    ("cluster.x-k8s.io", "ClusterClass"): "kubernetes_capi_cluster_class",
    ("cluster.x-k8s.io", "Machine"): "kubernetes_capi_machine",
    ("cluster.x-k8s.io", "MachineSet"): "kubernetes_capi_machine_set",
    ("cluster.x-k8s.io", "MachineDeployment"): "kubernetes_capi_machine_deployment",
    ("cluster.x-k8s.io", "MachinePool"): "kubernetes_capi_machine_pool",
    ("cluster.x-k8s.io", "MachineHealthCheck"): "kubernetes_capi_machine_health_check",
    ("cluster.x-k8s.io", "MachineDrainRule"): "kubernetes_capi_machine_drain_rule",
    (
        "controlplane.cluster.x-k8s.io",
        "KubeadmControlPlane",
    ): "kubernetes_capi_kubeadm_control_plane",
    (
        "controlplane.cluster.x-k8s.io",
        "KubeadmControlPlaneTemplate",
    ): "kubernetes_capi_kubeadm_control_plane_template",
    ("bootstrap.cluster.x-k8s.io", "KubeadmConfig"): "kubernetes_capi_kubeadm_config",
    (
        "bootstrap.cluster.x-k8s.io",
        "KubeadmConfigTemplate",
    ): "kubernetes_capi_kubeadm_config_template",
    ("runtime.cluster.x-k8s.io", "ExtensionConfig"): "kubernetes_capi_extension_config",
    (
        "addons.cluster.x-k8s.io",
        "ClusterResourceSet",
    ): "kubernetes_capi_cluster_resource_set",
    (
        "addons.cluster.x-k8s.io",
        "ClusterResourceSetBinding",
    ): "kubernetes_capi_cluster_resource_set_binding",
    ("ipam.cluster.x-k8s.io", "IPAddress"): "kubernetes_capi_ip_address",
    ("ipam.cluster.x-k8s.io", "IPAddressClaim"): "kubernetes_capi_ip_address_claim",
}

_KARPENTER_KIND_MAP: dict[tuple[str, str], str] = {
    ("karpenter.sh", "NodePool"): "kubernetes_karpenter_node_pool",
    ("karpenter.sh", "NodeClaim"): "kubernetes_karpenter_node_claim",
    ("karpenter.sh", "Provisioner"): "kubernetes_karpenter_legacy_provisioner",
    ("karpenter.k8s.aws", "EC2NodeClass"): "kubernetes_karpenter_node_class",
    ("karpenter.k8s.aws", "AWSNodeTemplate"): "kubernetes_karpenter_legacy_node_template",
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
        "ClusterPolicy",
        "ClusterCleanupPolicy",
        "ValidatingPolicy",
        "MutatingPolicy",
        "GeneratingPolicy",
        "DeletingPolicy",
        "ImageValidatingPolicy",
        "ClusterTriggerAuthentication",
    }
)


class KubernetesInputError(ValueError):
    """Raised when text is not a supported Kubernetes JSON or YAML artifact."""


def _manifest_resources(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    if not isinstance(value, dict) or "kind" not in value:
        return []
    if value.get("kind") == "List" and isinstance(value.get("items"), list):
        return list(value["items"])
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
    kind = r.get("kind", "Unknown")
    return kind.strip() if isinstance(kind, str) and kind.strip() else "Unknown"


def _api_version_from_resource(r: dict[str, Any]) -> str:
    return str(r.get("apiVersion", ""))


def _name_from_resource(r: dict[str, Any]) -> str:
    metadata = r.get("metadata", {})
    if not isinstance(metadata, Mapping):
        return "<unnamed>"
    name = metadata.get("name", "<unnamed>")
    return name.strip() if isinstance(name, str) and name.strip() else "<unnamed>"


def _namespace_from_resource(r: dict[str, Any]) -> str | None:
    kind = _kind_from_resource(r)
    api_group = _api_version_from_resource(r).partition("/")[0]
    if api_group == "karpenter.sh" or api_group.startswith("karpenter."):
        return None
    if kind in _CLUSTER_SCOPED_KINDS:
        return None
    metadata = r.get("metadata", {})
    if not isinstance(metadata, Mapping):
        return None
    namespace = metadata.get("namespace")
    return namespace.strip() if isinstance(namespace, str) and namespace.strip() else None


def _get_properties_for_rules(r: dict[str, Any]) -> dict[str, Any]:
    """Extract the properties subset that the rules engine cares about."""
    meta = r.get("metadata", {})
    if not isinstance(meta, Mapping):
        meta = {}
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
            return True
        return False

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        if "old_manifests" in input_data and "new_manifests" in input_data:
            return self._extract_from_diff(input_data)
        if "resources" in input_data:
            return self._extract_from_single(input_data)
        return []

    def _extract_from_diff(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        old_manifests = data.get("old_manifests", [])
        new_manifests = data.get("new_manifests", [])
        if not isinstance(old_manifests, list) or not isinstance(new_manifests, list):
            return [self._malformed_input_change()]
        if not all(isinstance(r, Mapping) for r in (*old_manifests, *new_manifests)):
            return [self._malformed_input_change()]
        if not all(self._has_valid_diff_identity(r) for r in (*old_manifests, *new_manifests)):
            return [self._malformed_input_change()]

        old_ids = [self._validated_identity(r) for r in old_manifests]
        new_ids = [self._validated_identity(r) for r in new_manifests]
        if len(set(old_ids)) != len(old_ids) or len(set(new_ids)) != len(new_ids):
            return [self._malformed_input_change()]

        # Build identity maps
        old_by_id: dict[tuple[str, str, str], dict[str, Any]] = {}
        for r in old_manifests:
            if (not isinstance(r, Mapping) or "kind" not in r
                    or not isinstance(r.get("metadata", {}), Mapping)):
                continue
            kid = _kind_from_resource(r)
            name = _name_from_resource(r)
            ns = _namespace_from_resource(r)
            key = _resource_identity(kid, name, ns)
            old_by_id[key] = r

        new_by_id: dict[tuple[str, str, str], dict[str, Any]] = {}
        for r in new_manifests:
            if (not isinstance(r, Mapping) or "kind" not in r
                    or not isinstance(r.get("metadata", {}), Mapping)):
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
                        "adapter": "kubernetes",
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
                        "adapter": "kubernetes",
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
                            "adapter": "kubernetes",
                            "before": old_props,
                            "after": new_props,
                        },
                    }
                )

        return changes

    def _extract_from_single(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        changes = []
        resources = data.get("resources", [])
        if not isinstance(resources, list):
            return [self._malformed_input_change()]
        if not all(
            isinstance(r, Mapping)
            and isinstance(r.get("kind"), str)
            and bool(r["kind"].strip())
            and isinstance(r.get("metadata", {}), Mapping)
            for r in resources
        ):
            return [self._malformed_input_change()]
        for r in resources:
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
                        "adapter": "kubernetes",
                        "before": {},
                        "after": properties,
                    },
                }
            )
        if resources and not changes:
            return [self._malformed_input_change()]
        return changes

    @staticmethod
    def _has_valid_diff_identity(resource: Mapping[str, Any]) -> bool:
        kind = resource.get("kind")
        metadata = resource.get("metadata")
        if not isinstance(kind, str) or not kind.strip() or not isinstance(metadata, Mapping):
            return False
        name = metadata.get("name")
        if not isinstance(name, str) or not name.strip():
            return False
        namespace = metadata.get("namespace")
        return namespace is None or isinstance(namespace, str)

    @staticmethod
    def _validated_identity(resource: Mapping[str, Any]) -> tuple[str, str, str]:
        return _resource_identity(
            _kind_from_resource(resource),
            _name_from_resource(resource),
            _namespace_from_resource(resource),
        )

    @staticmethod
    def _malformed_input_change() -> dict[str, Any]:
        return {
            "Action": "Unknown",
            "Kind": "Unknown",
            "ResourceType": "Unknown",
            "LogicalResourceId": "<malformed-input>",
            "Namespace": None,
            "Replacement": "False",
        }

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

        malformed_identity = kind == "Unknown" or logical_id in {
            "<unnamed>", "<unknown>", "<malformed-input>",
        }
        if malformed_identity:
            explanation = "Malformed Kubernetes resource input requires review."
        elif action == "Add":
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
        if not isinstance(kind, str) or not kind or kind == "Unknown":
            return "unknown"
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
        istio_type = _ISTIO_KIND_MAP.get((api_group, kind)) if separator else None
        if istio_type:
            return istio_type
        if separator and api_group in {"kyverno.io", "policies.kyverno.io"}:
            kyverno_type = _KYVERNO_KIND_MAP.get(kind)
            if kyverno_type:
                return kyverno_type
        gatekeeper_type = _GATEKEEPER_KIND_MAP.get((api_group, kind)) if separator else None
        if gatekeeper_type:
            return gatekeeper_type
        if separator and api_group == "constraints.gatekeeper.sh":
            return "kubernetes_gatekeeper_constraint"
        if separator and api_group in {"keda.sh", "eventing.keda.sh"}:
            keda_type = _KEDA_KIND_MAP.get(kind)
            if keda_type:
                return keda_type
        knative_type = _KNATIVE_KIND_MAP.get((api_group, kind)) if separator else None
        if knative_type:
            return knative_type
        if separator and api_group == "sources.knative.dev":
            return "kubernetes_knative_event_source"
        cluster_api_type = (
            _CLUSTER_API_KIND_MAP.get((api_group, kind)) if separator else None
        )
        if cluster_api_type:
            return cluster_api_type
        if separator and api_group == "infrastructure.cluster.x-k8s.io":
            normalized_kind = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", kind)
            normalized_kind = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", normalized_kind).lower()
            return f"kubernetes_capi_infrastructure_{normalized_kind}"
        karpenter_type = _KARPENTER_KIND_MAP.get((api_group, kind)) if separator else None
        if karpenter_type:
            return karpenter_type
        if separator and api_group.startswith("karpenter.") and kind.endswith("NodeClass"):
            return "kubernetes_karpenter_node_class"
        mapped = _K8S_KIND_MAP.get(kind)
        if mapped:
            return mapped
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
