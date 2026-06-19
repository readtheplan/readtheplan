from __future__ import annotations

import copy
from typing import Any

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
    }
)


def _resource_identity(kind: str, name: str, namespace: str | None) -> tuple[str, str, str]:
    """Build a stable identity key for matching resources across diff manifests."""
    ns = namespace or ""
    return (kind, name, ns)


def _kind_from_resource(r: dict[str, Any]) -> str:
    return r.get("kind", "Unknown")


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
    }


class KubernetesAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "kubernetes"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        # Format 1: old_manifests / new_manifests diff
        if "old_manifests" in input_data and "new_manifests" in input_data:
            if isinstance(input_data["old_manifests"], list) or isinstance(input_data["new_manifests"], list):
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
            changes.append({
                "Action": "Add",
                "Kind": _kind_from_resource(r),
                "ResourceType": _kind_from_resource(r),
                "LogicalResourceId": _name_from_resource(r),
                "Namespace": _namespace_from_resource(r),
                "Replacement": "False",
                "Spec": r.get("spec", {}),
                "Data": r.get("data", {}),
            })

        # Removed resources (in old but not in new)
        removed_ids = set(old_by_id.keys()) - set(new_by_id.keys())
        for key in removed_ids:
            r = old_by_id[key]
            changes.append({
                "Action": "Remove",
                "Kind": _kind_from_resource(r),
                "ResourceType": _kind_from_resource(r),
                "LogicalResourceId": _name_from_resource(r),
                "Namespace": _namespace_from_resource(r),
                "Replacement": "False",
                "Spec": r.get("spec", {}),
                "Data": r.get("data", {}),
            })

        # Modified resources (in both — check for spec/data changes)
        common_ids = set(old_by_id.keys()) & set(new_by_id.keys())
        for key in common_ids:
            old_r = old_by_id[key]
            new_r = new_by_id[key]
            old_props = _get_properties_for_rules(old_r)
            new_props = _get_properties_for_rules(new_r)

            if old_props != new_props:
                changes.append({
                    "Action": "Modify",
                    "Kind": _kind_from_resource(new_r),
                    "ResourceType": _kind_from_resource(new_r),
                    "LogicalResourceId": _name_from_resource(new_r),
                    "Namespace": _namespace_from_resource(new_r),
                    "Replacement": "Conditional",
                    "_metadata": {
                        "before": old_props,
                        "after": new_props,
                    },
                })

        return changes

    def _extract_from_single(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        changes = []
        for r in data.get("resources", []):
            if not isinstance(r, dict) or "kind" not in r:
                continue
            changes.append({
                "Action": "Add",
                "Kind": _kind_from_resource(r),
                "ResourceType": _kind_from_resource(r),
                "LogicalResourceId": _name_from_resource(r),
                "Namespace": _namespace_from_resource(r),
                "Replacement": "False",
                "Spec": r.get("spec", {}),
                "Data": r.get("data", {}),
            })
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        action = raw.get("Action", "Unknown")
        replacement = str(raw.get("Replacement", "False"))
        kind = raw.get("Kind", "Unknown")
        logical_id = raw.get("LogicalResourceId", "<unknown>")
        namespace = raw.get("Namespace")
        address = f"{namespace}/{logical_id}" if namespace else logical_id

        risk = "review"
        actions = ("unknown",)
        explanation = f"Kubernetes action '{action}' on {kind} requires review."

        if action == "Add":
            risk = "safe"
            actions = ("create",)
            explanation = f"Kubernetes will create {kind} '{logical_id}'."
        elif action == "Modify":
            if replacement == "True":
                risk = "dangerous"
                actions = ("delete", "create")
                explanation = f"Kubernetes will replace {kind} '{logical_id}' (destroy and recreate)."
            elif replacement == "Conditional":
                risk = "review"
                actions = ("update",)
                explanation = f"Kubernetes will update {kind} '{logical_id}'. Review the spec changes before applying."
            else:
                risk = "review"
                actions = ("update",)
                explanation = f"Kubernetes will update {kind} '{logical_id}' in place."
        elif action == "Remove":
            risk = "irreversible"
            actions = ("delete",)
            explanation = f"Kubernetes will delete {kind} '{logical_id}'."

        normalized_type = self._normalize_resource_type(kind)

        return ResourceChange(
            address=address,
            resource_type=normalized_type,
            actions=actions,
            risk=risk,
            explanation=explanation,
        )

    def _normalize_resource_type(self, kind: str) -> str:
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
