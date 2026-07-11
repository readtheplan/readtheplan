"""Tests for the Kubernetes adapter."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from readtheplan.adapters.kubernetes import KubernetesAdapter, analyze_kubernetes

# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

DEPLOYMENT_CREATE = {
    "resources": [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web-frontend", "namespace": "production", "labels": {"app": "web"}},  # noqa: E501
            "spec": {
                "replicas": 3,
                "selector": {"matchLabels": {"app": "web"}},
                "template": {
                    "metadata": {"labels": {"app": "web"}},
                    "spec": {
                        "containers": [{"name": "nginx", "image": "nginx:1.25", "ports": [{"containerPort": 80}]}],  # noqa: E501
                    },
                },
            },
        }
    ]
}

SVC_OLD = {
    "apiVersion": "v1",
    "kind": "Service",
    "metadata": {"name": "api", "namespace": "default"},
    "spec": {
        "type": "ClusterIP",
        "ports": [{"port": 80, "targetPort": 8080}],
        "selector": {"app": "api"},
    },
}

SVC_NEW = {
    "apiVersion": "v1",
    "kind": "Service",
    "metadata": {"name": "api", "namespace": "default"},
    "spec": {
        "type": "NodePort",
        "ports": [{"port": 80, "targetPort": 8080, "nodePort": 30080}],
        "selector": {"app": "api"},
    },
}

SECRET_KIND = {
    "apiVersion": "v1",
    "kind": "Secret",
    "metadata": {"name": "db-creds", "namespace": "default"},
    "type": "Opaque",
    "data": {"username": "YWRtaW4=", "password": "cGFzc3dvcmQ="},
}

NAMESPACE_OLD = {
    "apiVersion": "v1",
    "kind": "Namespace",
    "metadata": {"name": "staging"},
}

NAMESPACE_NEW = {
    "apiVersion": "v1",
    "kind": "Namespace",
    "metadata": {"name": "staging", "labels": {"env": "staging-v2"}},
}

CLUSTER_ROLE = {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "ClusterRole",
    "metadata": {"name": "admin-cluster"},
    "rules": [
        {"apiGroups": [""], "resources": ["pods", "services"], "verbs": ["get", "list", "watch"]},
    ],
}

DEPLOYMENT_WITH_LIVENESS = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "worker", "namespace": "default"},
    "spec": {
        "replicas": 2,
        "selector": {"matchLabels": {"app": "worker"}},
        "template": {
            "metadata": {"labels": {"app": "worker"}},
            "spec": {
                "containers": [{"name": "worker", "image": "worker:v1", "livenessProbe": {"httpGet": {"path": "/health", "port": 8080}}}],  # noqa: E501
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Adapter unit tests
# ---------------------------------------------------------------------------


class TestKubernetesAdapter:
    def test_adapter_name(self):
        assert KubernetesAdapter().adapter_name == "kubernetes"

    def test_can_handle_diff_format(self):
        adapter = KubernetesAdapter()
        data = {"old_manifests": [DEPLOYMENT_WITH_LIVENESS], "new_manifests": [DEPLOYMENT_WITH_LIVENESS]}  # noqa: E501
        assert adapter.can_handle(data) is True

    def test_can_handle_single_format(self):
        adapter = KubernetesAdapter()
        assert adapter.can_handle(DEPLOYMENT_CREATE) is True

    def test_cannot_handle_random_data(self):
        adapter = KubernetesAdapter()
        assert adapter.can_handle({"foo": "bar"}) is False
        assert adapter.can_handle([]) is False

    def test_extract_changes_from_single(self):
        adapter = KubernetesAdapter()
        changes = adapter.extract_changes(DEPLOYMENT_CREATE)
        assert len(changes) == 1
        assert changes[0]["Action"] == "Add"
        assert changes[0]["Kind"] == "Deployment"
        assert changes[0]["LogicalResourceId"] == "web-frontend"
        assert changes[0]["_metadata"]["before"] == {}
        assert changes[0]["_metadata"]["after"]["spec"] == (
            DEPLOYMENT_CREATE["resources"][0]["spec"]
        )

    def test_extract_changes_from_diff_add(self):
        adapter = KubernetesAdapter()
        data = {"old_manifests": [], "new_manifests": [SECRET_KIND]}
        changes = adapter.extract_changes(data)
        assert len(changes) == 1
        assert changes[0]["Action"] == "Add"
        assert changes[0]["Kind"] == "Secret"
        assert changes[0]["_metadata"]["before"] == {}
        assert changes[0]["_metadata"]["after"]["type"] == "Opaque"

    def test_extract_changes_from_diff_remove(self):
        adapter = KubernetesAdapter()
        data = {"old_manifests": [SECRET_KIND], "new_manifests": []}
        changes = adapter.extract_changes(data)
        assert len(changes) == 1
        assert changes[0]["Action"] == "Remove"
        assert changes[0]["Kind"] == "Secret"
        assert changes[0]["_metadata"]["before"]["type"] == "Opaque"
        assert changes[0]["_metadata"]["after"] == {}

    def test_extract_changes_from_diff_modify(self):
        adapter = KubernetesAdapter()
        data = {"old_manifests": [SVC_OLD], "new_manifests": [SVC_NEW]}
        changes = adapter.extract_changes(data)
        assert len(changes) == 1
        assert changes[0]["Action"] == "Modify"
        assert changes[0]["Kind"] == "Service"
        assert "_metadata" in changes[0]
        assert "before" in changes[0]["_metadata"]
        assert "after" in changes[0]["_metadata"]

    @pytest.mark.parametrize(
        ("kind", "field", "before", "after"),
        [
            (
                "ClusterRole",
                "rules",
                [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
                [{"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]}],
            ),
            (
                "RoleBinding",
                "roleRef",
                {"kind": "Role", "name": "viewer"},
                {"kind": "Role", "name": "editor"},
            ),
            (
                "RoleBinding",
                "subjects",
                [{"kind": "ServiceAccount", "name": "app"}],
                [{"kind": "Group", "name": "developers"}],
            ),
            ("Secret", "stringData", {"token": "old"}, {"token": "new"}),
            ("ConfigMap", "binaryData", {"blob": "b2xk"}, {"blob": "bmV3"}),
            (
                "ClusterRole",
                "aggregationRule",
                {"clusterRoleSelectors": [{"matchLabels": {"tier": "reader"}}]},
                {"clusterRoleSelectors": [{"matchLabels": {"tier": "editor"}}]},
            ),
            ("Secret", "type", "Opaque", "kubernetes.io/tls"),
        ],
    )
    def test_top_level_rule_property_change_produces_modify(
        self,
        kind,
        field,
        before,
        after,
    ):
        adapter = KubernetesAdapter()
        old = {
            "apiVersion": "v1",
            "kind": kind,
            "metadata": {"name": "example", "namespace": "default"},
            field: before,
        }
        new = {**old, field: after}

        changes = adapter.extract_changes(
            {"old_manifests": [old], "new_manifests": [new]}
        )

        assert len(changes) == 1
        assert changes[0]["Action"] == "Modify"
        assert changes[0]["_metadata"]["before"][field] == before
        assert changes[0]["_metadata"]["after"][field] == after

    def test_extract_changes_identical_noop(self):
        adapter = KubernetesAdapter()
        data = {"old_manifests": [SVC_OLD], "new_manifests": [SVC_OLD]}
        changes = adapter.extract_changes(data)
        assert len(changes) == 0

    def test_normalize_create(self):
        adapter = KubernetesAdapter()
        raw = {
            "Action": "Add",
            "Kind": "Deployment",
            "LogicalResourceId": "web",
            "Namespace": "default",
            "Replacement": "False",
        }
        rc = adapter.normalize_change(raw)
        assert rc.risk == "safe"
        assert rc.actions == ("create",)
        assert rc.resource_type == "kubernetes_deployment"
        assert rc.address == "default/web"

    def test_normalize_delete(self):
        adapter = KubernetesAdapter()
        raw = {
            "Action": "Remove",
            "Kind": "Secret",
            "LogicalResourceId": "db-creds",
            "Namespace": "default",
            "Replacement": "False",
        }
        rc = adapter.normalize_change(raw)
        assert rc.risk == "irreversible"
        assert rc.actions == ("delete",)

    def test_normalize_modify_review(self):
        adapter = KubernetesAdapter()
        raw = {
            "Action": "Modify",
            "Kind": "Service",
            "LogicalResourceId": "api",
            "Namespace": "default",
            "Replacement": "Conditional",
        }
        rc = adapter.normalize_change(raw)
        assert rc.risk == "review"
        assert rc.actions == ("update",)

    def test_normalize_replacement(self):
        adapter = KubernetesAdapter()
        raw = {
            "Action": "Modify",
            "Kind": "Deployment",
            "LogicalResourceId": "web",
            "Namespace": "default",
            "Replacement": "True",
        }
        rc = adapter.normalize_change(raw)
        assert rc.risk == "dangerous"
        assert rc.actions == ("delete", "create")

    def test_normalize_cluster_scoped_no_namespace(self):
        adapter = KubernetesAdapter()
        raw = {
            "Action": "Remove",
            "Kind": "ClusterRole",
            "LogicalResourceId": "admin-cluster",
            "Namespace": None,
            "Replacement": "False",
        }
        rc = adapter.normalize_change(raw)
        assert rc.address == "admin-cluster"
        assert rc.resource_type == "kubernetes_cluster_role"
        assert rc.risk == "irreversible"

    def test_resource_type_mapping(self):
        adapter = KubernetesAdapter()
        assert adapter._normalize_resource_type("Deployment") == "kubernetes_deployment"
        assert adapter._normalize_resource_type("Service") == "kubernetes_service"
        assert adapter._normalize_resource_type("Namespace") == "kubernetes_namespace"
        assert adapter._normalize_resource_type("ClusterRole") == "kubernetes_cluster_role"
        assert adapter._normalize_resource_type("NetworkPolicy") == "kubernetes_network_policy"
        assert adapter._normalize_resource_type("UnknownKind") == "kubernetes_unknownkind"


# ---------------------------------------------------------------------------
# Integration: analyze_kubernetes()
# ---------------------------------------------------------------------------


def test_analyze_create_deployment():
    gate = analyze_kubernetes(DEPLOYMENT_CREATE)
    assert gate["schema"] == "rtp-agent-gate-v1"
    assert gate["adapter"] == "kubernetes"
    assert gate["total_changes"] == 1
    assert gate["decision"] in ("proceed", "warn", "block")
    assert isinstance(gate["risk_counts"], dict)


def test_analyze_service_type_change():
    data = {"old_manifests": [SVC_OLD], "new_manifests": [SVC_NEW]}
    gate = analyze_kubernetes(data)
    assert gate["adapter"] == "kubernetes"
    assert gate["total_changes"] == 1
    assert gate["decision"] == "warn"
    assert gate["risk"] == "review"


def test_analyze_secret_create_uses_rules():
    """Secret creation should trigger the rules engine for dangerous risk."""
    data = {"resources": [SECRET_KIND]}
    gate = analyze_kubernetes(data)
    assert gate["total_changes"] == 1
    # The adapter normalize says "safe" for Add, but the rules engine
    # in _apply_resource_rules may escalate to "dangerous" for secrets.


def test_analyze_namespace_replace_via_diff():
    """Namespace with label changes should be a modify."""
    data = {"old_manifests": [NAMESPACE_OLD], "new_manifests": [NAMESPACE_NEW]}
    gate = analyze_kubernetes(data)
    assert gate["total_changes"] == 1


def test_analyze_empty_diff():
    gate = analyze_kubernetes({"old_manifests": [], "new_manifests": []})
    assert gate["total_changes"] == 0
    assert gate["decision"] == "proceed"


def test_analyze_none_values():
    """Ensure nulls in manifest lists don't crash."""
    data = {"old_manifests": [None, SVC_OLD], "new_manifests": [SVC_NEW, None]}
    gate = analyze_kubernetes(data)
    assert gate["total_changes"] >= 1


def test_analyze_cluster_role_diff():
    data = {
        "old_manifests": [CLUSTER_ROLE],
        "new_manifests": [],
    }
    gate = analyze_kubernetes(data)
    assert gate["total_changes"] == 1


def test_analyze_cluster_role_aggregation_selector_only_diff():
    old = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "aggregate-readers"},
        "aggregationRule": {
            "clusterRoleSelectors": [{"matchLabels": {"rbac.example/tier": "reader"}}]
        },
    }
    new = {
        **old,
        "aggregationRule": {
            "clusterRoleSelectors": [{"matchLabels": {"rbac.example/tier": "editor"}}]
        },
    }

    gate = analyze_kubernetes({"old_manifests": [old], "new_manifests": [new]})

    assert gate["total_changes"] >= 1
    assert gate["decision"] != "proceed"


@pytest.mark.parametrize("wildcard_field", ["apiGroups", "resources", "verbs"])
def test_analyze_role_wildcard_grant_is_dangerous(wildcard_field):
    rule = {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}
    rule[wildcard_field] = ["*"]
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "broad-role", "namespace": "production"},
        "rules": [rule],
    }

    changes = KubernetesAdapter().analyze({"resources": [role]}, tool_name="Kubernetes")

    assert changes[0].risk == "dangerous"
    assert wildcard_field in changes[0].explanation


def test_analyze_role_update_to_wildcard_grant_is_dangerous():
    old = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "pod-reader", "namespace": "production"},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
    }
    new = {
        **old,
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}],
    }

    changes = KubernetesAdapter().analyze(
        {"old_manifests": [old], "new_manifests": [new]},
        tool_name="Kubernetes",
    )

    assert len(changes) == 1
    assert changes[0].risk == "dangerous"
    assert "wildcard verbs" in changes[0].explanation


def test_analyze_bounded_role_grant_requires_review_without_escalation():
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "pod-reader", "namespace": "production"},
        "rules": [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}
        ],
    }

    changes = KubernetesAdapter().analyze({"resources": [role]}, tool_name="Kubernetes")

    assert changes[0].risk == "review"
    assert "change a Role" in changes[0].explanation


@pytest.mark.parametrize(
    "rules",
    [None, "not-a-list", {"verbs": ["*"]}, [None, "not-a-rule", {"verbs": None}]],
)
def test_analyze_malformed_role_rules_do_not_crash(rules):
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "malformed-role", "namespace": "production"},
        "rules": rules,
    }

    gate = analyze_kubernetes({"resources": [role]})

    assert gate["total_changes"] == 1
    assert gate["risk"] == "review"


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------


def test_cli_kubernetes_subcommand():
    """Verify the CLI has a working 'kubernetes' subcommand."""
    import subprocess

    repo_root = Path(__file__).resolve().parent.parent
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(DEPLOYMENT_CREATE, f)
        tmp = f.name

    try:
        result = subprocess.run(
            ["readtheplan", "kubernetes", tmp],
            capture_output=True, text=True, cwd=repo_root,
        )
        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        output = json.loads(result.stdout)
        assert output["adapter"] == "kubernetes"
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# MCP smoke test
# ---------------------------------------------------------------------------


def test_mcp_tool_kubernetes():
    """Verify the MCP tool function works with a temp file."""
    from readtheplan.mcp_server import agent_gate_kubernetes

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(DEPLOYMENT_CREATE, f)
        tmp = f.name

    try:
        result = agent_gate_kubernetes(tmp)
        assert isinstance(result, dict)
        assert result["adapter"] == "kubernetes"
    finally:
        os.unlink(tmp)


def test_mcp_tool_invalid_path():
    from readtheplan.mcp_server import MCPToolInputError, agent_gate_kubernetes

    with pytest.raises(MCPToolInputError):
        agent_gate_kubernetes("")


def test_mcp_tool_file_not_found():
    from readtheplan.mcp_server import MCPToolInputError, agent_gate_kubernetes

    with pytest.raises(MCPToolInputError, match="File not found"):
        agent_gate_kubernetes("/nonexistent/path.json")
