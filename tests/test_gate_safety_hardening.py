"""Red tests for gate-safety hardening (Codex review 2026-07-10, findings 1-3).

These tests encode REQUIRED behavior. They are expected to FAIL on
main@22a6b54 and must pass once ``fix/gate-safety-hardening`` lands.

Findings covered:

1. Generated evolution rules must never activate without explicit approval,
   and rule generation must not write into the installed package or the
   repository ``tests/`` directory.
2. The Kubernetes diff must surface changes to RBAC ``rules``, binding
   ``roleRef``/``subjects``, Secret ``stringData``, and ``binaryData``;
   wildcard namespace Roles must not classify as safe.
3. The Kubernetes MCP handler must enforce ``MCP_ROOT`` exactly like the
   Terraform and CloudFormation handlers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.kubernetes import analyze_kubernetes
from readtheplan.evolution import EvolutionEngine
from readtheplan.mcp_server import MCPToolInputError, agent_gate_kubernetes

# ---------------------------------------------------------------------------
# Finding 1 — generated rules must not self-activate
# ---------------------------------------------------------------------------


def test_evolve_decision_never_auto_merges(tmp_path) -> None:
    """No score/risk combination may bypass human approval.

    The maximum status a generated rule can reach on its own is
    ``pr-ready``; activation requires an explicit approval step.
    """
    engine = EvolutionEngine(data_dir=tmp_path)
    for score in (70.0, 85.0, 90.0, 95.0, 100.0):
        for risk in ("safe", "review", "dangerous", "irreversible"):
            decision = engine._evolve_decision(score, risk)
            assert decision != "auto-merge", (
                f"score={score} risk={risk} auto-merged without approval"
            )


def _tree_snapshot(root: Path) -> set[str]:
    if not root.exists():
        return set()
    return {str(p.relative_to(root)) for p in root.rglob("*")}


def test_rule_generation_does_not_write_into_package_or_tests(tmp_path) -> None:
    """Candidate generation must confine all writes to the engine data dir.

    On main, ``analyze_with_agents`` writes rule modules into
    ``src/readtheplan/rules/auto/`` (where they are imported and thus
    ACTIVE on next start) and test files into the repo ``tests/`` tree.
    """
    import readtheplan.rules as rules_pkg

    pkg_dir = Path(rules_pkg.__file__).resolve().parent
    repo_tests_dir = Path(__file__).resolve().parent

    before_pkg = _tree_snapshot(pkg_dir)
    before_tests = _tree_snapshot(repo_tests_dir)

    engine = EvolutionEngine(data_dir=tmp_path)
    pattern = {
        "resource_type": "aws_s3_bucket",
        "risk": "dangerous",
        "incident_count": 12,
        "pattern_hash": "deadbeefdeadbeef",
    }
    engine.analyze_with_agents([pattern])

    assert _tree_snapshot(pkg_dir) == before_pkg, (
        "rule generation wrote into the installed package directory"
    )
    assert _tree_snapshot(repo_tests_dir) == before_tests, (
        "rule generation wrote into the repository tests/ directory"
    )


def test_high_scoring_candidate_stays_pr_ready(tmp_path) -> None:
    """Even a maximum-scoring candidate must be recorded as pr-ready, not active."""
    engine = EvolutionEngine(data_dir=tmp_path)
    pattern = {
        "resource_type": "aws_iam_role",
        "risk": "dangerous",
        "incident_count": 12,
        "pattern_hash": "cafebabecafebabe",
    }
    evolved = engine.analyze_with_agents([pattern])
    assert evolved, "expected a candidate to be produced"
    for candidate in evolved:
        assert candidate["rule_status"] in ("pr-ready", "disabled"), (
            f"candidate reached status {candidate['rule_status']!r} without approval"
        )


# ---------------------------------------------------------------------------
# Finding 2 — Kubernetes diff blind spots
# ---------------------------------------------------------------------------


def _cluster_role(rules: list[dict]) -> dict:
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "ops-role"},
        "rules": rules,
    }


def _role_binding(role_ref: dict, subjects: list[dict]) -> dict:
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "ops-binding", "namespace": "prod"},
        "roleRef": role_ref,
        "subjects": subjects,
    }


def test_rbac_rules_change_is_visible() -> None:
    """A ClusterRole whose only change is its ``rules`` must not vanish."""
    old = _cluster_role(
        [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
    )
    new = _cluster_role(
        [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
    )
    gate = analyze_kubernetes({"old_manifests": [old], "new_manifests": [new]})
    assert gate["total_changes"] >= 1, "rules-only RBAC change was dropped"
    assert gate["decision"] != "proceed"


def test_rolebinding_roleref_and_subjects_change_is_visible() -> None:
    """A binding whose roleRef/subjects change must not produce proceed."""
    old = _role_binding(
        {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "viewer"},
        [{"kind": "ServiceAccount", "name": "app", "namespace": "prod"}],
    )
    new = _role_binding(
        {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
        [{"kind": "Group", "name": "system:authenticated"}],
    )
    gate = analyze_kubernetes({"old_manifests": [old], "new_manifests": [new]})
    assert gate["total_changes"] >= 1, "roleRef/subjects change was dropped"
    assert gate["decision"] != "proceed"


def test_secret_stringdata_change_is_visible() -> None:
    old = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "db-creds", "namespace": "prod"},
        "type": "Opaque",
        "stringData": {"password": "old"},
    }
    new = {**old, "stringData": {"password": "new"}}
    gate = analyze_kubernetes({"old_manifests": [old], "new_manifests": [new]})
    assert gate["total_changes"] >= 1, "stringData-only change was dropped"
    assert gate["decision"] != "proceed"


def test_secret_binarydata_change_is_visible() -> None:
    old = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "tls-cert", "namespace": "prod"},
        "type": "Opaque",
        "binaryData": {"cert.pem": "b2xk"},
    }
    new = {**old, "binaryData": {"cert.pem": "bmV3"}}
    gate = analyze_kubernetes({"old_manifests": [old], "new_manifests": [new]})
    assert gate["total_changes"] >= 1, "binaryData-only change was dropped"
    assert gate["decision"] != "proceed"


def test_wildcard_namespace_role_is_not_safe() -> None:
    """Creating a namespaced Role with wildcard grants must require review."""
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "god-mode", "namespace": "prod"},
        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
    }
    gate = analyze_kubernetes({"resources": [role]})
    assert gate["decision"] != "proceed", (
        "wildcard namespace Role classified as safe"
    )


# ---------------------------------------------------------------------------
# Finding 3 — Kubernetes MCP handler must enforce MCP_ROOT
# ---------------------------------------------------------------------------

_K8S_INPUT = {
    "resources": [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "app-config", "namespace": "default"},
            "data": {"key": "value"},
        }
    ]
}


def test_agent_gate_kubernetes_rejects_path_outside_root(monkeypatch, tmp_path) -> None:
    """The k8s MCP tool must apply the same MCP_ROOT confinement as CFN/Terraform."""
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    outside = tmp_path.parent / "k8s-diff.json"
    outside.write_text(json.dumps(_K8S_INPUT), encoding="utf-8")

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_kubernetes(str(outside))

    assert exc_info.value.code == "PATH_TRAVERSAL"


def test_agent_gate_kubernetes_allows_path_inside_root(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MCP_ROOT", str(tmp_path))
    inside = tmp_path / "k8s-diff.json"
    inside.write_text(json.dumps(_K8S_INPUT), encoding="utf-8")

    result = agent_gate_kubernetes(str(inside))
    assert result["adapter"] == "kubernetes"
