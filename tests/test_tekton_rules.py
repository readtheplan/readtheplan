from __future__ import annotations

from pathlib import Path

import pytest

from readtheplan.adapters.kubernetes import KubernetesAdapter, parse_kubernetes_input

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(source: str):
    return KubernetesAdapter().analyze(
        parse_kubernetes_input(source), tool_name="Kubernetes"
    )


def test_tekton_risky_resources_receive_native_rules() -> None:
    changes = _analyze((FIXTURES / "tekton_risky.yml").read_text(encoding="utf-8"))
    by_type = {change.resource_type: change for change in changes}

    assert by_type["kubernetes_tekton_task"].risk == "dangerous"
    assert "container-runtime access" in by_type["kubernetes_tekton_task"].explanation
    assert by_type["kubernetes_tekton_pipeline"].risk == "dangerous"
    assert "mutable Git revision" in by_type["kubernetes_tekton_pipeline"].explanation
    assert by_type["kubernetes_tekton_pipeline_run"].risk == "dangerous"
    assert "ServiceAccount" in by_type["kubernetes_tekton_pipeline_run"].explanation
    assert by_type["kubernetes_tekton_event_listener"].risk == "dangerous"
    assert "event-driven pipeline ingress" in by_type[
        "kubernetes_tekton_event_listener"
    ].explanation
    assert by_type["kubernetes_tekton_trigger_template"].risk == "dangerous"
    assert "creates Kubernetes resources" in by_type[
        "kubernetes_tekton_trigger_template"
    ].explanation
    assert by_type["kubernetes_tekton_trigger_binding"].risk == "review"
    assert by_type["kubernetes_tekton_resolution_request"].risk == "dangerous"


@pytest.mark.parametrize(
    ("api_version", "kind", "expected_type"),
    [
        ("tekton.dev/v1", "Task", "kubernetes_tekton_task"),
        ("tekton.dev/v1", "ClusterTask", "kubernetes_tekton_cluster_task"),
        ("tekton.dev/v1", "Pipeline", "kubernetes_tekton_pipeline"),
        ("tekton.dev/v1", "TaskRun", "kubernetes_tekton_task_run"),
        ("tekton.dev/v1", "PipelineRun", "kubernetes_tekton_pipeline_run"),
        ("tekton.dev/v1beta1", "CustomRun", "kubernetes_tekton_custom_run"),
        ("tekton.dev/v1alpha1", "StepAction", "kubernetes_tekton_step_action"),
        (
            "tekton.dev/v1alpha1",
            "PipelineResource",
            "kubernetes_tekton_pipeline_resource",
        ),
        (
            "triggers.tekton.dev/v1beta1",
            "ClusterTriggerBinding",
            "kubernetes_tekton_cluster_trigger_binding",
        ),
        (
            "triggers.tekton.dev/v1alpha1",
            "ClusterInterceptor",
            "kubernetes_tekton_cluster_interceptor",
        ),
    ],
)
def test_tekton_api_groups_normalize_known_resources(
    api_version: str, kind: str, expected_type: str
) -> None:
    change = _analyze(
        f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: example\nspec: {{}}\n"
    )[0]
    assert change.resource_type == expected_type


def test_non_tekton_task_stays_generic() -> None:
    change = _analyze(
        "apiVersion: example.io/v1\nkind: Task\nmetadata:\n  name: example\nspec: {}\n"
    )[0]
    assert change.resource_type == "kubernetes_task"
    assert change.risk == "review"


def test_pinned_git_resolver_pipeline_still_requires_review() -> None:
    sha = "a" * 40
    change = _analyze(
        f"""
apiVersion: tekton.dev/v1
kind: Pipeline
metadata:
  name: pinned
spec:
  tasks:
    - name: test
      taskRef:
        resolver: git
        params:
          - name: revision
            value: {sha}
          - name: url
            value: https://github.com/example/catalog.git
"""
    )[0]
    assert change.risk == "review"
    assert "task references" in change.explanation


def test_deleting_tekton_run_is_irreversible() -> None:
    data = {
        "old_manifests": [
            {
                "apiVersion": "tekton.dev/v1",
                "kind": "TaskRun",
                "metadata": {"name": "running", "namespace": "ci"},
                "spec": {"taskRef": {"name": "build"}},
            }
        ],
        "new_manifests": [],
    }
    change = KubernetesAdapter().analyze(data, tool_name="Kubernetes")[0]
    assert change.resource_type == "kubernetes_tekton_task_run"
    assert change.risk == "irreversible"
    assert "cancelling or removing run state" in change.explanation
