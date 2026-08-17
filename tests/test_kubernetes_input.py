from __future__ import annotations

import json
import textwrap

import pytest

import readtheplan.adapters.kubernetes as kubernetes_adapter
from readtheplan.adapters.kubernetes import (
    KubernetesAdapter,
    KubernetesInputError,
    parse_kubernetes_input,
)
from readtheplan.cli import main
from readtheplan.mcp_server import agent_gate_kubernetes

DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: example/web:1.0
"""


def test_parse_multi_document_yaml_and_list_kind() -> None:
    source = DEPLOYMENT + """
---
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Service
    metadata:
      name: web
      namespace: production
    spec:
      selector:
        app: web
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: settings
"""
    data = parse_kubernetes_input(source)
    assert [resource["kind"] for resource in data["resources"]] == [
        "Deployment",
        "Service",
        "ConfigMap",
    ]


def test_parse_single_json_manifest_and_wrapper_yaml() -> None:
    manifest = json.dumps(
        {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "token"}}
    )
    assert parse_kubernetes_input(manifest)["resources"][0]["kind"] == "Secret"

    wrapper = (
        "old_manifests: []\nnew_manifests:\n  - kind: Namespace\n"
        "    metadata:\n      name: demo\n"
    )
    parsed = parse_kubernetes_input(wrapper)
    assert parsed["new_manifests"][0]["kind"] == "Namespace"


@pytest.mark.parametrize("source", ["", "plain text", "42", "items: []"])
def test_parser_rejects_non_manifest_input(source: str) -> None:
    with pytest.raises(KubernetesInputError):
        parse_kubernetes_input(source)


def test_parser_rejects_recursive_yaml_alias() -> None:
    source = """\
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: recursive
spec: &recursive
  nested: *recursive
"""

    with pytest.raises(KubernetesInputError, match="recursive YAML alias"):
        parse_kubernetes_input(source)


def test_parser_rejects_excessively_nested_yaml_without_recursion_error() -> None:
    nested = "leaf: true\n"
    for _ in range(500):
        nested = f"child:\n{textwrap.indent(nested, '  ')}"
    source = (
        "apiVersion: tekton.dev/v1\nkind: Task\nmetadata:\n  name: deep\nspec:\n"
        f"{textwrap.indent(nested, '  ')}"
    )

    with pytest.raises(KubernetesInputError, match="nesting depth limit exceeded"):
        parse_kubernetes_input(source)


def test_parser_rejects_excessively_nested_json_without_recursion_error() -> None:
    source = "[" * 2_000 + "0" + "]" * 2_000

    with pytest.raises(KubernetesInputError, match="nesting depth limit exceeded"):
        parse_kubernetes_input(source)


def test_parser_enforces_global_node_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kubernetes_adapter, "_MAX_K8S_YAML_NODES", 10)

    with pytest.raises(KubernetesInputError, match="node count limit exceeded"):
        parse_kubernetes_input(DEPLOYMENT)


def test_parser_preserves_nonrecursive_alias_dag() -> None:
    source = """\
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: shared
spec:
  first: &shared
    image: example.invalid/build@sha256:abc
  second: *shared
"""

    data = parse_kubernetes_input(source)
    [resource] = data["resources"]

    assert resource["spec"]["first"] is resource["spec"]["second"]
    assert KubernetesAdapter().analyze(data, tool_name="Kubernetes")[0].risk == "review"


def test_object_graph_depth_budget_applies_at_alias_sites() -> None:
    shared = {"child": {"leaf": True}}
    deep = shared
    for _ in range(kubernetes_adapter._MAX_K8S_NESTING_DEPTH - 1):
        deep = {"child": deep}
    value = {"shallow": shared, "deep": deep}

    with pytest.raises(KubernetesInputError, match="nesting depth limit exceeded"):
        kubernetes_adapter._validate_object_graph(value)


def test_parser_accepts_more_than_one_hundred_yaml_documents() -> None:
    source = "\n---\n".join(
        f"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: resource-{index}\n"
        for index in range(101)
    )

    assert len(parse_kubernetes_input(source)["resources"]) == 101


def test_cli_and_mcp_accept_rendered_yaml(tmp_path, capsys) -> None:
    rendered = tmp_path / "rendered.yaml"
    rendered.write_text(DEPLOYMENT, encoding="utf-8")

    assert main(["kubernetes", str(rendered)]) == 0
    assert json.loads(capsys.readouterr().out)["adapter"] == "kubernetes"

    mcp_gate = agent_gate_kubernetes(str(rendered), "soc2")
    assert mcp_gate["adapter"] == "kubernetes"
    assert mcp_gate["decision"] == "proceed"
    assert "rtp.control.soc2.CC8.1" in mcp_gate["required_checks"]


def test_crossplane_custom_resource_defaults_to_review() -> None:
    data = parse_kubernetes_input(
        """\
apiVersion: s3.aws.upbound.io/v1beta1
kind: Bucket
metadata:
  name: application-data
spec:
  forProvider:
    region: us-east-1
"""
    )
    change = KubernetesAdapter().analyze(data, use_rules=False)[0]
    assert change.risk == "review"
    assert "owning controller" in change.explanation


def test_admission_webhook_is_dangerous() -> None:
    data = parse_kubernetes_input(
        """\
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: inject-sidecar
webhooks: []
"""
    )
    change = KubernetesAdapter().analyze(data, use_rules=False)[0]
    assert change.resource_type == "kubernetes_mutating_webhook_configuration"
    assert change.risk == "dangerous"
