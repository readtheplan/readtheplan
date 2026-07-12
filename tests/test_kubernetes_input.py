from __future__ import annotations

import json

import pytest

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


def test_cli_and_mcp_accept_rendered_yaml(tmp_path, capsys) -> None:
    rendered = tmp_path / "rendered.yaml"
    rendered.write_text(DEPLOYMENT, encoding="utf-8")

    assert main(["kubernetes", str(rendered)]) == 0
    assert json.loads(capsys.readouterr().out)["adapter"] == "kubernetes"

    mcp_gate = agent_gate_kubernetes(str(rendered))
    assert mcp_gate["adapter"] == "kubernetes"
    assert mcp_gate["decision"] == "proceed"


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
