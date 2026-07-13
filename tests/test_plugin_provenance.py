"""Tests for plugin provenance (Task A) and entry-point discovery (Task B)."""

from __future__ import annotations

import readtheplan.rules._shared as shared
from readtheplan import controls
from readtheplan.adapters import (
    ADAPTER_ENTRY_POINT_GROUP,
    load_entry_point_adapters,
)
from readtheplan.attestation import (
    build_plan_read_attestation,
    parse_attestation_header,
)
from readtheplan.evidence import build_evidence
from readtheplan.plan import ResourceChange, analyze_plan_file
from readtheplan.rules import (
    RULES_ENTRY_POINT_GROUP,
    RuleResult,
    load_entry_point_rules,
    register_rule,
)


def test_rule_result_defaults_to_builtin_source() -> None:
    assert RuleResult("safe", "x").source == "builtin"


def test_resource_change_defaults_to_builtin_source() -> None:
    rc = ResourceChange("a", "t", ("create",), "safe", "x")
    assert rc.source == "builtin"


def test_builtin_rules_keep_builtin_source(tmp_path) -> None:
    plan = tmp_path / "p.json"
    plan.write_text(
        '{"resource_changes":[{"address":"aws_kms_key.k","type":"aws_kms_key",'
        '"change":{"actions":["delete"]}}]}'
    )
    summary = analyze_plan_file(plan)
    assert summary.resource_changes[0].source == "builtin"


def test_plugin_rule_source_flows_into_evidence(tmp_path, monkeypatch) -> None:
    # Register a plugin rule attributed to a fake plugin source.
    @register_rule("example_widget", source="acme-plugin")
    def _widget_rule(resource_type, action_set, change):
        return [RuleResult("dangerous", "__TOOL__ touches a widget.")]

    try:
        plan = tmp_path / "p.json"
        plan.write_text(
            '{"resource_changes":[{"address":"example_widget.w","type":"example_widget",'
            '"change":{"actions":["update"]}}]}'
        )
        summary = analyze_plan_file(plan)
        change = summary.resource_changes[0]
        assert change.risk == "dangerous"
        assert change.source == "acme-plugin"

        envelope = build_evidence(
            plan_summary=summary,
            plan_json=plan.read_bytes(),
            catalog=controls.load_catalog("soc2"),
            agent_id="tester",
        )
        payload = envelope.to_dict()
        # per-change provenance
        assert payload["changes"][0]["provenance"] == {"source": "acme-plugin"}
        # signed attestation provenance summary
        assert payload["agent_attestation"]["provenance"] == ["acme-plugin"]
    finally:
        shared._RULE_REGISTRY.pop("example_widget", None)


def test_attestation_header_roundtrips_provenance() -> None:
    att = build_plan_read_attestation(
        agent_id="codex", plan_json="{}", plugins=("acme-plugin", "beta")
    )
    parsed = parse_attestation_header(att.to_header_value())
    assert parsed.provenance == ("acme-plugin", "beta")


def test_entry_point_discovery_finds_builtins() -> None:
    assert RULES_ENTRY_POINT_GROUP == "readtheplan.rules"
    assert ADAPTER_ENTRY_POINT_GROUP == "readtheplan.adapters"
    rules = load_entry_point_rules()
    adapters = load_entry_point_adapters()
    assert {
        "aws",
        "gcp",
        "azure",
        "cloudflare",
        "datadog",
        "grafana",
        "github",
        "gitlab",
        "k8s",
        "newrelic",
        "pagerduty",
        "tfe",
        "vault",
    } <= set(rules)
    assert {
        "ansible-project",
        "bicep",
        "chef-project",
        "cdk",
        "cloudformation",
        "jenkins-jcasc",
        "jenkins-project",
        "teamcity",
        "concourse",
        "bamboo",
        "travis-ci",
        "drone-ci",
        "woodpecker-ci",
        "codebuild",
        "cloud-build",
        "codepipeline",
        "sops",
        "kubernetes",
        "nix",
        "dsc",
        "devspace",
        "cue",
        "jsonnet",
        "tanka",
        "helmfile",
        "terramate",
        "ytt",
        "vendir",
        "kbld",
        "imgpkg",
        "kapp",
        "cfengine",
        "puppet-project",
        "pulumi-project",
        "salt-project",
        "skaffold",
        "terraform-lock",
        "terraform-state",
        "tilt",
    } <= set(adapters)
