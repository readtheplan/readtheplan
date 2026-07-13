from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.packer import PackerInspectAdapter, parse_packer
from readtheplan.adapters.packer_template import (
    PackerTemplateInputError,
    parse_packer_template,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(name: str):
    path = FIXTURES / name
    data = parse_packer(path.read_text(encoding="utf-8"))
    adapter = detect_adapter(data)
    assert isinstance(adapter, PackerInspectAdapter)
    return data, adapter.analyze(data, use_rules=False)


def test_hcl_template_detects_plugins_builders_execution_publishing_and_secrets() -> None:
    data, changes = _changes("packer_template_risky.pkr.hcl")
    assert data["packer_template"]["representation"] == "hcl"
    kinds = {change.resource_type for change in changes}
    assert {
        "packer_required_plugin",
        "packer_unmasked_secret_variable",
        "packer_literal_secret",
        "packer_runtime_variable",
        "packer_unmasked_secret_local",
        "packer_external_data",
        "packer_builder",
        "packer_communicator",
        "packer_verification_bypass",
        "packer_mutable_base_image",
        "packer_remote_source",
        "packer_provisioner",
        "packer_elevated_provisioning",
        "packer_post_processor",
        "packer_weak_checksum",
        "packer_dynamic_evaluation",
        "packer_source_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 13


def test_exact_official_plugin_is_review_but_custom_range_is_dangerous() -> None:
    data = parse_packer_template(
        """packer {
  required_plugins {
    amazon = { source = "github.com/hashicorp/amazon", version = "1.2.3" }
    custom = { source = "github.com/example/custom", version = ">= 1.0.0" }
  }
}
"""
    )
    changes = PackerInspectAdapter().analyze(data, use_rules=False)
    plugins = [c for c in changes if c.resource_type == "packer_required_plugin"]
    assert [c.risk for c in plugins] == ["review", "dangerous"]


def test_legacy_json_template_is_supported() -> None:
    data = parse_packer_template(
        json.dumps(
            {
                "variables": {"region": "us-east-1"},
                "builders": [{"type": "amazon-ebs", "source_ami": "ami-123"}],
                "provisioners": [{"type": "shell", "inline": ["id"]}],
                "post-processors": [{"type": "manifest"}],
            }
        )
    )
    changes = PackerInspectAdapter().analyze(data, use_rules=False)
    kinds = {change.resource_type for change in changes}
    assert {"packer_builder", "packer_provisioner", "packer_post_processor"} <= kinds


def test_hcl_post_processor_sequence_is_supported() -> None:
    data = parse_packer_template(
        """source "null" "example" { communicator = "none" }
build {
  sources = ["source.null.example"]
  post-processors {
    post-processor "manifest" {}
    post-processor "docker-push" { login = true }
  }
}
"""
    )
    changes = PackerInspectAdapter().analyze(data, use_rules=False)
    processors = [c for c in changes if c.resource_type == "packer_post_processor"]
    assert [c.risk for c in processors] == ["safe", "dangerous"]


def test_inspect_autodetection_remains_backward_compatible() -> None:
    data = parse_packer((FIXTURES / "packer_inspect_risky.txt").read_text(encoding="utf-8"))
    assert "packer_inspect" in data


def test_template_cli_redacts_secrets_and_reports_artifact(capsys) -> None:
    path = FIXTURES / "packer_template_risky.pkr.hcl"
    assert main(["packer", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "packer"
    assert payload["artifact_type"] == "template"
    assert payload["decision"] == "block"
    assert "literal-example" not in json.dumps(payload)
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("", "empty"),
        ("[]", "object"),
        ("unrelated = true", "not recognized"),
        ('source "broken" {', "invalid Packer HCL"),
        ('{"builders": [], "builders": []}', "duplicate JSON key"),
    ],
)
def test_template_rejects_malformed_or_ambiguous_input(source: str, message: str) -> None:
    with pytest.raises(PackerTemplateInputError, match=message):
        parse_packer_template(source)


def test_template_never_executes_packer_or_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Packer execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _changes("packer_template_risky.pkr.hcl")
    assert changes
