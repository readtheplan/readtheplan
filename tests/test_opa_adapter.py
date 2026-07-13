from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.opa import OPAAdapter, OPAInputError, analyze_opa, parse_opa
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(name: str):
    path = FIXTURES / name
    data = parse_opa(path.read_text(encoding="utf-8"), path.name)
    return data, OPAAdapter().analyze(data, tool_name="OPA/Rego")


def test_rego_detects_runtime_network_fail_open_exceptions_and_boundary() -> None:
    data, changes = _changes("opa_policy_risky.rego")
    assert data["opa"]["artifact_type"] == "rego"
    kinds = {change.resource_type for change in changes}
    assert {
        "opa_external_data_dependency",
        "opa_runtime_builtin",
        "opa_debug_output",
        "opa_unconditional_allow",
        "opa_fail_open_default",
        "opa_broad_exception",
        "opa_enforcement_boundary",
        "opa_test_coverage_boundary",
        "opa_rego_version_boundary",
        "opa_literal_secret",
        "opa_evaluation_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 7


def test_rego_comments_do_not_create_builtin_findings() -> None:
    data = parse_opa(
        """package safe
import rego.v1
# http.send({})
default allow := false
deny contains msg if { msg := "no" }
"""
    )
    changes = OPAAdapter().analyze(data, tool_name="OPA/Rego")
    assert not any("http.send" in change.address for change in changes)


def test_rego_strings_do_not_create_builtin_findings() -> None:
    data = parse_opa(
        """package safe
import rego.v1
message := "http.send({}) and opa.runtime()"
deny contains msg if { msg := message }
"""
    )
    changes = OPAAdapter().analyze(data, tool_name="OPA/Rego")
    assert not any(change.resource_type == "opa_runtime_builtin" for change in changes)


def test_manifest_detects_global_scope_revision_wasm_signature_and_version() -> None:
    data, changes = _changes("opa_bundle_risky/.manifest")
    assert data["opa"]["artifact_type"] == "manifest"
    kinds = {change.resource_type for change in changes}
    assert {
        "opa_mutable_bundle_revision",
        "opa_global_bundle_root",
        "opa_legacy_rego_semantics",
        "opa_wasm_policy",
        "opa_signature_boundary",
    } <= kinds


def test_conftest_detects_external_paths_data_and_invocation_boundary() -> None:
    data, changes = _changes("opa_conftest_risky/conftest.toml")
    assert data["opa"]["artifact_type"] == "conftest"
    kinds = {change.resource_type for change in changes}
    assert {
        "opa_external_policy_path",
        "opa_all_namespace_scope",
        "opa_data_dependency",
        "opa_capabilities_dependency",
        "opa_invocation_boundary",
    } <= kinds


def test_signature_metadata_is_decoded_without_returning_token() -> None:
    def encoded(value: dict[str, object]) -> str:
        import base64

        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    token = f"{encoded({'alg': 'none'})}.{encoded({'files': []})}.signature-material"
    data = parse_opa(json.dumps({"signatures": [token]}), ".signatures.json")
    gate = analyze_opa(data)
    rendered = json.dumps(gate)
    assert token not in rendered
    assert gate["artifact_type"] == "signatures"
    assert gate["decision"] == "block"


@pytest.mark.parametrize(
    ("source", "filename", "message"),
    [
        ("", "policy.rego", "empty"),
        ("allow := true", "policy.rego", "package"),
        ("package a\npackage b", "policy.rego", "exactly one"),
        ('package a\nallow if { input.x == "unterminated }', "policy.rego", "unterminated"),
        ('{"roots": [], "roots": []}', ".manifest", "duplicate JSON key"),
        ('{"unrelated": true}', ".manifest", "not recognized"),
        ('{"signatures": []}', ".signatures.json", "non-empty"),
        ("policy = [1]", "conftest.toml", "policy must"),
    ],
)
def test_opa_rejects_malformed_or_ambiguous_input(source: str, filename: str, message: str) -> None:
    if filename == "conftest.toml" and "policy must" in message:
        data = parse_opa(source, filename)
        with pytest.raises(OPAInputError, match=message):
            OPAAdapter().analyze(data, tool_name="OPA/Rego")
        return
    with pytest.raises(OPAInputError, match=message):
        parse_opa(source, filename)


def test_opa_source_is_never_executed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("OPA or Conftest execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _changes("opa_policy_risky.rego")
    assert changes


@pytest.mark.parametrize(
    ("fixture", "artifact_type"),
    [
        ("opa_policy_risky.rego", "rego"),
        ("opa_bundle_risky/.manifest", "manifest"),
        ("opa_conftest_risky/conftest.toml", "conftest"),
    ],
)
def test_opa_cli_emits_gate_contract(
    fixture: str, artifact_type: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["opa", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "opa"
    assert payload["artifact_type"] == artifact_type
    assert payload["decision"] == "block" or artifact_type == "conftest"
