from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.tiltfile import (
    TiltfileAdapter,
    TiltfileInputError,
    analyze_tiltfile,
    parse_tiltfile,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes():
    data = parse_tiltfile((FIXTURES / "Tiltfile.risky").read_text(encoding="utf-8"))
    return data, TiltfileAdapter().analyze(data, tool_name="Tilt")


def test_tiltfile_detects_build_deploy_host_extension_and_live_update_boundaries() -> None:
    data, changes = _changes()
    assert data["tiltfile"]["parsed"] is True
    kinds = {change.resource_type for change in changes}
    assert {
        "tilt_tiltfile_dependency",
        "tilt_literal_secret",
        "tilt_environment_dependency",
        "tilt_environment_mutation",
        "tilt_cluster_or_registry_target",
        "tilt_secret_scrubbing",
        "tilt_docker_build",
        "tilt_custom_image_build",
        "tilt_image_target",
        "tilt_external_source_path",
        "tilt_live_file_sync",
        "tilt_container_or_probe_command",
        "tilt_compose_deployment",
        "tilt_host_command",
        "tilt_kubernetes_deployment",
        "tilt_helm_render",
        "tilt_kustomize_render",
        "tilt_custom_kubernetes_deploy",
        "tilt_kubernetes_resource_control",
        "tilt_port_forward",
        "tilt_host_file_read",
        "tilt_extension_invocation",
        "tilt_dynamic_argument",
        "tilt_evaluation_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 20


def test_gate_contract_redacts_secret_values() -> None:
    data, _ = _changes()
    gate = analyze_tiltfile(data)
    assert gate["adapter"] == "tilt"
    assert gate["syntax_mode"] == "ast"
    assert gate["decision"] == "block"
    assert "literal-example" not in json.dumps(gate)


def test_digest_pinned_build_target_is_review() -> None:
    data = parse_tiltfile(
        "docker_build('api@sha256:" + "a" * 64 + "', '.', dockerfile='Dockerfile')"
    )
    changes = TiltfileAdapter().analyze(data, tool_name="Tilt")
    target = next(change for change in changes if change.resource_type == "tilt_image_target")
    assert target.risk == "review"


def test_valid_but_non_python_source_uses_conservative_fallback() -> None:
    data = parse_tiltfile("local_resource('build', cmd='make') ???")
    changes = TiltfileAdapter().analyze(data, tool_name="Tilt")
    assert data["tiltfile"]["parsed"] is False
    assert any(change.resource_type == "tilt_dynamic_tilt_call" for change in changes)
    assert any(change.risk == "dangerous" for change in changes)


@pytest.mark.parametrize("source", ["", "print('hello')", "terraform plan"])
def test_rejects_non_tiltfile_input(source: str) -> None:
    with pytest.raises(TiltfileInputError):
        parse_tiltfile(source)


def test_tiltfile_never_executes_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Tilt execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _changes()
    assert changes


def test_cli_emits_gate_contract(capsys) -> None:
    path = FIXTURES / "Tiltfile.risky"
    assert main(["tilt", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "tilt"
    assert payload["syntax_mode"] == "ast"
    assert payload["decision"] == "block"
    assert "literal-example" not in json.dumps(payload)
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
