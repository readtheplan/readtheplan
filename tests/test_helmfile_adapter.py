from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.helmfile import (
    HelmfileAdapter,
    HelmfileInputError,
    analyze_helmfile,
    parse_helmfile,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(name: str):
    path = FIXTURES / name
    data = parse_helmfile(path.read_text(encoding="utf-8"), path.name)
    return data, HelmfileAdapter().analyze(data, tool_name="Helmfile")


def test_state_detects_execution_supply_chain_cluster_secret_and_render_boundaries() -> None:
    data, changes = _analyze("helmfile_risky.yaml.gotmpl")
    assert data["helmfile"]["artifact_type"] == "state"
    kinds = {change.resource_type for change in changes}
    assert {
        "helmfile_desired_state",
        "helmfile_template_exec",
        "helmfile_template_env_exec",
        "helmfile_template_file_read",
        "helmfile_remote_secret_resolution",
        "helmfile_environment_input",
        "helmfile_dynamic_template",
        "helmfile_chart_repository",
        "helmfile_repository_authentication",
        "helmfile_helm_release",
        "helmfile_unpinned_chart",
        "helmfile_sensitive_namespace",
        "helmfile_cluster_target",
        "helmfile_release_uninstall",
        "helmfile_unsafe_release_option",
        "helmfile_post_renderer",
        "helmfile_release_dependency_dag",
        "helmfile_release_values_source",
        "helmfile_release_secret_source",
        "helmfile_host_command_hook",
        "helmfile_hook_log_disclosure",
        "helmfile_adhoc_chart_dependency",
        "helmfile_production_environment",
        "helmfile_environment_cluster_target",
        "helmfile_environment_values_source",
        "helmfile_environment_secret_source",
        "helmfile_missing_input_fail_open",
        "helmfile_base_state",
        "helmfile_nested_state",
        "helmfile_kubectl_apply_hook",
        "helmfile_default_cluster_target",
        "helmfile_external_tool_or_lock_path",
        "helmfile_default_post_renderer",
        "helmfile_unsafe_helm_defaults",
        "helmfile_synthetic_cluster_capabilities",
        "helmfile_literal_secret",
        "helmfile_execution_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 25


def test_lock_distinguishes_reproducible_and_mutable_dependencies() -> None:
    data, changes = _analyze("helmfile_risky.lock")
    assert data["helmfile"]["artifact_type"] == "lock"
    dependencies = [change for change in changes if change.resource_type == "helmfile_locked_chart"]
    assert [change.risk for change in dependencies] == ["review", "dangerous"]
    integrity = next(
        change for change in changes if change.resource_type == "helmfile_lock_integrity"
    )
    assert integrity.risk == "review"


def test_gate_redacts_literal_and_embedded_credentials() -> None:
    data, _ = _analyze("helmfile_risky.yaml.gotmpl")
    gate = analyze_helmfile(data)
    encoded = json.dumps(gate)
    assert gate["adapter"] == "helmfile"
    assert gate["decision"] == "block"
    assert "literal-api-token" not in encoded
    assert "literal-repository-password" not in encoded
    assert "user:token" not in encoded


@pytest.mark.parametrize(
    ("source", "filename", "error"),
    [
        ("", "helmfile.yaml", "empty"),
        ("name: unrelated\n", "helmfile.yaml", "recognizable"),
        ("releases: []\nreleases: []\n", "helmfile.yaml", "duplicate YAML key"),
        ("releases: [\n", "helmfile.yaml", "invalid Helmfile YAML"),
        ('releases: []\nvalue: {{ env "X"\n', "helmfile.yaml", "unbalanced"),
        ("version: v1\n", "helmfile.lock", "dependencies array"),
    ],
)
def test_rejects_invalid_ambiguous_or_duplicate_input(
    source: str, filename: str, error: str
) -> None:
    with pytest.raises(HelmfileInputError, match=error):
        parse_helmfile(source, filename)


def test_multipart_state_is_merged_without_rendering() -> None:
    data = parse_helmfile(
        "environments:\n  default: {}\n---\nreleases:\n  - name: app\n    chart: repo/app\n",
        "helmfile.yaml.gotmpl",
    )
    assert set(data["helmfile"]["document"]) == {"environments", "releases"}


def test_helmfile_never_executes_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Helmfile execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _analyze("helmfile_risky.yaml.gotmpl")
    assert changes


@pytest.mark.parametrize(
    ("fixture", "artifact"),
    [("helmfile_risky.yaml.gotmpl", "state"), ("helmfile_risky.lock", "lock")],
)
def test_cli_supports_state_and_lock(capsys, fixture: str, artifact: str) -> None:
    path = FIXTURES / fixture
    assert main(["helmfile", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "helmfile"
    assert payload["artifact_type"] == artifact
    assert payload["decision"] == "block"
    assert "literal-api-token" not in json.dumps(payload)
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
