from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.carvel import (
    CarvelAdapter,
    CarvelInputError,
    analyze_carvel,
    parse_carvel,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _analyze(name: str):
    path = FIXTURES / name
    data = parse_carvel(path.read_text(encoding="utf-8"), path.name)
    return data, CarvelAdapter().analyze(data, tool_name="Carvel")


def test_ytt_detects_loads_values_overlays_libraries_generation_and_secrets() -> None:
    data, changes = _analyze("ytt_risky.yaml")
    assert data["carvel"]["artifact_type"] == "ytt"
    assert {
        "carvel_template_evaluation",
        "carvel_module_load",
        "carvel_library_load",
        "carvel_data_values_schema",
        "carvel_data_values",
        "carvel_overlay_mutation",
        "carvel_library_evaluation",
        "carvel_generated_configuration",
        "carvel_external_data_input",
        "carvel_credential_data",
        "carvel_evaluation_boundary",
    } <= {change.resource_type for change in changes}


def test_vendir_detects_managed_paths_fetchers_integrity_auth_and_permissions() -> None:
    data, changes = _analyze("vendir_risky.yml")
    assert data["carvel"]["artifact_type"] == "vendir"
    kinds = {change.resource_type for change in changes}
    assert {
        "carvel_managed_directory",
        "carvel_git_source",
        "carvel_http_source",
        "carvel_helmChart_source",
        "carvel_image_source",
        "carvel_directory_source",
        "carvel_inline_source",
        "carvel_githubRelease_source",
        "carvel_secret_reference",
        "carvel_source_path_selection",
        "carvel_broad_content_permissions",
        "carvel_resolution_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 9


def test_vendir_lock_distinguishes_resolved_and_unresolved_content() -> None:
    data, changes = _analyze("vendir_risky.lock.yml")
    assert data["carvel"]["artifact_type"] == "vendir-lock"
    locked = [change for change in changes if change.resource_type == "carvel_locked_content"]
    assert [change.risk for change in locked] == ["review", "dangerous"]


def test_kbld_detects_search_override_build_publish_and_mutability() -> None:
    data, changes = _analyze("kbld_risky.yml")
    assert data["carvel"]["artifact_type"] == "kbld"
    assert {
        "carvel_image_search_rules",
        "carvel_image_override",
        "carvel_image_build",
        "carvel_external_build_context",
        "carvel_image_publish",
        "carvel_mutable_image_destination",
        "carvel_literal_secret",
        "carvel_execution_boundary",
    } <= {change.resource_type for change in changes}


def test_imgpkg_locks_require_digest_references() -> None:
    data, changes = _analyze("imgpkg_risky_locks.yml")
    assert data["carvel"]["artifact_type"] == "imgpkg-lock"
    image_locks = [change for change in changes if change.resource_type == "carvel_image_lock"]
    assert [change.risk for change in image_locks] == ["review", "dangerous"]
    bundle = next(change for change in changes if change.resource_type == "carvel_bundle_lock")
    assert bundle.risk == "dangerous"


def test_kapp_detects_rebase_ownership_ordering_annotations_and_secrets() -> None:
    data, changes = _analyze("kapp_risky.yml")
    assert data["carvel"]["artifact_type"] == "kapp"
    assert {
        "carvel_deploy_configuration",
        "carvel_rebase_rule",
        "carvel_ownership_rules",
        "carvel_change_ordering",
        "carvel_resource_lifecycle_annotation",
        "carvel_literal_secret",
        "carvel_cluster_boundary",
    } <= {change.resource_type for change in changes}


@pytest.mark.parametrize(
    ("fixture", "literal"),
    [
        ("ytt_risky.yaml", "literal-ytt-token"),
        ("kbld_risky.yml", "literal-build-token"),
        ("kapp_risky.yml", "literal-kapp-token"),
    ],
)
def test_gate_redacts_literal_credentials(fixture: str, literal: str) -> None:
    data, _ = _analyze(fixture)
    gate = analyze_carvel(data)
    assert gate["adapter"] == "carvel"
    assert gate["decision"] == "block"
    assert literal not in json.dumps(gate)


@pytest.mark.parametrize(
    ("source", "error"),
    [
        ("", "empty"),
        ("kind: ConfigMap\n", "recognizable"),
        (
            "apiVersion: vendir.k14s.io/v1alpha1\nkind: Config\nkind: LockConfig\n",
            "duplicate YAML key",
        ),
        ("apiVersion: vendir.k14s.io/v1alpha1\nkind: [\n", "invalid Carvel YAML"),
    ],
)
def test_rejects_invalid_unrelated_or_duplicate_input(source: str, error: str) -> None:
    with pytest.raises(CarvelInputError, match=error):
        parse_carvel(source)


def test_carvel_never_executes_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Carvel execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _analyze("vendir_risky.yml")
    assert changes


@pytest.mark.parametrize(
    ("command", "fixture", "artifact"),
    [
        ("ytt", "ytt_risky.yaml", "ytt"),
        ("vendir", "vendir_risky.yml", "vendir"),
        ("kbld", "kbld_risky.yml", "kbld"),
        ("imgpkg", "imgpkg_risky_locks.yml", "imgpkg-lock"),
        ("kapp", "kapp_risky.yml", "kapp"),
    ],
)
def test_cli_aliases_cover_carvel_family(capsys, command: str, fixture: str, artifact: str) -> None:
    path = FIXTURES / fixture
    assert main([command, "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "carvel"
    assert payload["artifact_type"] == artifact
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
