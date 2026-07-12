from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.pulumi_project import (
    PulumiProjectAdapter,
    PulumiProjectInputError,
    analyze_pulumi_project,
    parse_pulumi_project,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _data(name: str):
    path = FIXTURES / name
    return parse_pulumi_project(path.read_text(encoding="utf-8"), filename=path.name)


def _changes(name: str):
    return PulumiProjectAdapter().analyze(_data(name), tool_name="Pulumi project")


def test_project_surfaces_runtime_paths_backend_packages_plugins_secrets_and_resources() -> None:
    changes = _changes("pulumi_project_risky.yaml")
    kinds = {change.resource_type for change in changes}

    assert {
        "pulumi_project_runtime_command",
        "pulumi_project_external_project_path",
        "pulumi_project_state_backend",
        "pulumi_project_plaintext_secret",
        "pulumi_project_unmarked_secret_schema",
        "pulumi_project_unmarked_template_secret",
        "pulumi_project_mutable_package_version",
        "pulumi_project_local_executable_plugin",
        "pulumi_project_external_plugin_path",
        "pulumi_project_delete_before_replace",
        "pulumi_project_project_boundary",
        "aws_s3_bucket",
    } <= kinds
    assert any(change.risk == "dangerous" for change in changes)
    s3 = next(change for change in changes if change.resource_type == "aws_s3_bucket")
    assert s3.risk == "dangerous"


def test_stack_surfaces_secret_provider_encryption_esc_and_plaintext_secrets() -> None:
    changes = _changes("pulumi_stack_risky.yaml")
    by_type: dict[str, list] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change)

    assert by_type["pulumi_project_plaintext_secret"]
    assert by_type["pulumi_project_encrypted_config"]
    assert by_type["pulumi_project_secrets_provider"][0].risk == "dangerous"
    assert any(
        change.risk == "dangerous"
        for change in by_type["pulumi_project_environment_import"]
    )
    assert by_type["pulumi_project_stack_boundary"]


def test_policy_surfaces_execution_version_path_and_policy_boundary() -> None:
    changes = _changes("pulumi_policy_risky.yaml")
    by_type = {change.resource_type: change for change in changes}

    assert by_type["pulumi_project_runtime_execution"].risk == "review"
    assert by_type["pulumi_project_external_runtime_path"].risk == "dangerous"
    assert by_type["pulumi_project_external_policy_path"].risk == "dangerous"
    assert by_type["pulumi_project_non_semver_policy_version"].risk == "review"
    assert by_type["pulumi_project_policy_boundary"].risk == "review"


def test_review_project_has_no_dangerous_findings() -> None:
    changes = _changes("pulumi_project_review.yaml")
    assert changes
    assert {change.risk for change in changes} == {"review"}
    assert not any(change.resource_type == "pulumi_project_plaintext_secret" for change in changes)


def test_gate_contract_identifies_artifact_and_never_repeats_secret_values() -> None:
    data = _data("pulumi_stack_risky.yaml")
    gate = analyze_pulumi_project(data)
    serialized = json.dumps(gate)

    assert gate["adapter"] == "pulumi-project"
    assert gate["artifact"] == "stack"
    assert gate["decision"] == "block"
    assert "plaintext-password" not in serialized
    assert "ciphertext-is-not-reported" not in serialized
    assert "inline-environment-password" not in serialized


def test_parser_uses_filename_and_shape_for_all_artifacts() -> None:
    assert _data("pulumi_project_risky.yaml")["pulumi_project"]["artifact"] == "project"
    assert _data("pulumi_stack_risky.yaml")["pulumi_project"]["artifact"] == "stack"
    assert _data("pulumi_policy_risky.yaml")["pulumi_project"]["artifact"] == "policy"
    inferred = parse_pulumi_project("config:\n  aws:region: us-west-2\n")
    assert inferred["pulumi_project"]["artifact"] == "stack"


@pytest.mark.parametrize(
    "source,filename,error",
    [
        ("", "Pulumi.yaml", "empty"),
        ("- item\n", "Pulumi.yaml", "exactly one YAML mapping"),
        ("name: app\nname: other\nruntime: python\n", "Pulumi.yaml", "duplicate YAML key"),
        ("base: &base {runtime: python}\n<<: *base\nname: app\n", "Pulumi.yaml", "merge keys"),
        ("name: bad name\nruntime: python\n", "Pulumi.yaml", "project name"),
        ("name: app\nruntime: shell\n", "Pulumi.yaml", "unsupported runtime"),
        ("config: []\n", "Pulumi.dev.yaml", "config must be a mapping"),
        ("runtime: go\n", "PulumiPolicy.yaml", "unsupported policy runtime"),
        ("services: {}\n", None, "not recognizable"),
    ],
)
def test_parser_rejects_ambiguous_or_malformed_input(
    source: str,
    filename: str | None,
    error: str,
) -> None:
    with pytest.raises(PulumiProjectInputError, match=error):
        parse_pulumi_project(source, filename=filename)


def test_parser_and_analyzer_never_execute_pulumi_or_language_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("external execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    assert _changes("pulumi_project_risky.yaml")


def test_adapter_rejects_wrong_shape() -> None:
    adapter = PulumiProjectAdapter()
    assert not adapter.can_handle({})
    assert not adapter.can_handle({"pulumi_project": {}})


def test_pulumi_project_cli_emits_framework_gate(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "pulumi-project",
                "--framework",
                "soc2",
                str(FIXTURES / "pulumi_project_risky.yaml"),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "pulumi-project"
    assert payload["artifact"] == "project"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
