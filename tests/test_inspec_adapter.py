from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.inspec import (
    InSpecAdapter,
    InSpecInputError,
    analyze_inspec,
    parse_inspec,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures" / "inspec_profile_risky"


def _analyze(relative: str):
    path = FIXTURES / relative
    data = parse_inspec(path.read_text(encoding="utf-8"), filename=str(path))
    return data, InSpecAdapter().analyze(data, tool_name="Chef InSpec")


def test_metadata_surfaces_scope_dependencies_gems_inputs_and_redacts_values() -> None:
    data, changes = _analyze("inspec.yml")
    kinds = {change.resource_type for change in changes}
    encoded = json.dumps([change.to_dict() for change in changes])

    assert data["inspec"]["artifact_type"] == "metadata"
    assert "inspec_unbounded_runtime" in kinds
    assert "inspec_platform_scope" in kinds
    assert "inspec_profile_dependency" in kinds
    assert "inspec_gem_dependency" in kinds
    assert "inspec_profile_input" in kinds
    assert sum(change.risk == "dangerous" for change in changes) == 6
    assert "fixture-user" not in encoded
    assert "fixture-password" not in encoded
    assert "fixture-secret-value" not in encoded
    assert "example.invalid" not in encoded
    assert "api_token" not in encoded


def test_lock_surfaces_missing_integrity_and_plaintext_without_leaking_source() -> None:
    data, changes = _analyze("inspec.lock")
    encoded = json.dumps([change.to_dict() for change in changes])

    assert data["inspec"]["artifact_type"] == "lock"
    assert len(changes) == 3
    assert sum(change.risk == "dangerous" for change in changes) == 1
    assert any("no valid SHA-256 digest" in change.explanation for change in changes)
    assert "fixture-user" not in encoded
    assert "fixture-password" not in encoded
    assert "example.invalid" not in encoded


def test_controls_surface_skips_inheritance_execution_remote_and_dynamic_boundaries() -> None:
    data, changes = _analyze("controls/main.rb")
    kinds = [change.resource_type for change in changes]
    encoded = json.dumps([change.to_dict() for change in changes])

    assert data["inspec"]["artifact_type"] == "control"
    assert kinds.count("inspec_control") == 2
    assert kinds.count("inspec_profile_control_selection") == 2
    assert "inspec_conditional_skip" in kinds
    assert "inspec_alternative_assertion" in kinds
    assert "inspec_command_execution" in kinds
    assert "inspec_remote_assessment" in kinds
    assert "inspec_ruby_execution" in kinds
    assert "inspec_dynamic_ruby" in kinds
    assert sum(change.risk == "dangerous" for change in changes) == 6
    assert "fixture-control-id" not in encoded
    assert "remote-control-id" not in encoded
    assert "fixture-token" not in encoded
    assert "example.invalid" not in encoded


def test_custom_resource_library_is_an_executable_ruby_boundary() -> None:
    data, changes = _analyze("libraries/custom.rb")

    assert data["inspec"]["artifact_type"] == "library"
    assert [change.resource_type for change in changes] == [
        "inspec_custom_resource_code",
        "inspec_ruby_execution",
        "inspec_library_boundary",
    ]
    assert [change.risk for change in changes] == ["dangerous", "dangerous", "review"]


def test_waivers_surface_skipped_permanent_expired_and_unjustified_controls() -> None:
    data, changes = _analyze("waivers.yml")
    encoded = json.dumps([change.to_dict() for change in changes])

    assert data["inspec"]["artifact_type"] == "waiver"
    assert len(changes) == 3
    assert sum(change.risk == "dangerous" for change in changes) == 2
    assert any("skips control execution" in change.explanation for change in changes)
    assert any("expiration date has passed" in change.explanation for change in changes)
    assert any("no non-empty justification" in change.explanation for change in changes)
    assert "fixture-control-id" not in encoded
    assert "remote-control-id" not in encoded


def test_json_and_csv_waivers_use_the_same_static_contract() -> None:
    json_data = parse_inspec(
        '{"control-one":{"justification":"approved","run":false}}',
        filename="waivers.json",
    )
    csv_data = parse_inspec(
        "control_id,justification,run,expiration_date\n"
        "control-two,approved,FALSE,2099-01-01\n",
        filename="waivers.csv",
    )

    assert json_data["inspec"]["artifact_type"] == "waiver"
    assert csv_data["inspec"]["artifact_type"] == "waiver"
    assert len(InSpecAdapter().analyze(json_data)) == 2
    assert len(InSpecAdapter().analyze(csv_data)) == 2


def test_exact_git_ref_is_accepted_in_metadata_and_lockfile() -> None:
    commit = "a" * 40
    metadata = parse_inspec(
        "name: pinned\n"
        "inspec_version: '= 7.1.0'\n"
        "supports:\n  - platform: linux\n"
        f"depends:\n  - name: baseline\n    git: git@example.invalid:base.git\n    ref: {commit}\n",
        filename="inspec.yml",
    )
    lock = parse_inspec(
        "lockfile_version: 1\n"
        "depends:\n  - name: baseline\n    resolved_source:\n"
        f"      git: git@example.invalid:base.git\n      ref: {commit}\n",
        filename="inspec.lock",
    )

    metadata_dependencies = [
        change
        for change in InSpecAdapter().analyze(metadata)
        if change.resource_type == "inspec_profile_dependency"
    ]
    lock_dependencies = [
        change
        for change in InSpecAdapter().analyze(lock)
        if change.resource_type == "inspec_locked_dependency"
    ]
    assert [change.risk for change in metadata_dependencies] == ["review"]
    assert [change.risk for change in lock_dependencies] == ["review"]


def test_embedded_erb_is_never_rendered_and_is_reported_as_execution() -> None:
    data = parse_inspec(
        "name: <%= ENV['PROFILE_NAME'] %>\nsupports:\n  - platform: linux\n",
        filename="inspec.yml",
    )
    changes = InSpecAdapter().analyze(data)

    assert data["inspec"]["dynamic_erb"] is True
    assert any(
        change.resource_type == "inspec_dynamic_metadata" and change.risk == "dangerous"
        for change in changes
    )
    assert "PROFILE_NAME" not in json.dumps([change.to_dict() for change in changes])


def test_control_scanner_handles_adversarial_escape_sequences_linearly() -> None:
    escaped = r"\a" * 100_000
    source = (
        "payload = 'multiline literal\n"
        f'control "{escaped}\n'
        "end of literal'\n"
        "control 'real-control' do\n"
        "  impact 1.0\n"
        "  describe file('/tmp/example') do\n"
        "    it { should exist }\n"
        "  end\n"
        "end\n"
    )

    data = parse_inspec(source, filename="controls/adversarial.rb")
    changes = InSpecAdapter().analyze(data)

    assert sum(change.resource_type == "inspec_control" for change in changes) == 1


@pytest.mark.parametrize(
    ("source", "filename", "error"),
    [
        ("", "inspec.yml", "empty"),
        ("name: one\nname: two\n", "inspec.yml", "duplicate YAML key"),
        ("base: &base {run: false}\ncopy: *base\n", "waivers.yml", "aliases"),
        (
            '{"control":{"run":true},"control":{"run":false}}',
            "waivers.json",
            "duplicate JSON key",
        ),
        ("puts 'hello'\n", "helper.rb", "not recognized"),
        ("a: b\n", "random.yml", "filename is not recognized"),
    ],
)
def test_parser_rejects_ambiguous_duplicate_or_dynamic_input(
    source: str, filename: str, error: str
) -> None:
    with pytest.raises(InSpecInputError, match=error):
        parse_inspec(source, filename=filename)


@pytest.mark.parametrize(
    ("relative", "artifact_type"),
    [
        ("inspec.yml", "metadata"),
        ("inspec.lock", "lock"),
        ("controls/main.rb", "control"),
        ("libraries/custom.rb", "library"),
        ("waivers.yml", "waiver"),
    ],
)
def test_gate_and_cli_support_every_inspec_artifact(
    relative: str,
    artifact_type: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = FIXTURES / relative
    data = parse_inspec(path.read_text(encoding="utf-8"), filename=str(path))
    gate = analyze_inspec(data)

    assert gate["adapter"] == "inspec"
    assert gate["artifact_type"] == artifact_type
    assert gate["decision"] == "block"
    assert gate["total_changes"] == sum(gate["risk_counts"].values())

    assert main(["inspec", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "inspec"
    assert payload["artifact_type"] == artifact_type
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
