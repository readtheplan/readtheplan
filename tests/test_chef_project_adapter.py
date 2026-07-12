from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.chef_project import (
    ChefProjectAdapter,
    ChefProjectInputError,
    analyze_chef_project,
    parse_chef_project,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(fixture: str):
    data = parse_chef_project((FIXTURES / fixture).read_text(encoding="utf-8"))
    return ChefProjectAdapter().analyze(data, tool_name="Chef project")


def test_policyfile_surfaces_sources_mutability_attributes_and_ruby_execution() -> None:
    changes = _changes("chef_policyfile_risky.rb")
    by_type: dict[str, list] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change)

    assert len(changes) == 14
    assert sum(change.risk == "dangerous" for change in changes) == 8
    assert by_type["chef_project_default_cookbook_source"][0].risk == "dangerous"
    assert len(by_type["chef_project_cookbook_dependency"]) == 6
    assert (
        sum(change.risk == "dangerous" for change in by_type["chef_project_cookbook_dependency"])
        == 4
    )
    assert by_type["chef_project_secret_attribute"][0].risk == "dangerous"
    assert by_type["chef_project_ruby_execution"][0].risk == "dangerous"


def test_policy_lock_distinguishes_immutable_and_risky_resolution() -> None:
    review = _changes("chef_policy_lock_review.json")
    risky = _changes("chef_policy_lock_risky.json")

    assert {change.risk for change in review} == {"review"}
    assert sum(change.risk == "dangerous" for change in risky) == 5
    assert any("full commit" in change.explanation for change in risky)
    assert any("plaintext transport" in change.explanation for change in risky)
    assert any("no content identifier" in change.explanation for change in risky)
    assert any(change.resource_type == "chef_project_secret_attribute" for change in risky)


def test_metadata_surfaces_cookbook_gem_compatibility_privacy_and_execution() -> None:
    changes = _changes("chef_metadata_risky.rb")
    dependencies = [
        change for change in changes if change.resource_type == "chef_project_cookbook_dependency"
    ]
    gems = [change for change in changes if change.resource_type == "chef_project_gem_dependency"]

    assert len(dependencies) == 3
    assert sum(change.risk == "dangerous" for change in dependencies) == 2
    assert len(gems) == 2
    assert sum(change.risk == "dangerous" for change in gems) == 1
    assert any(change.resource_type == "chef_project_public_cookbook_upload" for change in changes)
    assert any(change.resource_type == "chef_project_ruby_execution" for change in changes)


def test_minimal_static_metadata_is_recognized_without_dependency_directives() -> None:
    data = parse_chef_project(
        'name "simple"\nversion "1.0.0"\nlicense "Apache-2.0"\nmaintainer "Infra"\n'
    )
    assert data["chef_project"]["artifact_type"] == "metadata"


def test_missing_required_policy_and_metadata_identity_is_dangerous() -> None:
    policy = parse_chef_project('default_source :supermarket\ncookbook "nginx", "1.0.0"\n')
    metadata = parse_chef_project('depends "nginx", "= 1.0.0"\n')
    policy_types = {change.resource_type for change in ChefProjectAdapter().analyze(policy)}
    metadata_types = {change.resource_type for change in ChefProjectAdapter().analyze(metadata)}
    assert "chef_project_missing_policy_name" in policy_types
    assert "chef_project_missing_run_list" in policy_types
    assert "chef_project_missing_cookbook_name" in metadata_types
    assert "chef_project_missing_cookbook_version" in metadata_types


def test_known_directive_cannot_hide_same_line_ruby_execution() -> None:
    data = parse_chef_project('name "production"; system "./mutate"\nrun_list "recipe[base]"\n')
    changes = ChefProjectAdapter().analyze(data)
    execution = [
        change for change in changes if change.resource_type == "chef_project_ruby_execution"
    ]
    assert len(execution) == 1
    assert execution[0].risk == "dangerous"


def test_quote_scanner_handles_long_adversarial_escape_sequences_linearly() -> None:
    escaped = "\\\\a" * 20_000
    data = parse_chef_project(
        f'name "production"\nrun_list "recipe[base]"\n'
        f'cookbook "payload", git: "https://example.test/{escaped}", branch: "main"\n'
    )
    changes = ChefProjectAdapter().analyze(data)
    dependencies = [
        change for change in changes if change.resource_type == "chef_project_cookbook_dependency"
    ]
    assert len(dependencies) == 1
    assert dependencies[0].risk == "dangerous"


@pytest.mark.parametrize(
    ("source", "error"),
    [
        ("", "empty"),
        ("puts 'hello'", "not a recognized"),
        ('{"name": "not-a-lock"}', "not recognized"),
        ('{"revision_id": "one", "revision_id": "two"}', "duplicate JSON key"),
        (
            '{"revision_id": "one", "cookbook_locks": {"bad": {"source_options": []}}}',
            "source_options",
        ),
        ('name "mixed"\nrun_list "recipe[x]"\ndepends "y"\n', "mixes"),
    ],
)
def test_parser_rejects_unrelated_ambiguous_or_duplicate_input(source: str, error: str) -> None:
    with pytest.raises(ChefProjectInputError, match=error):
        parse_chef_project(source)


@pytest.mark.parametrize(
    ("fixture", "artifact_type"),
    [
        ("chef_policyfile_risky.rb", "policyfile"),
        ("chef_policy_lock_risky.json", "lock"),
        ("chef_metadata_risky.rb", "metadata"),
    ],
)
def test_gate_and_cli_support_every_chef_project_format(
    fixture: str,
    artifact_type: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = parse_chef_project((FIXTURES / fixture).read_text(encoding="utf-8"))
    gate = analyze_chef_project(data)
    assert gate["adapter"] == "chef-project"
    assert gate["artifact_type"] == artifact_type
    assert gate["decision"] == "block"
    assert gate["total_changes"] == sum(gate["risk_counts"].values())

    assert main(["chef-project", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "chef-project"
    assert payload["artifact_type"] == artifact_type
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
