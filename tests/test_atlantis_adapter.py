from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.atlantis import (
    AtlantisAdapter,
    AtlantisInputError,
    parse_atlantis_config,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(fixture: str) -> dict[str, list[str]]:
    data = parse_atlantis_config((FIXTURES / fixture).read_text(encoding="utf-8"))
    changes = AtlantisAdapter().analyze(data, tool_name="Atlantis")
    result: dict[str, list[str]] = defaultdict(list)
    for change in changes:
        result[change.resource_type].append(change.risk)
    return result


def test_repo_config_surfaces_mutation_gates_workflows_and_concurrency() -> None:
    risks = _risks("atlantis_risky.yaml")
    assert risks["atlantis_schema_version"] == ["safe"]
    assert risks["atlantis_parallel_apply"] == ["dangerous"]
    assert risks["atlantis_execution_failure_policy"] == ["dangerous"]
    assert risks["atlantis_command_requirements"] == [
        "dangerous",
        "dangerous",
        "dangerous",
    ]
    assert risks["atlantis_repo_locks"] == ["dangerous"]
    assert risks["atlantis_autoplan"] == ["dangerous"]
    assert risks["atlantis_environment"] == ["dangerous"]
    assert risks["atlantis_custom_command"] == ["dangerous", "dangerous"]
    assert risks["atlantis_effective_configuration"] == ["review"]


def test_server_config_surfaces_wildcards_overrides_hooks_and_custom_code() -> None:
    risks = _risks("atlantis_server_risky.yaml")
    assert risks["atlantis_repository_scope"] == ["dangerous"]
    assert risks["atlantis_command_requirements"] == ["dangerous"]
    assert risks["atlantis_allowed_overrides"] == ["dangerous"]
    assert risks["atlantis_custom_workflows"] == ["dangerous"]
    assert risks["atlantis_policy_check"] == ["dangerous"]
    assert risks["atlantis_custom_command"] == ["dangerous", "dangerous"]
    assert risks["atlantis_workflow_hooks"] == ["dangerous", "dangerous"]


def test_hardened_server_defaults_are_safe() -> None:
    data = parse_atlantis_config(
        "repos:\n"
        "  - id: github.com/example/infra\n"
        "    apply_requirements: [approved, mergeable, undiverged]\n"
        "    allow_custom_workflows: false\n"
        "    policy_check: true\n"
    )
    changes = AtlantisAdapter().analyze(data, tool_name="Atlantis")
    by_type = {change.resource_type: change.risk for change in changes}
    assert by_type["atlantis_repository_scope"] == "review"
    assert by_type["atlantis_command_requirements"] == "safe"
    assert by_type["atlantis_custom_workflows"] == "safe"
    assert by_type["atlantis_policy_check"] == "safe"


@pytest.mark.parametrize(
    "fixture", ["atlantis_risky.yaml", "atlantis_server_risky.yaml"]
)
def test_atlantis_cli_and_framework_baseline(capsys, fixture: str) -> None:
    assert main(["atlantis", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "atlantis"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize(
    "source", ["", "[]", "foo: bar", "version: 3", "repos: not-a-list"]
)
def test_atlantis_parser_rejects_invalid_input(source: str) -> None:
    with pytest.raises(AtlantisInputError):
        parse_atlantis_config(source)
