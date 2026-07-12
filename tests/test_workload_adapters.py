from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.workloads import (
    DockerComposeAdapter,
    NomadPlanAdapter,
    WorkloadInputError,
    parse_docker_compose,
    parse_nomad_plan,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_compose_flags_host_and_supply_chain_boundaries() -> None:
    data = parse_docker_compose((FIXTURES / "docker_compose_risky.yml").read_text(encoding="utf-8"))
    adapter = detect_adapter(data)
    assert isinstance(adapter, DockerComposeAdapter)

    changes = adapter.analyze(data, use_rules=False)
    by_address = {change.address: change for change in changes}
    assert by_address["services.api.image"].risk == "dangerous"
    assert by_address["services.api.privileged"].risk == "dangerous"
    assert by_address["services.api.network_mode"].risk == "dangerous"
    assert by_address["services.api.volumes[0]"].risk == "dangerous"
    assert by_address["services.api.ports[0]"].risk == "dangerous"
    assert by_address["services.worker.image"].risk == "review"
    assert by_address["services.worker.read_only"].risk == "safe"
    assert by_address["services.worker.cap_drop"].risk == "safe"
    assert by_address["compose.secrets"].risk == "dangerous"


def test_compose_loopback_and_named_volume_require_review() -> None:
    data = parse_docker_compose(
        """
services:
  db:
    image: postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ports:
      - 127.0.0.1:5432:5432
    volumes:
      - db-data:/var/lib/postgresql/data
"""
    )
    changes = DockerComposeAdapter().analyze(data, use_rules=False)
    assert [change.risk for change in changes] == ["review", "review", "review"]


def test_compose_ipv6_loopback_port_requires_review() -> None:
    data = parse_docker_compose(
        "services:\n  api:\n    image: api@sha256:abc\n    ports: ['[::1]:8080:80']\n"
    )
    changes = DockerComposeAdapter().analyze(data, use_rules=False)
    assert changes[-1].risk == "review"


def test_compose_windows_bind_mount_preserves_drive_prefix() -> None:
    data = parse_docker_compose(
        "services:\n  api:\n    image: api@sha256:abc\n"
        "    volumes: ['C:/Users/admin/.ssh:/keys:ro']\n"
    )
    changes = DockerComposeAdapter().analyze(data, use_rules=False)
    mount = changes[-1]
    assert mount.risk == "dangerous"
    assert "C:/Users/admin/.ssh" in mount.explanation


def test_compose_flags_api_socket_host_namespaces_and_sensitive_environment() -> None:
    data = parse_docker_compose(
        """
services:
  agent:
    image: agent@sha256:abc
    uts: host
    use_api_socket: true
    environment:
      DEPLOY_TOKEN: ${DEPLOY_TOKEN}
"""
    )
    changes = DockerComposeAdapter().analyze(data, use_rules=False)
    by_type = {change.resource_type: change for change in changes}
    assert by_type["docker_compose_host_namespace"].risk == "dangerous"
    assert by_type["docker_compose_container_api"].risk == "dangerous"
    assert by_type["docker_compose_secret_input"].risk == "dangerous"


def test_nomad_plan_flags_scheduler_and_execution_risks() -> None:
    data = parse_nomad_plan((FIXTURES / "nomad_plan_risky.json").read_text(encoding="utf-8"))
    adapter = detect_adapter(data)
    assert isinstance(adapter, NomadPlanAdapter)

    changes = adapter.analyze(data, use_rules=False)
    resource_types = {change.resource_type: change for change in changes}
    assert resource_types["nomad_placement_failure"].risk == "dangerous"
    assert resource_types["nomad_destructive_update"].risk == "dangerous"
    assert resource_types["nomad_stop"].risk == "dangerous"
    assert resource_types["nomad_task_driver"].risk == "dangerous"
    assert resource_types["nomad_image"].risk == "dangerous"
    assert resource_types["nomad_command"].risk == "dangerous"


def test_nomad_no_change_is_safe() -> None:
    data = parse_nomad_plan(json.dumps({"Diff": None, "JobModifyIndex": 12}))
    changes = NomadPlanAdapter().analyze(data, use_rules=False)
    assert len(changes) == 1
    assert changes[0].resource_type == "nomad_no_change"
    assert changes[0].risk == "safe"


@pytest.mark.parametrize(
    ("tool", "fixture", "expected_adapter"),
    [
        ("docker-compose", "docker_compose_risky.yml", "docker-compose"),
        ("nomad", "nomad_plan_risky.json", "nomad"),
    ],
)
def test_workload_cli_and_framework_baseline(
    tool: str,
    fixture: str,
    expected_adapter: str,
    capsys,
) -> None:
    assert main([tool, "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == expected_adapter
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize("source", ["", "[]", "services: []", "services: {}", "not: compose"])
def test_compose_parser_rejects_invalid_input(source: str) -> None:
    with pytest.raises(WorkloadInputError):
        parse_docker_compose(source)


@pytest.mark.parametrize("source", ["", "[]", "{}", "not json"])
def test_nomad_parser_rejects_invalid_input(source: str) -> None:
    with pytest.raises(WorkloadInputError):
        parse_nomad_plan(source)
