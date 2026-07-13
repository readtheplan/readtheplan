from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.docker_bake import (
    DockerBakeAdapter,
    DockerBakeInputError,
    analyze_docker_bake,
    parse_docker_bake,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(data: dict) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)
    for change in DockerBakeAdapter().analyze(data, use_rules=False):
        result[change.resource_type].append(change.risk)
    return result


def test_hcl_bake_classifies_build_graph_and_secret_boundaries() -> None:
    source = (FIXTURES / "docker-bake.risky.hcl").read_text(encoding="utf-8")
    data = parse_docker_bake(source, "docker-bake.hcl")

    assert data["docker_bake"]["representation"] == "hcl"
    assert isinstance(detect_adapter(data), DockerBakeAdapter)
    risks = _risks(data)

    assert risks["docker_bake_context"] == ["review", "dangerous"]
    assert risks["docker_bake_missing_target_context"] == ["dangerous"]
    assert risks["docker_bake_inline_dockerfile"] == ["dangerous"]
    assert risks["docker_bake_entitlement"] == ["dangerous", "dangerous"]
    assert risks["docker_bake_secret_build_arg"] == ["dangerous"]
    assert risks["docker_bake_secret_mount"] == ["dangerous"]
    assert risks["docker_bake_ssh_forwarding"] == ["dangerous"]
    assert risks["docker_bake_cache_from"] == ["dangerous"]
    assert risks["docker_bake_cache_to"] == ["dangerous"]
    assert risks["docker_bake_output"] == ["dangerous"]
    assert risks["docker_bake_attestation"] == ["dangerous", "safe"]
    assert risks["docker_bake_source_policy"] == ["dangerous"]
    assert risks["docker_bake_matrix"] == ["review"]
    assert risks["docker_bake_secret_variable"] == ["dangerous"]
    assert risks["docker_bake_environment_override_boundary"] == ["review"]
    assert risks["docker_bake_custom_function"] == ["review"]
    assert risks["docker_bake_evaluation_boundary"] == ["review"]

    payload = analyze_docker_bake(data)
    serialized = json.dumps(payload)
    assert payload["adapter"] == "docker-bake"
    assert payload["artifact_type"] == "hcl"
    assert payload["decision"] == "block"
    assert "literal-build-token-must-not-leak" not in serialized
    assert "literal-build-arg-must-not-leak" not in serialized


def test_json_bake_accepts_immutable_context_and_local_delete_output() -> None:
    data = parse_docker_bake(
        json.dumps(
            {
                "target": {
                    "release": {
                        "context": (
                            "https://github.com/example/app.git#"
                            "0123456789abcdef0123456789abcdef01234567"
                        ),
                        "network": "none",
                        "output": [{"type": "local", "dest": "dist", "mode": "delete"}],
                        "attest": [{"type": "provenance"}, {"type": "sbom"}],
                    }
                }
            }
        ),
        "docker-bake.json",
    )
    risks = _risks(data)
    assert risks["docker_bake_context"] == ["review"]
    assert risks["docker_bake_network"] == ["safe"]
    assert risks["docker_bake_output"] == ["irreversible"]
    assert risks["docker_bake_attestation"] == ["safe", "safe"]


def test_compose_bake_translates_build_and_x_bake_fields() -> None:
    data = parse_docker_bake(
        """
services:
  api:
    image: registry.example.com/api:latest
    build:
      context: https://github.com/example/api.git#main
      dockerfile: Dockerfile
      secrets:
        - source: npm_token
      x-bake:
        platforms: [linux/amd64, linux/arm64]
        cache-to:
          - type: registry
            ref: registry.example.com/api:cache
""",
        "compose.yaml",
    )
    assert data["docker_bake"]["representation"] == "compose"
    target = data["docker_bake"]["document"]["target"]["api"]
    assert target["platforms"] == ["linux/amd64", "linux/arm64"]
    assert target["tags"] == ["registry.example.com/api:latest"]
    risks = _risks(data)
    assert risks["docker_bake_context"] == ["dangerous"]
    assert risks["docker_bake_secret_mount"] == ["review"]
    assert risks["docker_bake_cache_to"] == ["dangerous"]
    assert risks["docker_bake_image_tag"] == ["dangerous"]


def test_compose_bake_supports_yaml_anchors_and_merge_overrides() -> None:
    data = parse_docker_bake(
        """
services:
  base:
    build: &shared
      context: .
      dockerfile: Dockerfile
  release:
    build:
      <<: *shared
      target: release
      x-bake:
        platforms: [linux/amd64, linux/arm64]
""",
        "compose.yaml",
    )

    release = data["docker_bake"]["document"]["target"]["release"]
    assert release["context"] == "."
    assert release["dockerfile"] == "Dockerfile"
    assert release["target"] == "release"
    assert release["platforms"] == ["linux/amd64", "linux/arm64"]


def test_unknown_graph_references_and_inheritance_cycles_block() -> None:
    data = parse_docker_bake(
        """
group "default" { targets = ["missing"] }
target "a" { inherits = ["b"] }
target "b" { inherits = ["a"] }
""",
        "docker-bake.hcl",
    )
    risks = _risks(data)
    assert risks["docker_bake_group_target"] == ["dangerous"]
    assert risks["docker_bake_inheritance_cycle"] == ["dangerous"]


def test_cli_and_framework_baseline_redact_literal_values(capsys) -> None:
    path = FIXTURES / "docker-bake.risky.hcl"
    assert main(["docker-bake", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "docker-bake"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
    assert "literal-build-token-must-not-leak" not in json.dumps(payload)


@pytest.mark.parametrize(
    ("source", "filename"),
    [
        ("", "docker-bake.hcl"),
        ("resource \"x\" \"y\" {}", "docker-bake.hcl"),
        ('{"target":{"x":{}},"target":{}}', "docker-bake.json"),
        ("services:\n  api:\n    image: alpine\n", "compose.yaml"),
        ("services:\n  api:\n    build: .\n    build: ..\n", "compose.yaml"),
    ],
)
def test_parser_rejects_invalid_or_duplicate_input(source: str, filename: str) -> None:
    with pytest.raises(DockerBakeInputError):
        parse_docker_bake(source, filename)
