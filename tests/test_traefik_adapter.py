from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.traefik import TraefikAdapter, TraefikInputError, parse_traefik_config
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(fixture: str) -> dict[str, list[str]]:
    data = parse_traefik_config((FIXTURES / fixture).read_text(encoding="utf-8"))
    result: dict[str, list[str]] = defaultdict(list)
    for change in TraefikAdapter().analyze(data, tool_name="Traefik"):
        result[change.resource_type].append(change.risk)
    return result


def test_combined_config_surfaces_static_and_dynamic_trust_boundaries() -> None:
    risks = _risks("traefik_risky.yml")
    assert risks["traefik_entrypoint"] == ["dangerous", "dangerous"]
    assert risks["traefik_insecure_forwarding"] == ["dangerous"]
    assert risks["traefik_provider"] == ["review", "review"]
    assert risks["traefik_default_exposure"] == ["dangerous"]
    assert risks["traefik_provider_endpoint"] == ["dangerous"]
    assert risks["traefik_provider_scope"] == ["dangerous"]
    assert risks["traefik_api_dashboard"] == ["dangerous"]
    assert risks["traefik_acme"] == ["dangerous"]
    assert risks["traefik_plugin"] == ["dangerous"]
    assert risks["traefik_router"] == ["review"]
    assert risks["traefik_middleware"] == ["dangerous", "dangerous", "dangerous"]
    assert "dangerous" in risks["traefik_tls"]
    assert risks["traefik_upstream"] == ["dangerous"]
    assert risks["traefik_certificate_material"] == ["dangerous"]
    assert risks["traefik_tls_options"] == ["dangerous"]


def test_toml_static_config_is_supported() -> None:
    data = parse_traefik_config(
        (FIXTURES / "traefik_static.toml").read_text(encoding="utf-8")
    )
    assert data["traefik_config"]["artifact_type"] == "static"
    changes = TraefikAdapter().analyze(data, tool_name="Traefik")
    by_type = {change.resource_type: change.risk for change in changes}
    assert by_type["traefik_entrypoint"] == "review"
    assert by_type["traefik_provider"] == "review"
    assert by_type["traefik_api_dashboard"] == "review"


def test_traefik_cli_and_framework_baseline(capsys) -> None:
    assert main(["traefik", "--framework", "soc2", str(FIXTURES / "traefik_risky.yml")]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "traefik"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize("source", ["", "[]", "foo: bar", "[broken"])
def test_parser_rejects_non_traefik_input(source: str) -> None:
    with pytest.raises(TraefikInputError):
        parse_traefik_config(source)
