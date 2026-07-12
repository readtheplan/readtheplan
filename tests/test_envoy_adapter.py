from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.envoy import EnvoyAdapter, EnvoyInputError, parse_envoy_config
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(fixture: str) -> dict[str, list[str]]:
    data = parse_envoy_config((FIXTURES / fixture).read_text(encoding="utf-8"))
    result: dict[str, list[str]] = defaultdict(list)
    for change in EnvoyAdapter().analyze(data, tool_name="Envoy"):
        result[change.resource_type].append(change.risk)
    return result


def test_bootstrap_surfaces_admin_xds_runtime_tls_secrets_and_extension_code() -> None:
    risks = _risks("envoy_risky.yaml")
    assert risks["envoy_admin"] == ["dangerous"]
    assert risks["envoy_dynamic_resources"] == ["dangerous"]
    assert risks["envoy_runtime_layers"] == ["dangerous"]
    assert risks["envoy_xds_source"]
    assert risks["envoy_secret_material"] == ["dangerous"]
    assert risks["envoy_tls_validation"] == ["dangerous"]
    assert "dangerous" in risks["envoy_filter"]
    assert risks["envoy_inline_code"] == ["dangerous"]
    assert risks["envoy_authorization_fail_open"] == ["dangerous"]
    assert risks["envoy_effective_configuration"] == ["review"]


def test_config_dump_is_accepted_as_runtime_snapshot() -> None:
    risks = _risks("envoy_config_dump.json")
    assert risks["envoy_runtime_snapshot"] == ["review"]
    assert risks["envoy_listener_or_endpoint"] == ["review"]
    assert risks["envoy_filter"] == ["review"]


def test_strong_validation_context_and_local_admin_reduce_risk() -> None:
    data = parse_envoy_config(
        "admin:\n"
        "  address:\n"
        "    socket_address: {address: 127.0.0.1, port_value: 9901}\n"
        "static_resources:\n"
        "  clusters:\n"
        "    - name: secure\n"
        "      transport_socket:\n"
        "        typed_config:\n"
        "          validation_context:\n"
        "            trusted_ca: {filename: /etc/ca.pem}\n"
        "            match_typed_subject_alt_names: [{san_type: DNS}]\n"
    )
    risks: dict[str, list[str]] = defaultdict(list)
    for change in EnvoyAdapter().analyze(data, tool_name="Envoy"):
        risks[change.resource_type].append(change.risk)
    assert risks["envoy_admin"] == ["review"]
    assert risks["envoy_tls_validation"] == ["safe"]


@pytest.mark.parametrize("fixture", ["envoy_risky.yaml", "envoy_config_dump.json"])
def test_envoy_cli_and_framework_baseline(capsys, fixture: str) -> None:
    assert main(["envoy", "--framework", "soc2", str(FIXTURES / fixture)]) in {1, 2}
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "envoy"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize("source", ["", "[]", "foo: bar", "configs: nope"])
def test_parser_rejects_non_envoy_input(source: str) -> None:
    with pytest.raises(EnvoyInputError):
        parse_envoy_config(source)
