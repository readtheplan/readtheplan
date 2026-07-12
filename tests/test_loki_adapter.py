from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.loki import LokiAdapter, LokiInputError, parse_loki_config
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks() -> dict[str, list[str]]:
    data = parse_loki_config((FIXTURES / "loki_risky.yml").read_text(encoding="utf-8"))
    result: dict[str, list[str]] = defaultdict(list)
    for change in LokiAdapter().analyze(data, tool_name="loki"):
        result[change.resource_type].append(change.risk)
    return result


def test_loki_surfaces_auth_server_storage_limits_ruler_and_retention() -> None:
    risks = _risks()
    assert risks["loki_authentication_boundary"] == ["review"]
    assert risks["loki_single_tenant_mode"] == ["dangerous"]
    assert len(risks["loki_public_listener"]) == 2
    assert risks["loki_weak_client_auth"] == ["dangerous"]
    assert risks["loki_single_replica"] == ["dangerous"]
    assert len(risks["loki_storage_backend"]) == 2
    assert len(risks["loki_plaintext_egress"]) >= 2
    assert risks["loki_storage_schema"] == ["review"]
    assert risks["loki_cluster_membership"] == ["dangerous"]
    assert len(risks["loki_unbounded_limit"]) == 2
    assert risks["loki_retention_policy"] == ["dangerous"]
    assert risks["loki_runtime_configuration"] == ["dangerous"]
    assert risks["loki_mutable_rule_api"] == ["dangerous"]
    assert len(risks["loki_rule_egress"]) == 2
    assert risks["loki_retention_deletion"] == ["dangerous"]
    assert risks["loki_query_egress"] == ["dangerous"]
    assert len(risks["loki_insecure_tls"]) >= 1
    assert len(risks["loki_secret_material"]) >= 3


def test_secure_minimal_loki_keeps_boundary_visible() -> None:
    data = parse_loki_config(
        "auth_enabled: true\n"
        "target: all\n"
        "server: {http_listen_address: 127.0.0.1}\n"
        "common: {replication_factor: 3}\n"
    )
    changes = LokiAdapter().analyze(data, tool_name="loki")
    kinds = {change.resource_type: change.risk for change in changes}
    assert "loki_single_tenant_mode" not in kinds
    assert "loki_public_listener" not in kinds
    assert kinds["loki_authentication_boundary"] == "review"


@pytest.mark.parametrize("source", ["", "[]", "route: {}", "{broken"])
def test_parser_rejects_invalid_or_unrecognized_input(source: str) -> None:
    with pytest.raises(LokiInputError):
        parse_loki_config(source)


def test_loki_cli_supports_framework_checks(capsys) -> None:
    assert main(["loki", "--framework", "soc2", str(FIXTURES / "loki_risky.yml")]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "loki"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
