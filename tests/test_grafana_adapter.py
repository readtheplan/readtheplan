from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.grafana import (
    GrafanaAdapter,
    GrafanaInputError,
    parse_grafana_config,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(fixture: str) -> dict[str, list[str]]:
    data = parse_grafana_config((FIXTURES / fixture).read_text(encoding="utf-8"))
    result: dict[str, list[str]] = defaultdict(list)
    for change in GrafanaAdapter().analyze(data, tool_name="grafana"):
        result[change.resource_type].append(change.risk)
    return result


def test_ini_surfaces_server_auth_storage_plugins_and_browser_risks() -> None:
    risks = _risks("grafana_risky.ini")
    assert risks["grafana_plaintext_server"] == ["dangerous"]
    assert risks["grafana_public_listener"] == ["dangerous"]
    assert risks["grafana_anonymous_access"] == ["dangerous"]
    assert risks["grafana_trusted_auth_proxy"] == ["dangerous"]
    assert risks["grafana_unrestricted_auth_proxy"] == ["dangerous"]
    assert risks["grafana_external_authentication"] == ["review"]
    assert risks["grafana_admin_role_mapping"] == ["dangerous"]
    assert risks["grafana_self_registration"] == ["dangerous"]
    assert risks["grafana_privileged_default_role"] == ["dangerous"]
    assert risks["grafana_plaintext_database"] == ["dangerous"]
    assert risks["grafana_plaintext_smtp"] == ["dangerous"]
    assert risks["grafana_unsigned_plugin"] == ["dangerous"]
    assert risks["grafana_wildcard_origin"] == ["dangerous"]
    assert len(risks["grafana_secret_material"]) >= 4


def test_provisioning_surfaces_data_dashboard_alert_plugin_and_rbac_risks() -> None:
    risks = _risks("grafana_provisioning_risky.yml")
    assert len(risks["grafana_resource_deletion"]) == 5
    assert risks["grafana_datasource"] == ["review"]
    assert risks["grafana_plaintext_datasource"] == ["dangerous"]
    assert risks["grafana_browser_datasource"] == ["dangerous"]
    assert risks["grafana_insecure_tls"] == ["dangerous"]
    assert risks["grafana_identity_forwarding"] == ["dangerous"]
    assert risks["grafana_dashboard_provider"] == ["review"]
    assert risks["grafana_alert_rules"] == ["review"]
    assert risks["grafana_notification_egress"] == ["dangerous"]
    assert risks["grafana_alert_suppression"] == ["dangerous"]
    assert risks["grafana_plugin"] == ["dangerous"]
    assert risks["grafana_access_control"] == ["dangerous"]
    assert risks["grafana_wildcard_permission"] == ["dangerous"]
    assert risks["grafana_role_assignment"] == ["dangerous"]


def test_secure_ini_has_review_only_effective_configuration() -> None:
    data = parse_grafana_config(
        "[server]\nprotocol = https\nhttp_addr = 127.0.0.1\n"
        "[security]\ncookie_secure = true\ncookie_samesite = strict\n"
        "[auth.anonymous]\nenabled = false\n"
    )
    changes = GrafanaAdapter().analyze(data, tool_name="grafana")
    assert [(change.resource_type, change.risk) for change in changes] == [
        ("grafana_effective_configuration", "review")
    ]


def test_json_provisioning_is_supported() -> None:
    data = parse_grafana_config(
        json.dumps(
            {"apiVersion": 1, "datasources": [{"name": "metrics", "url": "https://metrics"}]}
        )
    )
    assert data["grafana_config"]["artifact_type"] == "provisioning"


@pytest.mark.parametrize("source", ["", "foo: bar", "[]", "[unrelated]\nfoo = bar"])
def test_parser_rejects_unrecognized_inputs(source: str) -> None:
    with pytest.raises(GrafanaInputError):
        parse_grafana_config(source)


@pytest.mark.parametrize("fixture", ["grafana_risky.ini", "grafana_provisioning_risky.yml"])
def test_cli_supports_framework_checks(capsys, fixture: str) -> None:
    assert main(["grafana", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "grafana"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
