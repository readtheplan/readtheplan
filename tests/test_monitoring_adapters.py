from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.monitoring import (
    AlertmanagerAdapter,
    MonitoringInputError,
    PrometheusAdapter,
    parse_monitoring_config,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(ecosystem: str, fixture: str) -> dict[str, list[str]]:
    data = parse_monitoring_config(
        (FIXTURES / fixture).read_text(encoding="utf-8"), ecosystem
    )
    adapter = PrometheusAdapter() if ecosystem == "prometheus" else AlertmanagerAdapter()
    result: dict[str, list[str]] = defaultdict(list)
    for change in adapter.analyze(data, tool_name=ecosystem):
        result[change.resource_type].append(change.risk)
    return result


def test_prometheus_surfaces_discovery_ingest_egress_auth_and_tls() -> None:
    risks = _risks("prometheus", "prometheus_risky.yml")
    assert risks["prometheus_rule_files"] == ["review"]
    assert risks["prometheus_plaintext_scrape"] == ["dangerous"]
    assert risks["prometheus_label_trust"] == ["dangerous"]
    assert risks["prometheus_service_discovery"] == ["dangerous"]
    assert risks["prometheus_static_targets"] == ["review"]
    assert risks["prometheus_authentication"] == ["dangerous", "dangerous"]
    assert risks["prometheus_tls"] == ["dangerous", "dangerous"]
    assert risks["prometheus_remote_write"] == ["dangerous"]
    assert risks["prometheus_remote_read"] == ["dangerous"]
    assert risks["prometheus_alert_delivery"] == ["review"]
    assert risks["prometheus_otlp_ingest"] == ["review"]


def test_alertmanager_surfaces_routing_integrations_secrets_and_suppression() -> None:
    risks = _risks("alertmanager", "alertmanager_risky.yml")
    assert risks["alertmanager_plaintext_smtp"] == ["dangerous"]
    assert len(risks["alertmanager_secret_material"]) >= 3
    assert risks["alertmanager_routing"] == ["review"]
    assert risks["alertmanager_receiver"] == ["review", "review"]
    assert risks["alertmanager_notification_integration"] == ["dangerous", "dangerous"]
    assert risks["alertmanager_authentication"] == ["dangerous"]
    assert risks["alertmanager_tls"] == ["dangerous"]
    assert risks["alertmanager_templates"] == ["review"]
    assert risks["alertmanager_suppression"] == ["review"]
    assert risks["alertmanager_event_export"] == ["dangerous"]


def test_secure_prometheus_https_tls_is_review_not_dangerous() -> None:
    data = parse_monitoring_config(
        "scrape_configs:\n"
        "  - job_name: local\n"
        "    scheme: https\n"
        "    static_configs: [{targets: ['127.0.0.1:9090']}]\n"
        "    tls_config: {ca_file: /etc/ca.pem, server_name: localhost}\n",
        "prometheus",
    )
    changes = PrometheusAdapter().analyze(data, tool_name="prometheus")
    risks = {change.resource_type: change.risk for change in changes}
    assert "prometheus_plaintext_scrape" not in risks
    assert risks["prometheus_tls"] == "review"


@pytest.mark.parametrize(
    ("ecosystem", "fixture"),
    [
        ("prometheus", "prometheus_risky.yml"),
        ("alertmanager", "alertmanager_risky.yml"),
    ],
)
def test_monitoring_cli_and_framework_baseline(
    capsys, ecosystem: str, fixture: str
) -> None:
    assert main([ecosystem, "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == ecosystem
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize(
    ("ecosystem", "source"),
    [
        ("prometheus", ""),
        ("prometheus", "route: {}"),
        ("alertmanager", "scrape_configs: []"),
        ("alertmanager", "[]"),
        ("unknown", "foo: bar"),
    ],
)
def test_monitoring_parser_rejects_wrong_shapes(ecosystem: str, source: str) -> None:
    with pytest.raises(MonitoringInputError):
        parse_monitoring_config(source, ecosystem)
