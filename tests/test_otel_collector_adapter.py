from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.otel_collector import (
    OTelCollectorAdapter,
    OTelCollectorInputError,
    parse_otel_collector_config,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(source: str) -> dict[str, list[str]]:
    data = parse_otel_collector_config(source)
    result: dict[str, list[str]] = defaultdict(list)
    for change in OTelCollectorAdapter().analyze(data, tool_name="OpenTelemetry Collector"):
        result[change.resource_type].append(change.risk)
    return result


def test_collector_surfaces_endpoints_host_data_egress_auth_tls_and_refs() -> None:
    source = (FIXTURES / "otel_collector_risky.yml").read_text(encoding="utf-8")
    risks = _risks(source)
    assert risks["otel_collector_receiver"] == ["review", "dangerous"]
    assert risks["otel_collector_receiver_endpoint"] == ["dangerous", "dangerous"]
    assert risks["otel_collector_exporter"] == ["dangerous", "dangerous"]
    assert risks["otel_collector_credential"]
    assert risks["otel_collector_tls"] == ["dangerous"]
    assert risks["otel_collector_processor"] == ["safe", "safe", "review"]
    assert risks["otel_collector_connector"] == ["review"]
    assert "dangerous" in risks["otel_collector_extension"]
    assert risks["otel_collector_diagnostic_endpoint"] == ["dangerous", "dangerous"]
    assert risks["otel_collector_unresolved_component"] == ["dangerous", "dangerous"]
    assert risks["otel_collector_debug_telemetry"] == ["dangerous"]
    assert risks["otel_collector_configuration_provider"] == ["dangerous"]


def test_local_tls_receiver_and_complete_pipeline_reduce_risk() -> None:
    risks = _risks(
        "receivers:\n"
        "  otlp:\n"
        "    protocols:\n"
        "      grpc:\n"
        "        endpoint: 127.0.0.1:4317\n"
        "        tls: {cert_file: /etc/cert.pem, key_file: /etc/key.pem}\n"
        "processors: {batch: {}}\n"
        "exporters:\n"
        "  otlp:\n"
        "    endpoint: backend:4317\n"
        "    tls: {ca_file: /etc/ca.pem}\n"
        "service:\n"
        "  pipelines:\n"
        "    traces: {receivers: [otlp], processors: [batch], exporters: [otlp]}\n"
    )
    assert risks["otel_collector_receiver_endpoint"] == ["review"]
    assert risks["otel_collector_tls"] == ["review", "review"]
    assert "otel_collector_unresolved_component" not in risks
    assert "otel_collector_incomplete_pipeline" not in risks


def test_fragment_without_service_surfaces_merge_boundary() -> None:
    risks = _risks("receivers: {otlp: {}}\n")
    assert risks["otel_collector_unresolved_service"] == ["review"]


def test_collector_cli_and_framework_baseline(capsys) -> None:
    assert (
        main(
            [
                "otel-collector",
                "--framework",
                "soc2",
                str(FIXTURES / "otel_collector_risky.yml"),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "otel-collector"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize("source", ["", "[]", "foo: bar", "receivers: [otlp]"])
def test_parser_rejects_non_collector_input(source: str) -> None:
    with pytest.raises(OTelCollectorInputError):
        parse_otel_collector_config(source)
