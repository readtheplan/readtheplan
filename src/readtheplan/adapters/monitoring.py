from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class MonitoringInputError(ValueError):
    """Raised when Prometheus or Alertmanager YAML is invalid or unrecognizable."""


_SECRET_KEY = re.compile(
    r"(?:^|_)(?:api_key|auth_token|client_secret|credentials?|password|secret)(?:$|_)",
    re.IGNORECASE,
)
_DISCOVERY_KEYS = {
    "azure_sd_configs",
    "consul_sd_configs",
    "digitalocean_sd_configs",
    "dns_sd_configs",
    "docker_sd_configs",
    "dockerswarm_sd_configs",
    "ec2_sd_configs",
    "eureka_sd_configs",
    "file_sd_configs",
    "gce_sd_configs",
    "hetzner_sd_configs",
    "http_sd_configs",
    "kubernetes_sd_configs",
    "linode_sd_configs",
    "marathon_sd_configs",
    "nerve_sd_configs",
    "nomad_sd_configs",
    "openstack_sd_configs",
    "ovhcloud_sd_configs",
    "puppetdb_sd_configs",
    "scaleway_sd_configs",
    "serverset_sd_configs",
    "triton_sd_configs",
    "uyuni_sd_configs",
    "vultr_sd_configs",
    "xds_sd_configs",
    "zookeeper_sd_configs",
}


def parse_monitoring_config(source: str, ecosystem: str) -> dict[str, Any]:
    """Parse one explicitly selected Prometheus or Alertmanager configuration."""
    if ecosystem not in {"prometheus", "alertmanager"}:
        raise MonitoringInputError(f"unsupported monitoring ecosystem: {ecosystem}")
    if not source.strip():
        raise MonitoringInputError("input is empty")
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise MonitoringInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise MonitoringInputError("configuration must be a YAML object")
    if ecosystem == "prometheus":
        recognized = {"scrape_configs", "remote_write", "remote_read", "rule_files", "alerting"}
    else:
        recognized = {"route", "receivers", "inhibit_rules", "templates", "time_intervals"}
    if not recognized & set(document):
        raise MonitoringInputError(f"input is not recognizable as {ecosystem} configuration")
    return {"monitoring_config": {"ecosystem": ecosystem, "document": document}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


class MonitoringAdapter(BaseAdapter):
    def __init__(self, ecosystem: str) -> None:
        self.ecosystem = ecosystem

    @property
    def adapter_name(self) -> str:
        return self.ecosystem

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("monitoring_config")
        return (
            isinstance(config, dict)
            and config.get("ecosystem") == self.ecosystem
            and isinstance(config.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        document = input_data["monitoring_config"]["document"]
        changes = (
            self._prometheus(document)
            if self.ecosystem == "prometheus"
            else self._alertmanager(document)
        )
        changes.append(
            _change(
                f"{self.ecosystem}.effective_configuration",
                "effective_configuration",
                "review",
                f"Effective {self.ecosystem} behavior also depends on command-line flags, "
                "environment, external files, runtime reload state, and network policy.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"{self.ecosystem}_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )

    def _prometheus(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if document.get("rule_files") is not None:
            changes.append(
                _change(
                    "rule_files",
                    "rule_files",
                    "review",
                    "Prometheus loads recording and alerting expressions from external files.",
                )
            )
        for index, scrape in enumerate(_items(document.get("scrape_configs"))):
            address = f"scrape_configs[{index}]"
            if not isinstance(scrape, dict):
                changes.append(
                    _change(address, "unresolved", "review", "Scrape job is not an object.")
                )
                continue
            changes.append(
                _change(
                    f"{address}.job",
                    "scrape_job",
                    "review",
                    "Prometheus scrape job ingests metrics and labels from selected targets.",
                )
            )
            scheme = str(scrape.get("scheme") or "http").lower()
            if scheme == "http":
                changes.append(
                    _change(
                        f"{address}.scheme",
                        "plaintext_scrape",
                        "dangerous",
                        "Prometheus scrape uses plaintext HTTP; metrics or credentials may be "
                        "exposed in transit.",
                    )
                )
            if scrape.get("honor_labels") is True:
                changes.append(
                    _change(
                        f"{address}.honor_labels",
                        "label_trust",
                        "dangerous",
                        "Scraped targets can override server-assigned labels used for routing "
                        "and tenancy.",
                    )
                )
            for key in _DISCOVERY_KEYS:
                if scrape.get(key) is not None:
                    changes.append(
                        _change(
                            f"{address}.{key}",
                            "service_discovery",
                            "dangerous" if key != "dns_sd_configs" else "review",
                            f"Prometheus {key} imports targets and may use external APIs, files, "
                            "or ambient cloud credentials.",
                        )
                    )
            if scrape.get("static_configs") is not None:
                changes.append(
                    _change(
                        f"{address}.static_configs",
                        "static_targets",
                        "review",
                        "Static targets define endpoints from which Prometheus ingests data.",
                    )
                )
            for key in ("relabel_configs", "metric_relabel_configs"):
                if scrape.get(key) is not None:
                    changes.append(
                        _change(
                            f"{address}.{key}",
                            "relabeling",
                            "review",
                            "Relabeling can rewrite targets, labels, metric identity, and "
                            "retention.",
                        )
                    )
            changes.extend(self._http_config(scrape, address))
        for key, kind, explanation in (
            ("remote_write", "remote_write", "exports samples and metadata to remote storage"),
            ("remote_read", "remote_read", "imports query data from remote storage"),
        ):
            for index, remote in enumerate(_items(document.get(key))):
                address = f"{key}[{index}]"
                changes.append(
                    _change(
                        address,
                        kind,
                        "dangerous",
                        f"Prometheus {explanation}; verify endpoint, tenant, retention, and trust.",
                    )
                )
                if isinstance(remote, dict):
                    changes.extend(self._http_config(remote, address))
        alerting = document.get("alerting")
        if isinstance(alerting, dict) and alerting.get("alertmanagers") is not None:
            changes.append(
                _change(
                    "alerting.alertmanagers",
                    "alert_delivery",
                    "review",
                    "Prometheus sends alert labels and annotations to configured Alertmanagers.",
                )
            )
        if document.get("otlp") is not None:
            changes.append(
                _change(
                    "otlp",
                    "otlp_ingest",
                    "review",
                    "Prometheus OTLP ingestion changes accepted telemetry and attribute mapping.",
                )
            )
        return changes

    def _http_config(self, config: dict[str, Any], address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for key in ("basic_auth", "authorization", "oauth2", "sigv4", "azuread", "google_iam"):
            if config.get(key) is not None:
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "authentication",
                        "dangerous",
                        f"HTTP client {key} uses credential material or ambient identity.",
                    )
                )
        tls = config.get("tls_config")
        if isinstance(tls, dict):
            insecure = tls.get("insecure_skip_verify") is True
            changes.append(
                _change(
                    f"{address}.tls_config",
                    "tls",
                    "dangerous" if insecure else "review",
                    "TLS configuration controls peer verification, CA trust, and client identity.",
                )
            )
        if config.get("proxy_url") is not None or config.get("proxy_from_environment") is True:
            changes.append(
                _change(
                    f"{address}.proxy",
                    "proxy",
                    "review",
                    "HTTP proxy settings redirect telemetry and credentials through another host.",
                )
            )
        return changes

    def _alertmanager(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        global_config = document.get("global")
        if isinstance(global_config, dict):
            if global_config.get("smtp_require_tls") is False:
                changes.append(
                    _change(
                        "global.smtp_require_tls",
                        "plaintext_smtp",
                        "dangerous",
                        "Alertmanager permits SMTP notification delivery without required TLS.",
                    )
                )
            changes.extend(self._secret_fields(global_config, "global"))
            changes.extend(self._http_config(global_config, "global"))
        route = document.get("route")
        if isinstance(route, dict):
            changes.append(
                _change(
                    "route",
                    "routing",
                    "review",
                    "Alertmanager routing controls receiver selection, grouping, timing, and "
                    "notification fan-out.",
                )
            )
            if not route.get("receiver"):
                changes.append(
                    _change(
                        "route.receiver",
                        "unresolved_receiver",
                        "dangerous",
                        "Top-level Alertmanager route has no explicit receiver.",
                    )
                )
        for index, receiver in enumerate(_items(document.get("receivers"))):
            address = f"receivers[{index}]"
            if not isinstance(receiver, dict):
                changes.append(
                    _change(address, "unresolved", "review", "Receiver is not an object.")
                )
                continue
            changes.append(
                _change(
                    address,
                    "receiver",
                    "review",
                    "Alertmanager receiver sends alert labels and annotations to external systems.",
                )
            )
            for key, value in receiver.items():
                if key.endswith("_configs"):
                    changes.append(
                        _change(
                            f"{address}.{key}",
                            "notification_integration",
                            "dangerous",
                            f"Alertmanager {key} delivers alert data to an external integration.",
                        )
                    )
                    for config_index, config in enumerate(_items(value)):
                        if isinstance(config, dict):
                            nested = f"{address}.{key}[{config_index}]"
                            changes.extend(self._secret_fields(config, nested))
                            changes.extend(self._http_config(config, nested))
        if document.get("templates") is not None:
            changes.append(
                _change(
                    "templates",
                    "templates",
                    "review",
                    "Alertmanager imports external notification templates outside this artifact.",
                )
            )
        for key in ("inhibit_rules", "mute_time_intervals", "time_intervals"):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        key,
                        "suppression" if key == "inhibit_rules" else "time_intervals",
                        "review",
                        f"Alertmanager {key} can suppress or delay operational notifications.",
                    )
                )
        if document.get("event_recorder") is not None:
            changes.append(
                _change(
                    "event_recorder",
                    "event_export",
                    "dangerous",
                    "Alertmanager event recorder exports lifecycle, silence, and notification "
                    "data.",
                )
            )
        return changes

    def _secret_fields(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if not isinstance(value, dict):
            return changes
        for key, child in value.items():
            secret_url = str(key) in {"slack_api_url"}
            if secret_url or _SECRET_KEY.search(str(key)) or str(key).endswith(("_file", "_ref")):
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "secret_material",
                        "dangerous",
                        "Monitoring configuration references inline or external credential "
                        "material.",
                    )
                )
            elif isinstance(child, dict):
                changes.extend(self._secret_fields(child, f"{address}.{key}"))
        return changes


class PrometheusAdapter(MonitoringAdapter):
    def __init__(self) -> None:
        super().__init__("prometheus")


class AlertmanagerAdapter(MonitoringAdapter):
    def __init__(self) -> None:
        super().__init__("alertmanager")


def analyze_monitoring(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    config = data.get("monitoring_config")
    ecosystem = str(config.get("ecosystem")) if isinstance(config, dict) else "monitoring"
    adapter: MonitoringAdapter = (
        PrometheusAdapter() if ecosystem == "prometheus" else AlertmanagerAdapter()
    )
    changes = adapter.analyze(data, tool_name=ecosystem)
    summary = PlanSummary(
        path=Path(f"{ecosystem}://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name=ecosystem)
    gate["adapter"] = ecosystem
    gate["total_changes"] = len(changes)
    return gate
