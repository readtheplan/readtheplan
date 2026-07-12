from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class OTelCollectorInputError(ValueError):
    """Raised when YAML is not recognizable as Collector configuration."""


_COMPONENT_SECTIONS = ("receivers", "processors", "exporters", "connectors", "extensions")
_HOST_RECEIVERS = {
    "docker_stats",
    "filelog",
    "hostmetrics",
    "journald",
    "k8s_cluster",
    "kubeletstats",
    "syslog",
    "windowseventlog",
}
_AUTH_EXTENSIONS = {
    "asapclient",
    "asapserver",
    "basicauth",
    "bearertokenauth",
    "googleclientauth",
    "headers_setter",
    "oauth2client",
    "oidc",
    "sigv4auth",
}
_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|authorization|client[_-]?secret|credential|password|secret|token)(?:$|[_-])",
    re.IGNORECASE,
)
_CONF_PROVIDER = re.compile(r"\$\{(?P<provider>file|http|https|env|yaml):(?P<value>[^}]+)\}")


def parse_otel_collector_config(source: str) -> dict[str, Any]:
    """Parse one OpenTelemetry Collector YAML configuration fragment."""
    if not source.strip():
        raise OTelCollectorInputError("input is empty")
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise OTelCollectorInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise OTelCollectorInputError("Collector configuration must be a YAML object")
    if not (set(_COMPONENT_SECTIONS) | {"service"}) & set(document):
        raise OTelCollectorInputError("no Collector components or service section found")
    for section in _COMPONENT_SECTIONS:
        if section in document and not isinstance(document[section], dict):
            raise OTelCollectorInputError(f"{section} must be a mapping")
    if "service" in document and not isinstance(document["service"], dict):
        raise OTelCollectorInputError("service must be a mapping")
    return {"otel_collector": {"document": document}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _walk(value: Any, path: str = ""):
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from _walk(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")


def _component_type(identifier: str) -> str:
    return identifier.split("/", 1)[0]


def _public_endpoint(endpoint: str) -> bool:
    host = endpoint.rsplit(":", 1)[0].strip("[]").lower() if ":" in endpoint else endpoint
    return host in {"", "0.0.0.0", "::", "*"} or not host.startswith(
        ("127.", "localhost", "::1", "/")
    )


class OTelCollectorAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "otel-collector"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("otel_collector")
        return isinstance(config, dict) and isinstance(config.get("document"), dict)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        document = input_data["otel_collector"]["document"]
        changes: list[dict[str, Any]] = []
        definitions: dict[str, set[str]] = {}
        for section in _COMPONENT_SECTIONS:
            raw_components = document.get(section)
            components = raw_components if isinstance(raw_components, dict) else {}
            definitions[section] = {str(name) for name in components}
            for name, config in components.items():
                address = f"{section}.{name}"
                if not isinstance(config, dict):
                    config = {}
                changes.extend(self._component(section, str(name), config, address))
        changes.extend(self._service(document.get("service"), definitions))
        for path, value in _walk(document):
            if isinstance(value, str):
                changes.extend(self._providers(value, path))
        changes.append(
            _change(
                "otel_collector.effective_configuration",
                "effective_configuration",
                "review",
                "Effective Collector behavior combines merged config providers, distribution "
                "components, environment/proxy settings, command-line overrides, and runtime "
                "state.",
            )
        )
        return changes

    def _component(
        self, section: str, name: str, config: dict[str, Any], address: str
    ) -> list[dict[str, Any]]:
        component = _component_type(name)
        if section == "receivers":
            changes = self._receiver(component, config, address)
        elif section == "exporters":
            changes = self._exporter(component, config, address)
        elif section == "processors":
            changes = self._processor(component, config, address)
        elif section == "extensions":
            changes = self._extension(component, config, address)
        else:
            changes = [
                _change(
                    address,
                    "connector",
                    "review",
                    "Collector connector routes, summarizes, replicates, or transforms telemetry "
                    "between pipelines.",
                )
            ]
        changes.extend(self._config_security(config, address))
        return changes

    def _receiver(
        self, component: str, config: dict[str, Any], address: str
    ) -> list[dict[str, Any]]:
        risk = "dangerous" if component in _HOST_RECEIVERS else "review"
        changes = [
            _change(
                address,
                "receiver",
                risk,
                "Collector receiver ingests telemetry from network, cloud, host, container, or "
                "filesystem sources.",
            )
        ]
        for path, value in _walk(config, address):
            if path.endswith(".endpoint") and isinstance(value, str):
                public = _public_endpoint(value)
                parent = self._parent_config(config, path.removeprefix(address + "."))
                protected = isinstance(parent, dict) and (
                    isinstance(parent.get("tls"), dict) or parent.get("auth") is not None
                )
                changes.append(
                    _change(
                        path,
                        "receiver_endpoint",
                        "dangerous" if public and not protected else "review",
                        "Collector receiver endpoint controls network exposure; public listeners "
                        "should require TLS and authentication.",
                    )
                )
        return changes

    def _exporter(
        self, component: str, config: dict[str, Any], address: str
    ) -> list[dict[str, Any]]:
        explanation = (
            "Collector debug exporter can emit telemetry payloads and sensitive attributes to logs."
            if component in {"debug", "logging"}
            else "Collector exporter sends telemetry and attributes to an external backend or file."
        )
        return [_change(address, "exporter", "dangerous", explanation)]

    def _processor(
        self, component: str, config: dict[str, Any], address: str
    ) -> list[dict[str, Any]]:
        if component in {"batch", "memory_limiter", "redaction"}:
            risk = "safe"
        else:
            risk = "review"
        return [
            _change(
                address,
                "processor",
                risk,
                "Collector processor can transform, enrich, sample, redact, or drop telemetry; "
                "processor order is significant.",
            )
        ]

    def _extension(
        self, component: str, config: dict[str, Any], address: str
    ) -> list[dict[str, Any]]:
        if component in _AUTH_EXTENSIONS:
            risk = "dangerous"
            explanation = "Collector authentication extension handles credentials or identity."
        elif component in {"file_storage", "db_storage"}:
            risk = "dangerous"
            explanation = "Collector storage extension reads or writes persistent host data."
        else:
            risk = "review"
            explanation = "Collector extension adds diagnostics, discovery, forwarding, or control."
        changes = [_change(address, "extension", risk, explanation)]
        if component in {"health_check", "pprof", "zpages"}:
            endpoint = str(config.get("endpoint") or "")
            if endpoint:
                changes.append(
                    _change(
                        f"{address}.endpoint",
                        "diagnostic_endpoint",
                        "dangerous" if _public_endpoint(endpoint) else "review",
                        "Collector diagnostic endpoint may expose health, profiling, traces, or "
                        "runtime internals.",
                    )
                )
        return changes

    def _config_security(self, config: dict[str, Any], address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for path, value in _walk(config, address):
            key = path.rsplit(".", 1)[-1].split("[")[0]
            if key in {"headers", "auth", "authentication"} or _SECRET_KEY.search(key):
                changes.append(
                    _change(
                        path,
                        "credential",
                        "dangerous",
                        "Collector component references authentication headers, tokens, or "
                        "secrets.",
                    )
                )
            if key in {"tls", "tls_config"} and isinstance(value, dict):
                insecure = (
                    value.get("insecure") is True
                    or value.get("insecure_skip_verify") is True
                )
                changes.append(
                    _change(
                        path,
                        "tls",
                        "dangerous" if insecure else "review",
                        "Collector TLS settings control encryption, peer verification, and "
                        "certificate identity.",
                    )
                )
        return changes

    def _service(
        self, service: Any, definitions: dict[str, set[str]]
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if not isinstance(service, dict):
            return [
                _change(
                    "service",
                    "unresolved_service",
                    "review",
                    "Collector fragment has no service activation section; final merged pipelines "
                    "are outside this artifact.",
                )
            ]
        pipelines = service.get("pipelines")
        if not isinstance(pipelines, dict) or not pipelines:
            changes.append(
                _change(
                    "service.pipelines",
                    "unresolved_service",
                    "review",
                    "Collector service has no statically analyzable pipelines.",
                )
            )
        else:
            for name, pipeline in pipelines.items():
                address = f"service.pipelines.{name}"
                changes.append(
                    _change(
                        address,
                        "pipeline",
                        "review",
                        "Collector pipeline activates ordered telemetry receivers, processors, "
                        "connectors, and exporters.",
                    )
                )
                if not isinstance(pipeline, dict):
                    continue
                for key in ("receivers", "processors", "exporters"):
                    references = pipeline.get(key, [])
                    values = references if isinstance(references, list) else []
                    if key in {"receivers", "exporters"} and not values:
                        changes.append(
                            _change(
                                f"{address}.{key}",
                                "incomplete_pipeline",
                                "dangerous",
                                f"Collector pipeline has no {key}; telemetry flow is incomplete.",
                            )
                        )
                    for reference in values:
                        identifier = str(reference)
                        valid = (
                            identifier in definitions[key]
                            or identifier in definitions["connectors"]
                        )
                        if not valid:
                            changes.append(
                                _change(
                                    f"{address}.{key}.{identifier}",
                                    "unresolved_component",
                                    "dangerous",
                                    "Pipeline references a component not defined in this artifact; "
                                    "verify merged configuration.",
                                )
                            )
        enabled_extensions = service.get("extensions", [])
        for extension in enabled_extensions if isinstance(enabled_extensions, list) else []:
            if str(extension) not in definitions["extensions"]:
                changes.append(
                    _change(
                        f"service.extensions.{extension}",
                        "unresolved_component",
                        "dangerous",
                        "Service enables an extension not defined in this artifact.",
                    )
                )
        telemetry = service.get("telemetry")
        if isinstance(telemetry, dict):
            for path, value in _walk(telemetry, "service.telemetry"):
                if path.endswith(".level") and str(value).lower() == "debug":
                    changes.append(
                        _change(
                            path,
                            "debug_telemetry",
                            "dangerous",
                            "Collector debug telemetry can expose configuration and payload "
                            "details.",
                        )
                    )
                if path.endswith(".address") and isinstance(value, str):
                    changes.append(
                        _change(
                            path,
                            "telemetry_endpoint",
                            "dangerous" if _public_endpoint(value) else "review",
                            "Collector self-telemetry endpoint exposes operational metrics.",
                        )
                    )
        return changes

    def _providers(self, value: str, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for match in _CONF_PROVIDER.finditer(value):
            provider = match.group("provider")
            target = match.group("value")
            credential = provider == "env" and _SECRET_KEY.search(target)
            risk = "dangerous" if provider in {"file", "http", "https"} or credential else "review"
            changes.append(
                _change(
                    address,
                    "configuration_provider",
                    risk,
                    f"Collector configuration expands {provider}: input outside this artifact.",
                )
            )
        return changes

    def _parent_config(self, config: dict[str, Any], relative_path: str) -> Any:
        current: Any = config
        parts = relative_path.rsplit(".", 1)[0].split(".")
        for part in parts:
            if not isinstance(current, dict):
                return None
            current = current.get(part.split("[")[0])
        return current

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"otel_collector_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_otel_collector(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = OTelCollectorAdapter().analyze(data, tool_name="OpenTelemetry Collector")
    summary = PlanSummary(
        path=Path("otel-collector://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="OpenTelemetry Collector")
    gate["adapter"] = "otel-collector"
    gate["total_changes"] = len(changes)
    return gate
