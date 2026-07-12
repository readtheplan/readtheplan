from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class TraefikInputError(ValueError):
    """Raised when input is not recognizable Traefik file configuration."""


_STATIC_KEYS = {
    "api",
    "certificatesResolvers",
    "entryPoints",
    "experimental",
    "metrics",
    "providers",
    "serversTransport",
    "tracing",
}
_DYNAMIC_KEYS = {"http", "tcp", "tls", "udp"}


def _load_toml(source: str) -> dict[str, Any] | None:
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]
        parsed = tomllib.loads(source)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def parse_traefik_config(source: str) -> dict[str, Any]:
    """Parse Traefik static/dynamic YAML, JSON, or TOML file configuration."""
    if not source.strip():
        raise TraefikInputError("input is empty")
    try:
        parsed = yaml.safe_load(source)
    except yaml.YAMLError:
        parsed = None
    if not isinstance(parsed, dict):
        parsed = _load_toml(source)
    if not isinstance(parsed, dict):
        raise TraefikInputError("configuration is not valid YAML, JSON, or TOML")
    static = bool(_STATIC_KEYS & set(parsed))
    dynamic = bool(_DYNAMIC_KEYS & set(parsed))
    if not static and not dynamic:
        raise TraefikInputError("no recognized Traefik static or dynamic sections found")
    artifact_type = "combined" if static and dynamic else "static" if static else "dynamic"
    return {"traefik_config": {"artifact_type": artifact_type, "document": parsed}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _public_endpoint(value: str) -> bool:
    endpoint = value.strip()
    host = endpoint.rsplit(":", 1)[0].strip("[]") if ":" in endpoint else endpoint
    return host in {"", "0.0.0.0", "::", "*"} or not host.startswith(
        ("127.", "localhost", "::1", "/", "unix://")
    )


class TraefikAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "traefik"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("traefik_config")
        return (
            isinstance(config, dict)
            and config.get("artifact_type") in {"static", "dynamic", "combined"}
            and isinstance(config.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        config = input_data["traefik_config"]
        document = config["document"]
        changes: list[dict[str, Any]] = []
        if config["artifact_type"] in {"static", "combined"}:
            changes.extend(self._static(document))
        if config["artifact_type"] in {"dynamic", "combined"}:
            changes.extend(self._dynamic(document))
        changes.append(
            _change(
                "traefik.effective_configuration",
                "effective_configuration",
                "review",
                "Effective Traefik behavior combines static startup config, all dynamic providers, "
                "labels/annotations, environment/CLI overrides, plugins, and runtime state.",
            )
        )
        return changes

    def _static(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for name, entrypoint in _mapping(document.get("entryPoints")).items():
            config = _mapping(entrypoint)
            address = str(config.get("address") or "")
            changes.append(
                _change(
                    f"entryPoints.{name}.address",
                    "entrypoint",
                    "dangerous" if not address or _public_endpoint(address) else "review",
                    f"Traefik entry point '{address or 'unresolved'}' accepts inbound traffic.",
                )
            )
            forwarded = _mapping(config.get("forwardedHeaders"))
            proxy = _mapping(config.get("proxyProtocol"))
            if forwarded.get("insecure") is True or proxy.get("insecure") is True:
                changes.append(
                    _change(
                        f"entryPoints.{name}.trustedHeaders",
                        "insecure_forwarding",
                        "dangerous",
                        "Entry point trusts forwarded headers or PROXY protocol from any client.",
                    )
                )
        providers = _mapping(document.get("providers"))
        for name, provider in providers.items():
            config = _mapping(provider)
            address = f"providers.{name}"
            changes.append(
                _change(
                    address,
                    "provider",
                    "review",
                    "Traefik provider imports dynamic routes from infrastructure APIs, files, "
                    "labels, annotations, or key-value stores.",
                )
            )
            if name in {"docker", "swarm", "ecs", "nomad", "consulCatalog"}:
                exposed = config.get("exposedByDefault", True)
                if exposed is True:
                    changes.append(
                        _change(
                            f"{address}.exposedByDefault",
                            "default_exposure",
                            "dangerous",
                            "Provider exposes discovered workloads unless each is explicitly "
                            "disabled.",
                        )
                    )
            endpoint = str(config.get("endpoint") or "")
            if endpoint:
                changes.append(
                    _change(
                        f"{address}.endpoint",
                        "provider_endpoint",
                        "dangerous" if "docker.sock" in endpoint else "review",
                        "Provider endpoint grants discovery access and may expose a privileged "
                        "API.",
                    )
                )
            if config.get("allowCrossNamespace") is True or config.get(
                "allowExternalNameServices"
            ) is True:
                changes.append(
                    _change(
                        f"{address}.scope",
                        "provider_scope",
                        "dangerous",
                        "Provider permits cross-namespace or ExternalName routing beyond local "
                        "scope.",
                    )
                )
            changes.extend(self._tls_findings(config, address))
        api = _mapping(document.get("api"))
        if api:
            changes.append(
                _change(
                    "api",
                    "api_dashboard",
                    "dangerous" if api.get("insecure") is True else "review",
                    "Traefik API/dashboard exposes routing, service, middleware, and runtime "
                    "state.",
                )
            )
        transport = _mapping(document.get("serversTransport"))
        if transport:
            changes.extend(self._tls_findings(transport, "serversTransport"))
        for name, resolver in _mapping(document.get("certificatesResolvers")).items():
            if isinstance(resolver, dict) and resolver.get("acme") is not None:
                changes.append(
                    _change(
                        f"certificatesResolvers.{name}.acme",
                        "acme",
                        "dangerous",
                        "ACME resolver controls certificate issuance, account data, challenge "
                        "credentials, and persistent certificate storage.",
                    )
                )
        experimental = _mapping(document.get("experimental"))
        for key in ("plugins", "localPlugins"):
            if experimental.get(key) is not None:
                changes.append(
                    _change(
                        f"experimental.{key}",
                        "plugin",
                        "dangerous",
                        "Traefik plugin loads executable middleware code into the proxy process.",
                    )
                )
        for key in ("metrics", "tracing", "accessLog"):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        key,
                        "observability",
                        "review",
                        f"Traefik {key} exports request or runtime telemetry to files or backends.",
                    )
                )
        return changes

    def _dynamic(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for protocol in ("http", "tcp", "udp"):
            config = _mapping(document.get(protocol))
            for name, router in _mapping(config.get("routers")).items():
                changes.append(
                    _change(
                        f"{protocol}.routers.{name}",
                        "router",
                        "review",
                        "Traefik router matches inbound traffic and selects middleware, TLS, and "
                        "an upstream service.",
                    )
                )
            for name, service in _mapping(config.get("services")).items():
                address = f"{protocol}.services.{name}"
                changes.append(
                    _change(
                        address,
                        "service",
                        "review",
                        "Traefik service load-balances, mirrors, fails over, or weights upstreams.",
                    )
                )
                for server in _list(_mapping(service).get("loadBalancer", {}).get("servers")):
                    if isinstance(server, dict):
                        target = str(server.get("url") or server.get("address") or "")
                        if target:
                            changes.append(
                                _change(
                                    f"{address}.server.{target}",
                                    "upstream",
                                    "dangerous" if target.startswith("http://") else "review",
                                    "Traefik upstream receives forwarded request data and headers.",
                                )
                            )
            if protocol == "http":
                for name, middleware in _mapping(config.get("middlewares")).items():
                    changes.extend(
                        self._middleware(
                            str(name), _mapping(middleware), f"http.middlewares.{name}"
                        )
                    )
                for name, transport in _mapping(config.get("serversTransports")).items():
                    changes.extend(
                        self._tls_findings(_mapping(transport), f"http.serversTransports.{name}")
                    )
        tls = _mapping(document.get("tls"))
        if tls.get("certificates") is not None or tls.get("stores") is not None:
            changes.append(
                _change(
                    "tls.certificates",
                    "certificate_material",
                    "dangerous",
                    "Traefik dynamic TLS configuration references private keys or default "
                    "certificate material.",
                )
            )
        for name, option in _mapping(tls.get("options")).items():
            config = _mapping(option)
            legacy = str(config.get("minVersion") or "") in {"VersionTLS10", "VersionTLS11"}
            changes.append(
                _change(
                    f"tls.options.{name}",
                    "tls_options",
                    "dangerous" if legacy else "review",
                    "Traefik TLS options control protocol versions, cipher suites, and client "
                    "auth.",
                )
            )
        return changes

    def _middleware(
        self, name: str, config: dict[str, Any], address: str
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for kind, value in config.items():
            risk = "review"
            explanation = f"Traefik {kind} middleware mutates or controls HTTP request handling."
            details = _mapping(value)
            if kind in {"basicAuth", "digestAuth"}:
                risk = "dangerous"
                explanation = "Authentication middleware references inline or external credentials."
            elif kind == "forwardAuth":
                risk = "dangerous"
                explanation = (
                    "ForwardAuth delegates request authorization and headers to a service."
                )
            elif kind == "plugin":
                risk = "dangerous"
                explanation = "Plugin middleware executes extension code in the request path."
            elif kind == "headers":
                origins = details.get("accessControlAllowOriginList", [])
                if "*" in origins:
                    risk = "dangerous"
                    explanation = (
                        "Headers middleware permits cross-origin requests from any origin."
                    )
            changes.append(_change(f"{address}.{kind}", "middleware", risk, explanation))
            changes.extend(self._tls_findings(details, f"{address}.{kind}"))
        return changes

    def _tls_findings(self, config: dict[str, Any], address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        tls = _mapping(config.get("tls")) or config
        insecure = tls.get("insecureSkipVerify") is True
        if insecure or any(key in tls for key in ("ca", "cert", "key", "rootCAs", "certificates")):
            changes.append(
                _change(
                    f"{address}.tls",
                    "tls",
                    "dangerous" if insecure or "key" in tls else "review",
                    "Traefik TLS settings control peer trust, client certificates, and private "
                    "keys.",
                )
            )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"traefik_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_traefik(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = TraefikAdapter().analyze(data, tool_name="Traefik")
    summary = PlanSummary(
        path=Path("traefik://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Traefik")
    gate["adapter"] = "traefik"
    gate["total_changes"] = len(changes)
    return gate
