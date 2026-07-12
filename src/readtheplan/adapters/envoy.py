from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class EnvoyInputError(ValueError):
    """Raised when input is not recognizable Envoy bootstrap or config-dump data."""


def parse_envoy_config(source: str) -> dict[str, Any]:
    """Parse Envoy bootstrap YAML/JSON or admin config_dump JSON."""
    if not source.strip():
        raise EnvoyInputError("input is empty")
    try:
        parsed = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise EnvoyInputError(str(exc)) from exc
    if not isinstance(parsed, dict):
        raise EnvoyInputError("Envoy configuration must be an object")
    bootstrap_keys = {
        "admin",
        "dynamic_resources",
        "layered_runtime",
        "node",
        "static_resources",
    }
    if bootstrap_keys & set(parsed):
        artifact_type = "bootstrap"
    elif isinstance(parsed.get("configs"), list):
        artifact_type = "config_dump"
    else:
        raise EnvoyInputError("expected Envoy bootstrap fields or config_dump configs")
    return {"envoy_config": {"artifact_type": artifact_type, "document": parsed}}


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


def _public_address(address: str) -> bool:
    lowered = address.strip().lower()
    return lowered in {"0.0.0.0", "::", "[::]", "*"} or not lowered.startswith(
        ("127.", "localhost", "::1", "[::1]", "/")
    )


def _socket_endpoint(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    socket = value.get("socket_address")
    if not isinstance(socket, dict):
        return ""
    address = str(socket.get("address") or "")
    port = socket.get("port_value", socket.get("named_port", ""))
    return f"{address}:{port}" if port != "" else address


class EnvoyAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "envoy"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("envoy_config")
        return (
            isinstance(config, dict)
            and config.get("artifact_type") in {"bootstrap", "config_dump"}
            and isinstance(config.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        config = input_data["envoy_config"]
        document = config["document"]
        changes: list[dict[str, Any]] = []
        if config["artifact_type"] == "config_dump":
            changes.append(
                _change(
                    "configs",
                    "runtime_snapshot",
                    "review",
                    "Envoy config_dump represents active runtime resources and may contain "
                    "sensitive endpoints, certificates, and control-plane state.",
                )
            )
        if document.get("dynamic_resources") is not None:
            changes.append(
                _change(
                    "dynamic_resources",
                    "dynamic_resources",
                    "dangerous",
                    "xDS sources can replace listeners, routes, clusters, endpoints, and secrets "
                    "at runtime outside this bootstrap artifact.",
                )
            )
        if document.get("layered_runtime") is not None:
            changes.append(
                _change(
                    "layered_runtime",
                    "runtime_layers",
                    "dangerous",
                    "Layered runtime can change Envoy behavior from files, disk, or a runtime "
                    "discovery service.",
                )
            )
        admin = document.get("admin")
        if isinstance(admin, dict):
            endpoint = _socket_endpoint(admin.get("address"))
            host = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
            changes.append(
                _change(
                    "admin.address",
                    "admin",
                    "dangerous" if not host or _public_address(host) else "review",
                    f"Envoy admin endpoint '{endpoint or 'unresolved'}' exposes operational and "
                    "configuration controls; keep it on a protected local interface.",
                )
            )
        seen: set[tuple[str, str]] = set()
        for path, value in _walk(document):
            self._inspect(path, value, changes, seen)
        changes.append(
            _change(
                "envoy.effective_configuration",
                "effective_configuration",
                "review",
                "Effective Envoy behavior combines bootstrap, active xDS resources, runtime "
                "layers, extension binaries, environment, and command-line options.",
            )
        )
        return changes

    def _append_once(
        self,
        changes: list[dict[str, Any]],
        seen: set[tuple[str, str]],
        address: str,
        kind: str,
        risk: str,
        explanation: str,
    ) -> None:
        identity = (address, kind)
        if identity not in seen:
            seen.add(identity)
            changes.append(_change(address, kind, risk, explanation))

    def _inspect(
        self,
        path: str,
        value: Any,
        changes: list[dict[str, Any]],
        seen: set[tuple[str, str]],
    ) -> None:
        key = path.rsplit(".", 1)[-1].split("[")[0]
        if key == "address" and isinstance(value, dict) and "socket_address" in value:
            endpoint = _socket_endpoint(value)
            host = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
            is_admin = path == "admin.address"
            if is_admin:
                return
            kind = "admin" if is_admin else "listener_or_endpoint"
            risk = "dangerous" if is_admin and _public_address(host) else "review"
            self._append_once(
                changes,
                seen,
                path,
                kind,
                risk,
                f"Envoy socket endpoint '{endpoint}' changes network exposure or upstream routing.",
            )
        if key in {"api_config_source", "path_config_source", "ads_config"}:
            self._append_once(
                changes,
                seen,
                path,
                "xds_source",
                "dangerous",
                "Envoy discovery source imports runtime configuration from a control plane "
                "or file.",
            )
        if key in {"cluster", "cluster_name", "weighted_clusters"} and value:
            self._append_once(
                changes,
                seen,
                path,
                "route_or_cluster",
                "review",
                "Envoy route or service reference directs traffic to an upstream cluster.",
            )
        if key in {"access_log", "access_log_path"} and value is not None:
            self._append_once(
                changes,
                seen,
                path,
                "access_log",
                "review",
                "Envoy access logging can emit request metadata, headers, identities, and paths.",
            )
        if key in {"private_key", "password", "tls_certificate_sds_secret_configs"}:
            self._append_once(
                changes,
                seen,
                path,
                "secret_material",
                "dangerous",
                "Envoy TLS configuration references private keys, passwords, or SDS secrets.",
            )
        if key == "validation_context" and isinstance(value, dict):
            trusted = "trusted_ca" in value
            identity = any(
                item in value
                for item in (
                    "match_subject_alt_names",
                    "match_typed_subject_alt_names",
                    "verify_certificate_hash",
                    "verify_certificate_spki",
                )
            )
            risk = "safe" if trusted and identity else "dangerous"
            self._append_once(
                changes,
                seen,
                path,
                "tls_validation",
                risk,
                "Envoy certificate validation should verify both trust chain and peer identity.",
            )
        if key == "trust_chain_verification" and str(value).upper() == "ACCEPT_UNTRUSTED":
            self._append_once(
                changes,
                seen,
                path,
                "tls_validation",
                "dangerous",
                "Envoy accepts untrusted peer certificate chains.",
            )
        if key == "tls_minimum_protocol_version" and str(value).upper() in {
            "TLSV1_0",
            "TLSV1_1",
        }:
            self._append_once(
                changes,
                seen,
                path,
                "tls_protocol",
                "dangerous",
                "Envoy permits a legacy minimum TLS protocol version.",
            )
        if key == "name" and isinstance(value, str) and value.startswith("envoy."):
            self._filter(path, value, changes, seen)
        if key == "inline_code":
            self._append_once(
                changes,
                seen,
                path,
                "inline_code",
                "dangerous",
                "Envoy Lua configuration executes inline code in the request processing path.",
            )
        if key in {"filename", "http_uri", "remote"} and any(
            token in path.lower() for token in ("wasm", "code", "extension")
        ):
            self._append_once(
                changes,
                seen,
                path,
                "extension_code",
                "dangerous",
                "Envoy extension loads executable Wasm or native code from local or remote input.",
            )
        if key == "failure_mode_allow" and value is True:
            self._append_once(
                changes,
                seen,
                path,
                "authorization_fail_open",
                "dangerous",
                "Envoy external authorization is configured to allow traffic when checks fail.",
            )

    def _filter(
        self,
        path: str,
        name: str,
        changes: list[dict[str, Any]],
        seen: set[tuple[str, str]],
    ) -> None:
        lower = name.lower()
        executable = any(token in lower for token in (".lua", ".wasm", "dynamic_module"))
        auth = any(token in lower for token in ("ext_authz", ".rbac", "jwt_authn"))
        if executable:
            risk = "dangerous"
        elif auth:
            risk = "review"
        else:
            risk = "safe" if lower.endswith(".router") else "review"
        self._append_once(
            changes,
            seen,
            path,
            "filter",
            risk,
            f"Envoy filter '{name}' participates in traffic processing, authorization, or code "
            "execution.",
        )

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"envoy_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_envoy(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = EnvoyAdapter().analyze(data, tool_name="Envoy")
    summary = PlanSummary(
        path=Path("envoy://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Envoy")
    gate["adapter"] = "envoy"
    gate["total_changes"] = len(changes)
    return gate
