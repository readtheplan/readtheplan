from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class LokiInputError(ValueError):
    """Raised when Loki configuration YAML is invalid or unrecognizable."""


_RECOGNIZED = {
    "auth_enabled",
    "common",
    "compactor",
    "distributor",
    "frontend",
    "ingester",
    "limits_config",
    "memberlist",
    "overrides",
    "querier",
    "query_range",
    "ruler",
    "runtime_config",
    "schema_config",
    "server",
    "storage_config",
    "target",
}
_SECRET_KEY = re.compile(
    r"(?:^|_)(?:access_key|api_key|auth_token|client_secret|credentials?|password|"
    r"secret|secret_key|token)(?:$|_)",
    re.IGNORECASE,
)
_STORAGE_BACKENDS = {
    "alibabacloud",
    "aws",
    "azure",
    "bos",
    "cassandra",
    "filesystem",
    "gcs",
    "grpc_store",
    "inmemory",
    "s3",
    "swift",
}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _enabled(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def _disabled(value: Any) -> bool:
    return value is False or str(value).strip().lower() in {"0", "false", "no", "off"}


def parse_loki_config(source: str) -> dict[str, Any]:
    """Parse Loki YAML without expanding environment variables or external files."""
    if not source.strip():
        raise LokiInputError("input is empty")
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise LokiInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise LokiInputError("configuration must be a YAML object")
    if not _RECOGNIZED & set(document):
        raise LokiInputError("input is not recognizable as Loki configuration")
    return {"loki_config": {"document": document}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


class LokiAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "loki"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("loki_config")
        return isinstance(config, dict) and isinstance(config.get("document"), dict)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        document = input_data["loki_config"]["document"]
        changes: list[dict[str, Any]] = [
            _change(
                "authentication_boundary",
                "authentication_boundary",
                "review",
                "Loki has no built-in user authentication; an authenticating reverse proxy "
                "must protect client-facing APIs and set trusted tenant identity.",
            )
        ]
        if _disabled(document.get("auth_enabled")):
            changes.append(
                _change(
                    "auth_enabled",
                    "single_tenant_mode",
                    "dangerous",
                    "Loki disables tenant isolation and accepts requests without X-Scope-OrgID.",
                )
            )
        target = str(document.get("target", "all"))
        changes.append(
            _change(
                "target",
                "deployment_target",
                "review",
                f"Loki runs the {target} component target, defining its ingest, query, or "
                "control-plane responsibilities.",
            )
        )
        changes.extend(self._server(_mapping(document.get("server"))))
        changes.extend(self._storage(_mapping(document.get("storage_config")), "storage_config"))
        common = _mapping(document.get("common"))
        if common:
            changes.append(
                _change(
                    "common",
                    "shared_configuration",
                    "review",
                    "Loki common settings provide storage, ring, address, and replication "
                    "defaults to multiple components.",
                )
            )
            if str(common.get("replication_factor", "")) == "1":
                changes.append(
                    _change(
                        "common.replication_factor",
                        "single_replica",
                        "dangerous",
                        "Loki stores only one replica, increasing permanent log-loss risk.",
                    )
                )
            changes.extend(self._storage(_mapping(common.get("storage")), "common.storage"))
        if document.get("schema_config") is not None:
            changes.append(
                _change(
                    "schema_config",
                    "storage_schema",
                    "review",
                    "Loki schema periods control index format, object store, and compatibility; "
                    "incorrect transitions can make historical logs unavailable.",
                )
            )
        memberlist = _mapping(document.get("memberlist"))
        if memberlist:
            changes.append(
                _change(
                    "memberlist",
                    "cluster_membership",
                    "dangerous",
                    "Loki joins a gossip cluster and trusts discovered members for ring state.",
                )
            )
        changes.extend(self._limits(_mapping(document.get("limits_config"))))
        runtime = _mapping(document.get("runtime_config"))
        if runtime.get("file") is not None:
            changes.append(
                _change(
                    "runtime_config.file",
                    "runtime_configuration",
                    "dangerous",
                    "Loki periodically reloads per-tenant limits and ring behavior from an "
                    "external runtime file.",
                )
            )
        if document.get("overrides") is not None:
            changes.append(
                _change(
                    "overrides",
                    "tenant_overrides",
                    "review",
                    "Loki applies tenant-specific ingestion, retention, and query limits.",
                )
            )
        changes.extend(self._ruler(_mapping(document.get("ruler"))))
        compactor = _mapping(document.get("compactor"))
        if compactor:
            changes.append(
                _change(
                    "compactor",
                    "retention_deletion",
                    "dangerous" if _enabled(compactor.get("retention_enabled")) else "review",
                    "Loki compactor manages retention and deletion of stored log data.",
                )
            )
        for key in ("frontend", "querier", "query_range"):
            config = _mapping(document.get(key))
            if not config:
                continue
            changes.append(
                _change(
                    key,
                    "query_path",
                    "review",
                    f"Loki {key} settings change query routing, caching, parallelism, or tenancy.",
                )
            )
            if config.get("downstream_url") is not None:
                changes.append(
                    _change(
                        f"{key}.downstream_url",
                        "query_egress",
                        "dangerous",
                        "Loki forwards queries and tenant context to an external endpoint.",
                    )
                )
            changes.extend(self._scan_tls(config, key))
        for key in ("tracing", "analytics"):
            config = _mapping(document.get(key))
            if config and (_enabled(config.get("enabled")) or key == "analytics"):
                changes.append(
                    _change(
                        key,
                        "telemetry_egress",
                        "review",
                        f"Loki {key} may export operational or usage metadata.",
                    )
                )
        changes.extend(self._secret_fields(document, "loki"))
        changes.append(
            _change(
                "loki.effective_configuration",
                "effective_configuration",
                "review",
                "Effective Loki behavior also depends on command-line flags, environment "
                "expansion, runtime overrides, object-store policy, reverse proxies, and network "
                "controls.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"loki_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )

    def _server(self, server: dict[str, Any]) -> list[dict[str, Any]]:
        if not server:
            return []
        changes = [
            _change(
                "server",
                "server",
                "review",
                "Loki exposes HTTP and gRPC endpoints for ingest, query, metrics, and internode "
                "traffic.",
            )
        ]
        for protocol in ("http", "grpc"):
            address = str(server.get(f"{protocol}_listen_address", ""))
            if address in {"0.0.0.0", "::", "[::]"}:
                changes.append(
                    _change(
                        f"server.{protocol}_listen_address",
                        "public_listener",
                        "dangerous",
                        f"Loki {protocol.upper()} listens on every network interface.",
                    )
                )
            tls = _mapping(server.get(f"{protocol}_tls_config"))
            if tls:
                changes.append(
                    _change(
                        f"server.{protocol}_tls_config",
                        "tls",
                        "review",
                        f"Loki configures TLS identity and client authentication for {protocol}.",
                    )
                )
                client_auth = str(tls.get("client_auth_type", "")).lower()
                if client_auth in {"noclientcert", "requestclientcert"}:
                    changes.append(
                        _change(
                            f"server.{protocol}_tls_config.client_auth_type",
                            "weak_client_auth",
                            "dangerous",
                            "Loki TLS does not require and verify a client certificate.",
                        )
                    )
        return changes

    def _storage(self, storage: dict[str, Any], address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for backend in _STORAGE_BACKENDS & set(storage):
            changes.append(
                _change(
                    f"{address}.{backend}",
                    "storage_backend",
                    "dangerous" if backend == "inmemory" else "review",
                    f"Loki stores or retrieves log and index data using the {backend} backend.",
                )
            )
            config = _mapping(storage.get(backend))
            changes.extend(self._scan_plaintext(config, f"{address}.{backend}"))
            changes.extend(self._scan_tls(config, f"{address}.{backend}"))
        return changes

    def _limits(self, limits: dict[str, Any]) -> list[dict[str, Any]]:
        if not limits:
            return []
        changes = [
            _change(
                "limits_config",
                "tenant_limits",
                "review",
                "Loki limits control ingestion, query cost, retention, deletion, and tenant "
                "resource isolation.",
            )
        ]
        for key in (
            "ingestion_rate_mb",
            "max_entries_limit_per_query",
            "max_global_streams_per_user",
            "max_query_bytes_read",
            "max_query_parallelism",
            "max_query_series",
        ):
            if str(limits.get(key, "")) in {"0", "0.0"}:
                changes.append(
                    _change(
                        f"limits_config.{key}",
                        "unbounded_limit",
                        "dangerous",
                        f"Loki {key} is unlimited, increasing denial-of-service or cost risk.",
                    )
                )
        if limits.get("retention_period") is not None or limits.get("retention_stream") is not None:
            changes.append(
                _change(
                    "limits_config.retention",
                    "retention_policy",
                    "dangerous",
                    "Loki tenant limits can expire stored log data.",
                )
            )
        if _disabled(limits.get("reject_old_samples")):
            changes.append(
                _change(
                    "limits_config.reject_old_samples",
                    "historical_ingest",
                    "review",
                    "Loki accepts arbitrarily old samples, affecting retention and storage usage.",
                )
            )
        return changes

    def _ruler(self, ruler: dict[str, Any]) -> list[dict[str, Any]]:
        if not ruler:
            return []
        changes = [
            _change(
                "ruler",
                "ruler",
                "review",
                "Loki ruler evaluates log queries and can send alerts or recording-rule samples.",
            )
        ]
        if _enabled(ruler.get("enable_api")):
            changes.append(
                _change(
                    "ruler.enable_api",
                    "mutable_rule_api",
                    "dangerous",
                    "Loki exposes an API that can create, update, or delete rule groups.",
                )
            )
        for key in ("alertmanager_url", "external_url", "remote_write"):
            if ruler.get(key) is not None:
                changes.append(
                    _change(
                        f"ruler.{key}",
                        "rule_egress",
                        "dangerous",
                        f"Loki ruler sends alert, query, or sample data through {key}.",
                    )
                )
        changes.extend(self._scan_tls(ruler, "ruler"))
        return changes

    def _scan_plaintext(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                child_address = f"{address}.{key}"
                if isinstance(child, str) and child.lower().startswith("http://"):
                    changes.append(
                        _change(
                            child_address,
                            "plaintext_egress",
                            "dangerous",
                            "Loki sends log, index, identity, or credential-bearing traffic over "
                            "plaintext HTTP.",
                        )
                    )
                else:
                    changes.extend(self._scan_plaintext(child, child_address))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                changes.extend(self._scan_plaintext(child, f"{address}[{index}]"))
        return changes

    def _scan_tls(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                child_address = f"{address}.{key}"
                if str(key).lower() in {"insecure_skip_verify", "tls_skip_verify"} and _enabled(
                    child
                ):
                    changes.append(
                        _change(
                            child_address,
                            "insecure_tls",
                            "dangerous",
                            "Loki does not verify the remote TLS certificate.",
                        )
                    )
                else:
                    changes.extend(self._scan_tls(child, child_address))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                changes.extend(self._scan_tls(child, f"{address}[{index}]"))
        return changes

    def _secret_fields(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if not isinstance(value, dict):
            return changes
        for key, child in value.items():
            child_address = f"{address}.{key}"
            if _SECRET_KEY.search(str(key)):
                changes.append(
                    _change(
                        child_address,
                        "secret_material",
                        "dangerous",
                        "Loki configuration contains or references credential material.",
                    )
                )
            elif isinstance(child, dict):
                changes.extend(self._secret_fields(child, child_address))
            elif isinstance(child, list):
                for index, item in enumerate(child):
                    if isinstance(item, dict):
                        changes.extend(self._secret_fields(item, f"{child_address}[{index}]"))
        return changes


def analyze_loki(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    adapter = LokiAdapter()
    changes = adapter.analyze(data, tool_name="loki")
    summary = PlanSummary(
        path=Path("loki://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="loki")
    gate["adapter"] = "loki"
    gate["total_changes"] = len(changes)
    return gate
