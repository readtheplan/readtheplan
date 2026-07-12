from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class HashiCorpInputError(ValueError):
    """Raised when Vault or Consul configuration is invalid or unrecognizable."""


_VAULT_KEYS = {
    "api_addr",
    "cluster_addr",
    "disable_mlock",
    "listener",
    "plugin_directory",
    "raw_storage_endpoint",
    "seal",
    "service_registration",
    "storage",
    "telemetry",
    "ui",
    "user_lockout",
}
_CONSUL_KEYS = {
    "acl",
    "addresses",
    "bind_addr",
    "bootstrap",
    "bootstrap_expect",
    "client_addr",
    "connect",
    "data_dir",
    "datacenter",
    "encrypt",
    "ports",
    "retry_join",
    "server",
    "service",
    "services",
    "tls",
    "ui_config",
}
_SECRET_KEY = re.compile(
    r"(?:^|_)(?:access_key|auth_token|client_secret|credentials?|encrypt|kms_key_id|"
    r"key_file|password|private_key|secret|tokens?)(?:$|_)",
    re.IGNORECASE,
)


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
        return value[0]
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    text = str(value).strip().strip("\"'")
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1]
    return text.strip().strip("\"'")


def _enabled(value: Any) -> bool:
    return value is True or _text(value).lower() in {"1", "true", "yes", "on"}


def _disabled(value: Any) -> bool:
    return value is False or _text(value).lower() in {"0", "false", "no", "off"}


def _blocks(document: dict[str, Any], key: str) -> list[tuple[str, dict[str, Any]]]:
    """Normalize labeled and unlabeled HCL/JSON blocks."""
    value = document.get(key)
    raw_items = value if isinstance(value, list) else [value]
    blocks: list[tuple[str, dict[str, Any]]] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        candidates = [(str(label), body) for label, body in item.items() if isinstance(body, dict)]
        non_meta = [name for name in item if name != "__is_block__"]
        if candidates and len(non_meta) == 1:
            label, body = candidates[0]
            blocks.append((_text(label), body))
        else:
            blocks.append(("", item))
    return blocks


def parse_hashicorp_config(source: str, ecosystem: str) -> dict[str, Any]:
    """Parse one explicitly selected Vault or Consul HCL/JSON artifact."""
    if ecosystem not in {"vault", "consul"}:
        raise HashiCorpInputError(f"unsupported HashiCorp ecosystem: {ecosystem}")
    if not source.strip():
        raise HashiCorpInputError("input is empty")
    try:
        document: Any = json.loads(source)
    except json.JSONDecodeError:
        try:
            import hcl2
            from hcl2.utils import SerializationOptions

            document = hcl2.loads(
                source,
                serialization_options=SerializationOptions(
                    explicit_blocks=False,
                    strip_string_quotes=True,
                ),
            )
        except Exception as exc:
            raise HashiCorpInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise HashiCorpInputError("configuration must be an HCL or JSON object")
    recognized = _VAULT_KEYS if ecosystem == "vault" else _CONSUL_KEYS
    if not recognized & set(document):
        raise HashiCorpInputError(f"input is not recognizable as {ecosystem} configuration")
    return {"hashicorp_config": {"ecosystem": ecosystem, "document": document}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


class HashiCorpAdapter(BaseAdapter):
    def __init__(self, ecosystem: str) -> None:
        self.ecosystem = ecosystem

    @property
    def adapter_name(self) -> str:
        return self.ecosystem

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("hashicorp_config")
        return (
            isinstance(config, dict)
            and config.get("ecosystem") == self.ecosystem
            and isinstance(config.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        document = input_data["hashicorp_config"]["document"]
        changes = self._vault(document) if self.ecosystem == "vault" else self._consul(document)
        changes.append(
            _change(
                f"{self.ecosystem}.effective_configuration",
                "effective_configuration",
                "review",
                f"Effective {self.ecosystem} behavior also depends on environment variables, "
                "command-line flags, merged configuration directories, runtime reload state, "
                "external identity systems, and network policy.",
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

    def _vault(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for index, (kind, listener) in enumerate(_blocks(document, "listener")):
            address = f"listener[{index}]"
            changes.append(
                _change(
                    address,
                    "listener",
                    "review",
                    f"Vault exposes a {kind or 'configured'} API listener to clients.",
                )
            )
            bind = _text(listener.get("address", ""))
            if bind.startswith(("0.0.0.0:", "[::]:", "::")):
                changes.append(
                    _change(
                        f"{address}.address",
                        "public_listener",
                        "dangerous",
                        "Vault listens for API requests on every network interface.",
                    )
                )
            if _enabled(listener.get("tls_disable")):
                changes.append(
                    _change(
                        f"{address}.tls_disable",
                        "plaintext_listener",
                        "dangerous",
                        "Vault API transport encryption and server authentication are disabled.",
                    )
                )
            if _text(listener.get("tls_min_version", "tls12")).lower() in {
                "tls10",
                "tls11",
                "tls1.0",
                "tls1.1",
            }:
                changes.append(
                    _change(
                        f"{address}.tls_min_version",
                        "legacy_tls",
                        "dangerous",
                        "Vault listener permits a legacy TLS protocol version.",
                    )
                )
            if _enabled(listener.get("unauthenticated_metrics_access")):
                changes.append(
                    _change(
                        f"{address}.unauthenticated_metrics_access",
                        "unauthenticated_metrics",
                        "dangerous",
                        "Vault metrics can be read without a Vault token.",
                    )
                )
            if (
                listener.get("proxy_protocol_authorized_addrs") is not None
                or listener.get("x_forwarded_for_authorized_addrs") is not None
            ):
                changes.append(
                    _change(
                        f"{address}.proxy_trust",
                        "proxy_trust",
                        "dangerous",
                        "Vault trusts client identity or network metadata supplied by proxies.",
                    )
                )
            changes.extend(self._secret_fields(listener, address))

        for index, (kind, storage) in enumerate(_blocks(document, "storage")):
            address = f"storage[{index}]"
            changes.append(
                _change(
                    address,
                    "storage_backend",
                    "review",
                    f"Vault persists encrypted security-critical state in the {kind or 'selected'} "
                    "storage backend.",
                )
            )
            if kind in {"file", "inmem"}:
                changes.append(
                    _change(
                        f"{address}.{kind}",
                        "non_ha_storage",
                        "dangerous" if kind == "inmem" else "review",
                        "Vault storage does not provide external high-availability coordination.",
                    )
                )
            changes.extend(self._secret_fields(storage, address))
        for index, (kind, storage) in enumerate(_blocks(document, "ha_storage")):
            changes.append(
                _change(
                    f"ha_storage[{index}]",
                    "ha_storage",
                    "review",
                    f"Vault uses {kind or 'an external backend'} for HA coordination.",
                )
            )
            changes.extend(self._secret_fields(storage, f"ha_storage[{index}]"))

        seals = _blocks(document, "seal")
        if seals:
            for index, (kind, seal) in enumerate(seals):
                address = f"seal[{index}]"
                changes.append(
                    _change(
                        address,
                        "auto_unseal",
                        "dangerous",
                        "Vault delegates unsealing and root-key protection to "
                        f"{kind or 'an external seal'}.",
                    )
                )
                changes.extend(self._secret_fields(seal, address))
        else:
            changes.append(
                _change(
                    "seal",
                    "shamir_seal",
                    "review",
                    "Vault uses Shamir key shares unless an external seal is supplied elsewhere.",
                )
            )

        for key in ("api_addr", "cluster_addr"):
            value = _text(document.get(key, ""))
            if value:
                changes.append(
                    _change(
                        key,
                        "advertised_address",
                        "dangerous" if value.lower().startswith("http://") else "review",
                        f"Vault advertises {key} for redirects, plugins, or cluster traffic.",
                    )
                )
        if _enabled(document.get("disable_mlock")):
            changes.append(
                _change(
                    "disable_mlock",
                    "memory_locking",
                    "dangerous",
                    "Vault may allow sensitive in-memory data to be swapped to disk.",
                )
            )
        if _enabled(document.get("raw_storage_endpoint")):
            changes.append(
                _change(
                    "raw_storage_endpoint",
                    "raw_storage_api",
                    "dangerous",
                    "Vault exposes privileged raw storage inspection endpoints.",
                )
            )
        if document.get("plugin_directory") is not None:
            changes.append(
                _change(
                    "plugin_directory",
                    "plugin_execution",
                    "dangerous",
                    "Vault loads executable secret, auth, or database plugins from this directory.",
                )
            )
        if _enabled(document.get("ui")):
            changes.append(
                _change("ui", "web_ui", "review", "Vault serves its browser-based management UI.")
            )
        for index, (_, telemetry) in enumerate(_blocks(document, "telemetry")):
            changes.append(
                _change(
                    f"telemetry[{index}]",
                    "telemetry_egress",
                    "review",
                    "Vault emits operational metadata to configured telemetry systems.",
                )
            )
            if _enabled(telemetry.get("unauthenticated_metrics_access")):
                changes.append(
                    _change(
                        f"telemetry[{index}].unauthenticated_metrics_access",
                        "unauthenticated_metrics",
                        "dangerous",
                        "Vault permits metrics access without authentication.",
                    )
                )
            changes.extend(self._secret_fields(telemetry, f"telemetry[{index}]"))
        for index, (_, registration) in enumerate(_blocks(document, "service_registration")):
            address = f"service_registration[{index}]"
            changes.append(
                _change(
                    address,
                    "service_registration",
                    "review",
                    "Vault publishes node identity and health to a service registry.",
                )
            )
            changes.extend(self._secret_fields(registration, address))
        for index, (_, lockout) in enumerate(_blocks(document, "user_lockout")):
            if _enabled(lockout.get("disable_lockout")):
                changes.append(
                    _change(
                        f"user_lockout[{index}].disable_lockout",
                        "authentication_hardening",
                        "dangerous",
                        "Vault user lockout protection is explicitly disabled.",
                    )
                )
        return changes

    def _consul(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if _enabled(document.get("server")):
            changes.append(
                _change(
                    "server",
                    "server_agent",
                    "review",
                    "Consul agent participates in Raft consensus and stores authoritative state.",
                )
            )
        if (
            _enabled(document.get("bootstrap"))
            or _text(document.get("bootstrap_expect", "")) == "1"
        ):
            changes.append(
                _change(
                    "bootstrap",
                    "single_server_bootstrap",
                    "dangerous",
                    "Consul can bootstrap a single-server cluster without normal quorum safety.",
                )
            )
        if _enabled(document.get("dev")) or _enabled(document.get("dev_mode")):
            changes.append(
                _change(
                    "dev_mode",
                    "development_mode",
                    "dangerous",
                    "Consul development mode is not suitable for durable or secure deployments.",
                )
            )

        addresses = _mapping(document.get("addresses"))
        public_services: list[str] = []
        for key, value in addresses.items():
            if _text(value) in {"0.0.0.0", "::", "[::]"}:
                public_services.append(str(key))
        if _text(document.get("client_addr", "")) in {"0.0.0.0", "::", "[::]"}:
            public_services.append("all client services")
        if public_services:
            changes.append(
                _change(
                    "addresses",
                    "public_listener",
                    "dangerous",
                    "Consul exposes " + ", ".join(public_services) + " on every network interface.",
                )
            )
        ports = _mapping(document.get("ports"))
        if _text(ports.get("http", "8500")) not in {"-1", ""}:
            changes.append(
                _change(
                    "ports.http",
                    "plaintext_api",
                    "dangerous",
                    "Consul HTTP API is enabled without transport encryption.",
                )
            )

        acl = _mapping(document.get("acl"))
        if acl:
            changes.append(
                _change(
                    "acl",
                    "access_control",
                    "review",
                    "Consul ACL configuration controls API and service authorization.",
                )
            )
            if _disabled(acl.get("enabled")):
                changes.append(
                    _change(
                        "acl.enabled",
                        "disabled_acl",
                        "dangerous",
                        "Consul ACL enforcement is explicitly disabled.",
                    )
                )
            if _text(acl.get("default_policy", "deny")).lower() == "allow":
                changes.append(
                    _change(
                        "acl.default_policy",
                        "permissive_acl",
                        "dangerous",
                        "Unmatched Consul ACL requests are allowed by default.",
                    )
                )
            changes.extend(self._secret_fields(acl, "acl"))

        tls = _mapping(document.get("tls"))
        for scope in ("defaults", "internal_rpc", "grpc", "https"):
            settings = _mapping(tls.get(scope))
            if not settings:
                continue
            address = f"tls.{scope}"
            changes.append(
                _change(
                    address,
                    "tls",
                    "review",
                    f"Consul configures TLS identity and trust for {scope} traffic.",
                )
            )
            for key in ("verify_incoming", "verify_outgoing", "verify_server_hostname"):
                if _disabled(settings.get(key)):
                    changes.append(
                        _change(
                            f"{address}.{key}",
                            "insecure_tls",
                            "dangerous",
                            f"Consul TLS {key} verification is explicitly disabled.",
                        )
                    )
            changes.extend(self._secret_fields(settings, address))
        for key in ("encrypt", "encrypt_verify_incoming", "encrypt_verify_outgoing"):
            if document.get(key) is not None:
                if key == "encrypt":
                    changes.append(
                        _change(
                            key,
                            "gossip_encryption",
                            "dangerous",
                            "Consul configuration contains or references the gossip "
                            "encryption key.",
                        )
                    )
                elif _disabled(document.get(key)):
                    changes.append(
                        _change(
                            key,
                            "insecure_gossip",
                            "dangerous",
                            f"Consul {key} verification is explicitly disabled.",
                        )
                    )

        connect = _mapping(document.get("connect"))
        if _enabled(connect.get("enabled")):
            changes.append(
                _change(
                    "connect",
                    "service_mesh",
                    "review",
                    "Consul service mesh issues workload identities and controls "
                    "service connectivity.",
                )
            )
            changes.extend(self._secret_fields(connect, "connect"))
        for key in ("retry_join", "retry_join_wan"):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        key,
                        "cluster_discovery",
                        "dangerous",
                        "Consul dynamically discovers and joins cluster members using external "
                        "addresses, APIs, or ambient cloud credentials.",
                    )
                )
        if _enabled(document.get("enable_script_checks")) or _enabled(
            document.get("enable_local_script_checks")
        ):
            changes.append(
                _change(
                    "script_checks",
                    "script_execution",
                    "dangerous",
                    "Consul health checks may execute local commands on the agent host.",
                )
            )
        if _disabled(document.get("disable_remote_exec")):
            changes.append(
                _change(
                    "disable_remote_exec",
                    "remote_execution",
                    "dangerous",
                    "Consul remote execution is explicitly enabled.",
                )
            )
        ui = _mapping(document.get("ui_config"))
        if _enabled(ui.get("enabled")):
            changes.append(
                _change(
                    "ui_config",
                    "web_ui",
                    "review",
                    "Consul serves its browser-based management UI.",
                )
            )
        if document.get("recursors") is not None:
            changes.append(
                _change(
                    "recursors",
                    "dns_forwarding",
                    "review",
                    "Consul forwards unresolved DNS queries to external recursors.",
                )
            )
        for key in ("services", "service", "checks", "check"):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        key,
                        "service_definition",
                        "review",
                        "Consul registers services or health checks from agent configuration.",
                    )
                )
                if self._contains_script(document.get(key)):
                    changes.append(
                        _change(
                            f"{key}.script",
                            "script_execution",
                            "dangerous",
                            "Consul service health checking executes a local command.",
                        )
                    )
        telemetry = _mapping(document.get("telemetry"))
        if telemetry:
            changes.append(
                _change(
                    "telemetry",
                    "telemetry_egress",
                    "review",
                    "Consul emits operational metadata to configured telemetry systems.",
                )
            )
            changes.extend(self._secret_fields(telemetry, "telemetry"))
        for key in ("auto_config", "auto_encrypt", "cloud"):
            block = _mapping(document.get(key))
            if block:
                changes.append(
                    _change(
                        key,
                        "dynamic_configuration",
                        "dangerous",
                        f"Consul {key} delegates identity, TLS, or configuration to an "
                        "external control plane.",
                    )
                )
                changes.extend(self._secret_fields(block, key))
        return changes

    def _contains_script(self, value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                str(key).lower() in {"args", "script", "script_args", "shell"}
                or self._contains_script(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(self._contains_script(item) for item in value)
        return False

    def _secret_fields(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if not isinstance(value, dict):
            return changes
        for key, child in value.items():
            field_address = f"{address}.{key}"
            if _SECRET_KEY.search(str(key)):
                changes.append(
                    _change(
                        field_address,
                        "secret_material",
                        "dangerous",
                        f"{self.ecosystem.title()} configuration contains or references "
                        "credential or cryptographic key material.",
                    )
                )
            elif isinstance(child, dict):
                changes.extend(self._secret_fields(child, field_address))
            elif isinstance(child, list):
                for index, item in enumerate(child):
                    if isinstance(item, dict):
                        changes.extend(self._secret_fields(item, f"{field_address}[{index}]"))
        return changes


class VaultAdapter(HashiCorpAdapter):
    def __init__(self) -> None:
        super().__init__("vault")


class ConsulAdapter(HashiCorpAdapter):
    def __init__(self) -> None:
        super().__init__("consul")


def analyze_hashicorp(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    config = data.get("hashicorp_config")
    ecosystem = str(config.get("ecosystem")) if isinstance(config, dict) else "hashicorp"
    adapter: HashiCorpAdapter = VaultAdapter() if ecosystem == "vault" else ConsulAdapter()
    changes = adapter.analyze(data, tool_name=ecosystem)
    summary = PlanSummary(
        path=Path(f"{ecosystem}://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name=ecosystem)
    gate["adapter"] = ecosystem
    gate["total_changes"] = len(changes)
    return gate
