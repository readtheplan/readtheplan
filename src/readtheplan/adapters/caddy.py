from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class CaddyInputError(ValueError):
    """Raised when Caddyfile or native Caddy JSON is invalid or unrecognizable."""


_JSON_KEYS = {"admin", "apps", "logging", "storage"}
_SECRET_KEY = re.compile(
    r"(?:^|_)(?:api_key|client_secret|credentials?|key|mac_key|password|secret|token)(?:$|_)",
    re.IGNORECASE,
)
_GROUPING_DIRECTIVES = {
    "handle",
    "handle_errors",
    "handle_path",
    "route",
    "servers",
}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _enabled(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def _strip_comment(line: str) -> str:
    quote = ""
    escaped = False
    output: list[str] = []
    for char in line:
        if escaped:
            output.append(char)
            escaped = False
            continue
        if char == "\\":
            output.append(char)
            escaped = True
            continue
        if quote:
            output.append(char)
            if char == quote:
                quote = ""
            continue
        if char in {'"', "'", "`"}:
            quote = char
            output.append(char)
        elif char == "#":
            break
        else:
            output.append(char)
    return "".join(output).strip()


def _caddyfile_lines(source: str) -> list[str]:
    lines = [cleaned for line in source.splitlines() if (cleaned := _strip_comment(line))]
    depth = 0
    for line in lines:
        depth += line.count("{") - line.count("}")
        if depth < 0:
            raise CaddyInputError("Caddyfile has an unmatched closing brace")
    if depth != 0:
        raise CaddyInputError("Caddyfile has unbalanced braces")
    if not any("{" in line for line in lines):
        raise CaddyInputError("input is not recognizable as a Caddyfile")
    return lines


def parse_caddy_config(source: str) -> dict[str, Any]:
    """Parse native Caddy JSON or conservatively tokenize a Caddyfile."""
    if not source.strip():
        raise CaddyInputError("input is empty")
    try:
        document: Any = json.loads(source)
    except json.JSONDecodeError:
        document = None
    if isinstance(document, dict):
        if not _JSON_KEYS & set(document):
            raise CaddyInputError("input is not recognizable as native Caddy JSON")
        return {"caddy_config": {"artifact_type": "json", "document": document}}
    return {
        "caddy_config": {
            "artifact_type": "caddyfile",
            "document": {"lines": _caddyfile_lines(source)},
        }
    }


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


class CaddyAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "caddy"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("caddy_config")
        return (
            isinstance(config, dict)
            and config.get("artifact_type") in {"caddyfile", "json"}
            and isinstance(config.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        config = input_data["caddy_config"]
        changes = (
            self._caddyfile(config["document"]["lines"])
            if config["artifact_type"] == "caddyfile"
            else self._json(config["document"])
        )
        changes.append(
            _change(
                "caddy.effective_configuration",
                "effective_configuration",
                "review",
                "Effective Caddy behavior also depends on environment substitutions, imported "
                "files, config adapters, installed modules, admin-API runtime state, certificate "
                "storage, and network policy.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"caddy_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )

    def _tokens(self, line: str) -> list[str]:
        candidate = line.replace("{", " ").replace("}", " ").strip()
        try:
            return shlex.split(candidate, posix=True)
        except ValueError:
            return candidate.split()

    def _caddyfile(self, lines: list[str]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        depth = 0
        on_demand_ask = any(self._tokens(line)[:1] == ["ask"] for line in lines)
        for number, line in enumerate(lines, start=1):
            tokens = self._tokens(line)
            if not tokens:
                depth += line.count("{") - line.count("}")
                continue
            first = tokens[0]
            address = f"line[{number}]"
            opens = line.count("{")
            closes = line.count("}")
            if depth == 0 and opens and first not in _GROUPING_DIRECTIVES:
                self._site_address(changes, address, tokens)
            if first == "admin":
                listen = tokens[1] if len(tokens) > 1 else "localhost:2019"
                changes.append(
                    _change(
                        address,
                        "admin_api",
                        "dangerous" if self._public_address(listen) else "review",
                        "Caddy admin API can replace live configuration and control the server.",
                    )
                )
            elif first == "origins" and "*" in tokens[1:]:
                changes.append(
                    _change(
                        address,
                        "wildcard_admin_origin",
                        "dangerous",
                        "Caddy admin API accepts browser origins without restriction.",
                    )
                )
            elif first == "auto_https" and any(
                value in {"off", "disable_redirects", "disable_certs"} for value in tokens[1:]
            ):
                changes.append(
                    _change(
                        address,
                        "automatic_https",
                        "dangerous",
                        "Caddy automatic certificates or HTTP-to-HTTPS redirects are disabled.",
                    )
                )
            elif first in {"acme_dns", "dns"}:
                changes.append(
                    _change(
                        address,
                        "dns_provider",
                        "dangerous",
                        "Caddy delegates DNS changes and certificate challenges to a "
                        "provider plugin.",
                    )
                )
            elif first == "acme_eab":
                changes.append(
                    _change(
                        address,
                        "secret_material",
                        "dangerous",
                        "Caddy configures ACME External Account Binding credentials.",
                    )
                )
            elif first == "on_demand_tls" and not on_demand_ask:
                changes.append(
                    _change(
                        address,
                        "unrestricted_on_demand_tls",
                        "dangerous",
                        "Caddy on-demand TLS has no visible authorization endpoint, "
                        "enabling certificate issuance abuse.",
                    )
                )
            elif first == "storage":
                changes.append(
                    _change(
                        address,
                        "certificate_storage",
                        "dangerous",
                        "Caddy uses a configurable module to store certificates and private keys.",
                    )
                )
            elif first == "order":
                changes.append(
                    _change(
                        address,
                        "handler_order",
                        "review",
                        "Caddy overrides HTTP handler ordering, including possible "
                        "third-party modules.",
                    )
                )
            elif first == "persist_config" and "off" in tokens[1:]:
                changes.append(
                    _change(
                        address,
                        "runtime_persistence",
                        "review",
                        "Caddy does not persist configuration applied through the admin API.",
                    )
                )
            elif first == "debug":
                changes.append(
                    _change(
                        address,
                        "debug_logging",
                        "review",
                        "Caddy emits verbose debug logs that may expose operational detail.",
                    )
                )
            elif first == "log_credentials":
                changes.append(
                    _change(
                        address,
                        "credential_logging",
                        "dangerous",
                        "Caddy access logs include normally redacted credential headers.",
                    )
                )
            elif first == "trusted_proxies":
                changes.append(
                    _change(
                        address,
                        "proxy_trust",
                        "dangerous",
                        "Caddy trusts client address metadata supplied by configured proxies.",
                    )
                )
            elif first == "strict_sni_host" and "insecure_off" in tokens[1:]:
                changes.append(
                    _change(
                        address,
                        "weak_sni_validation",
                        "dangerous",
                        "Caddy disables strict Host-to-TLS-SNI consistency checks.",
                    )
                )
            elif first == "reverse_proxy":
                changes.append(
                    _change(
                        address,
                        "reverse_proxy",
                        "review",
                        "Caddy forwards requests, headers, and bodies to configured "
                        "upstream services.",
                    )
                )
                if any(
                    value.startswith("http://") and not self._local_url(value)
                    for value in tokens[1:]
                ):
                    changes.append(
                        _change(
                            address,
                            "plaintext_upstream",
                            "dangerous",
                            "Caddy proxies to a non-local upstream over plaintext HTTP.",
                        )
                    )
            elif first == "tls_insecure_skip_verify":
                changes.append(
                    _change(
                        address,
                        "insecure_upstream_tls",
                        "dangerous",
                        "Caddy disables upstream certificate verification.",
                    )
                )
            elif first == "tls_client_auth":
                changes.append(
                    _change(
                        address,
                        "client_certificate",
                        "dangerous",
                        "Caddy references a client certificate and private key for "
                        "upstream authentication.",
                    )
                )
            elif first in {"forward_auth", "basic_auth"}:
                changes.append(
                    _change(
                        address,
                        "authentication",
                        "dangerous",
                        "Caddy delegates or enforces request authentication and handles "
                        "identity material.",
                    )
                )
            elif first == "file_server":
                changes.append(
                    _change(
                        address,
                        "file_server",
                        "dangerous" if "browse" in tokens else "review",
                        "Caddy serves files from the configured filesystem root.",
                    )
                )
            elif first == "root":
                changes.append(
                    _change(
                        address,
                        "filesystem_root",
                        "review",
                        "Caddy exposes content relative to a local or pluggable filesystem root.",
                    )
                )
            elif first in {"php_fastcgi", "php_server", "cgi"}:
                changes.append(
                    _change(
                        address,
                        "application_execution",
                        "dangerous",
                        "Caddy routes requests to application code execution through "
                        "PHP/FastCGI or a plugin.",
                    )
                )
            elif first in {"header", "request_header"}:
                changes.append(
                    _change(
                        address,
                        "header_mutation",
                        "review",
                        "Caddy adds, removes, or rewrites HTTP security and identity headers.",
                    )
                )
            elif first == "import":
                changes.append(
                    _change(
                        address,
                        "external_import",
                        "review",
                        "Caddy imports configuration outside this artifact.",
                    )
                )
            elif first == "acme_server":
                changes.append(
                    _change(
                        address,
                        "certificate_authority",
                        "dangerous",
                        "Caddy exposes an ACME certificate-authority endpoint.",
                    )
                )
            depth += opens - closes
        return changes

    def _site_address(self, changes: list[dict[str, Any]], address: str, tokens: list[str]) -> None:
        sites = [token.rstrip(",") for token in tokens if token != "{"]
        if not sites:
            return
        plaintext = any(site.startswith("http://") or site.endswith(":80") for site in sites)
        changes.append(
            _change(
                address,
                "site",
                "dangerous" if plaintext else "review",
                "Caddy defines a plaintext HTTP site"
                if plaintext
                else "Caddy defines an HTTP server site and its request-handling boundary.",
            )
        )

    def _json(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        admin = _mapping(document.get("admin"))
        if admin or document.get("admin") is not None:
            listen = str(admin.get("listen", "localhost:2019"))
            changes.append(
                _change(
                    "admin",
                    "admin_api",
                    "dangerous" if self._public_address(listen) else "review",
                    "Caddy admin API can replace live configuration and control the server.",
                )
            )
            if "*" in _items(admin.get("origins")):
                changes.append(
                    _change(
                        "admin.origins",
                        "wildcard_admin_origin",
                        "dangerous",
                        "Caddy admin API accepts browser origins without restriction.",
                    )
                )
        storage = _mapping(document.get("storage"))
        if storage:
            changes.append(
                _change(
                    "storage",
                    "certificate_storage",
                    "dangerous",
                    "Caddy uses a configurable module to store certificates and private keys.",
                )
            )
        http = _mapping(_mapping(document.get("apps")).get("http"))
        for name, server in _mapping(http.get("servers")).items():
            if not isinstance(server, dict):
                continue
            address = f"apps.http.servers.{name}"
            changes.append(
                _change(
                    address,
                    "server",
                    "review",
                    "Caddy JSON config defines an HTTP server and request-routing boundary.",
                )
            )
            if any(self._public_address(str(item)) for item in _items(server.get("listen"))):
                changes.append(
                    _change(
                        f"{address}.listen",
                        "public_listener",
                        "dangerous",
                        "Caddy listens on every network interface.",
                    )
                )
            if (
                _enabled(server.get("logs", {}).get("should_log_credentials"))
                if isinstance(server.get("logs"), dict)
                else False
            ):
                changes.append(
                    _change(
                        f"{address}.logs",
                        "credential_logging",
                        "dangerous",
                        "Caddy access logs include normally redacted credential headers.",
                    )
                )
            if server.get("trusted_proxies") is not None:
                changes.append(
                    _change(
                        f"{address}.trusted_proxies",
                        "proxy_trust",
                        "dangerous",
                        "Caddy trusts client address metadata supplied by configured proxies.",
                    )
                )
            self._json_routes(_items(server.get("routes")), f"{address}.routes", changes)
        tls = _mapping(_mapping(document.get("apps")).get("tls"))
        if tls:
            changes.append(
                _change(
                    "apps.tls",
                    "tls_automation",
                    "review",
                    "Caddy automates certificate issuance, loading, renewal, and storage.",
                )
            )
            automation = _mapping(tls.get("automation"))
            for index, policy in enumerate(_items(automation.get("policies"))):
                if (
                    isinstance(policy, dict)
                    and _enabled(policy.get("on_demand"))
                    and not policy.get("issuers")
                ):
                    changes.append(
                        _change(
                            f"apps.tls.automation.policies[{index}]",
                            "unrestricted_on_demand_tls",
                            "dangerous",
                            "Caddy on-demand TLS policy lacks a visible authorization mechanism.",
                        )
                    )
        changes.extend(self._secret_fields(document, "caddy"))
        return changes

    def _json_routes(self, routes: list[Any], address: str, changes: list[dict[str, Any]]) -> None:
        for index, route in enumerate(routes):
            if not isinstance(route, dict):
                continue
            route_address = f"{address}[{index}]"
            for handle_index, handler in enumerate(_items(route.get("handle"))):
                if not isinstance(handler, dict):
                    continue
                handler_address = f"{route_address}.handle[{handle_index}]"
                kind = str(handler.get("handler", "unknown"))
                if kind == "reverse_proxy":
                    changes.append(
                        _change(
                            handler_address,
                            "reverse_proxy",
                            "review",
                            "Caddy forwards requests, headers, and bodies to configured "
                            "upstream services.",
                        )
                    )
                    transport = _mapping(handler.get("transport"))
                    tls = _mapping(transport.get("tls"))
                    if _enabled(tls.get("insecure_skip_verify")):
                        changes.append(
                            _change(
                                f"{handler_address}.transport.tls",
                                "insecure_upstream_tls",
                                "dangerous",
                                "Caddy disables upstream certificate verification.",
                            )
                        )
                    for upstream in _items(handler.get("upstreams")):
                        dial = str(_mapping(upstream).get("dial", ""))
                        if dial.startswith("http://") and not self._local_url(dial):
                            changes.append(
                                _change(
                                    f"{handler_address}.upstreams",
                                    "plaintext_upstream",
                                    "dangerous",
                                    "Caddy proxies to a non-local upstream over plaintext HTTP.",
                                )
                            )
                elif kind == "file_server":
                    changes.append(
                        _change(
                            handler_address,
                            "file_server",
                            "dangerous" if handler.get("browse") is not None else "review",
                            "Caddy serves files from a configured filesystem.",
                        )
                    )
                elif kind in {"authentication", "forward_auth"}:
                    changes.append(
                        _change(
                            handler_address,
                            "authentication",
                            "dangerous",
                            "Caddy handler changes request authentication and identity trust.",
                        )
                    )
                elif kind in {"subroute", "routes"}:
                    self._json_routes(
                        _items(handler.get("routes")), f"{handler_address}.routes", changes
                    )
                elif kind not in {"encode", "headers", "rewrite", "static_response", "vars"}:
                    changes.append(
                        _change(
                            handler_address,
                            "extension_handler",
                            "review",
                            f"Caddy invokes the {kind} HTTP handler, which may be provided "
                            "by a module.",
                        )
                    )

    def _secret_fields(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                child_address = f"{address}.{key}"
                secret_key = str(key) not in {"should_log_credentials"} and _SECRET_KEY.search(
                    str(key)
                )
                if secret_key and child is not None and child != "":
                    changes.append(
                        _change(
                            child_address,
                            "secret_material",
                            "dangerous",
                            "Caddy configuration contains or references credential or "
                            "private-key material.",
                        )
                    )
                else:
                    changes.extend(self._secret_fields(child, child_address))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                changes.extend(self._secret_fields(child, f"{address}[{index}]"))
        return changes

    def _public_address(self, value: str) -> bool:
        return value.startswith((":", "0.0.0.0:", "[::]:", "::"))

    def _local_url(self, value: str) -> bool:
        return any(host in value.lower() for host in ("localhost", "127.0.0.1", "[::1]"))


def analyze_caddy(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    adapter = CaddyAdapter()
    changes = adapter.analyze(data, tool_name="caddy")
    summary = PlanSummary(
        path=Path("caddy://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="caddy")
    gate["adapter"] = "caddy"
    gate["total_changes"] = len(changes)
    return gate
