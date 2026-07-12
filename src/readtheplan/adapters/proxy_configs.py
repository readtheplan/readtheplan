from __future__ import annotations

import re
import shlex
from collections import Counter
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class ProxyConfigInputError(ValueError):
    """Raised when input is not recognizable as a supported proxy configuration."""


def _entry(
    ecosystem: str,
    context: str,
    directive: str,
    arguments: str,
    line: int,
    occurrence: int,
    *,
    kind: str | None = None,
) -> dict[str, Any]:
    return {
        "Ecosystem": ecosystem,
        "Context": context,
        "Directive": directive,
        "Arguments": arguments,
        "Line": line,
        "Kind": kind or directive,
        "Address": f"{context}.{directive}[{occurrence}]",
    }


def _nginx_tokens(source: str) -> list[tuple[str, int]]:
    tokens: list[tuple[str, int]] = []
    value = ""
    quote = ""
    escaped = False
    line = 1
    token_line = 1
    index = 0
    while index < len(source):
        char = source[index]
        if char == "\n":
            line += 1
        if escaped:
            value += char
            escaped = False
        elif char == "\\":
            value += char
            escaped = True
        elif quote:
            value += char
            if char == quote:
                quote = ""
        elif char in {'"', "'"}:
            if not value:
                token_line = line
            value += char
            quote = char
        elif char == "#":
            while index < len(source) and source[index] != "\n":
                index += 1
            continue
        elif char.isspace():
            if value:
                tokens.append((value, token_line))
                value = ""
        elif char in ";{}":
            if value:
                tokens.append((value, token_line))
                value = ""
            tokens.append((char, line))
        else:
            if not value:
                token_line = line
            value += char
        index += 1
    if quote:
        raise ProxyConfigInputError("unterminated quoted string")
    if value:
        tokens.append((value, token_line))
    return tokens


def parse_nginx_config(source: str) -> dict[str, Any]:
    """Parse NGINX configuration statically without resolving includes."""
    if not source.strip():
        raise ProxyConfigInputError("input is empty")
    tokens = _nginx_tokens(source)
    stack = ["main"]
    statement: list[tuple[str, int]] = []
    entries: list[dict[str, Any]] = []
    occurrences: Counter[tuple[str, str]] = Counter()
    for token, line in tokens:
        if token not in {";", "{", "}"}:
            statement.append((token, line))
            continue
        if token == "}":
            if statement:
                raise ProxyConfigInputError(f"directive missing semicolon before line {line}")
            if len(stack) == 1:
                raise ProxyConfigInputError(f"unmatched closing brace at line {line}")
            stack.pop()
            continue
        if not statement:
            raise ProxyConfigInputError(f"empty statement at line {line}")
        directive = statement[0][0].lower()
        arguments = " ".join(item[0] for item in statement[1:])
        statement_line = statement[0][1]
        context = "/".join(stack)
        occurrence = occurrences[(context, directive)]
        occurrences[(context, directive)] += 1
        entries.append(
            _entry("nginx", context, directive, arguments, statement_line, occurrence)
        )
        if token == "{":
            label = f"{directive} {arguments}".strip()
            stack.append(label)
        statement = []
    if statement:
        raise ProxyConfigInputError(
            f"unterminated directive at line {statement[0][1]} (missing semicolon or block)"
        )
    if len(stack) != 1:
        raise ProxyConfigInputError("unclosed configuration block")
    if not entries:
        raise ProxyConfigInputError("no NGINX directives found")
    entries.append(
        _entry(
            "nginx",
            "main",
            "effective_config_boundary",
            "includes, modules, inheritance, environment, and command-line options",
            1,
            0,
            kind="effective_config_boundary",
        )
    )
    return {"proxy_config": {"ecosystem": "nginx", "entries": entries}}


_HAPROXY_SECTIONS = {
    "backend",
    "cache",
    "defaults",
    "frontend",
    "global",
    "listen",
    "mailers",
    "peers",
    "program",
    "resolvers",
    "ring",
    "userlist",
}


def parse_haproxy_config(source: str) -> dict[str, Any]:
    """Parse HAProxy configuration lines without loading files or running checks."""
    if not source.strip():
        raise ProxyConfigInputError("input is empty")
    context = ""
    entries: list[dict[str, Any]] = []
    occurrences: Counter[tuple[str, str]] = Counter()
    for line_number, raw_line in enumerate(source.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            parts = shlex.split(stripped, comments=True, posix=True)
        except ValueError as exc:
            raise ProxyConfigInputError(f"invalid quoting at line {line_number}: {exc}") from exc
        if not parts:
            continue
        directive = parts[0].lower()
        if directive in _HAPROXY_SECTIONS:
            name = " ".join(parts[1:])
            if directive not in {"global", "defaults"} and not name:
                raise ProxyConfigInputError(
                    f"{directive} section requires a name at line {line_number}"
                )
            context = f"{directive} {name}".strip()
            continue
        if not context:
            raise ProxyConfigInputError(f"directive appears before a section at line {line_number}")
        arguments = " ".join(parts[1:])
        occurrence = occurrences[(context, directive)]
        occurrences[(context, directive)] += 1
        entries.append(
            _entry("haproxy", context, directive, arguments, line_number, occurrence)
        )
    if not entries:
        raise ProxyConfigInputError("no HAProxy directives found")
    entries.append(
        _entry(
            "haproxy",
            "global",
            "effective_config_boundary",
            "defaults inheritance, environment, state files, maps, certificates, and runtime API",
            1,
            0,
            kind="effective_config_boundary",
        )
    )
    return {"proxy_config": {"ecosystem": "haproxy", "entries": entries}}


def _public_endpoint(value: str) -> bool:
    endpoint = value.split()[0] if value.split() else ""
    endpoint = endpoint.split(",", 1)[0]
    return not (
        endpoint.startswith(("127.", "localhost", "unix:", "/", "fd@"))
        or endpoint.startswith("[::1]")
    )


class ProxyConfigAdapter(BaseAdapter):
    def __init__(self, ecosystem: str) -> None:
        self.ecosystem = ecosystem

    @property
    def adapter_name(self) -> str:
        return self.ecosystem

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("proxy_config")
        return (
            isinstance(config, dict)
            and config.get("ecosystem") == self.ecosystem
            and isinstance(config.get("entries"), list)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        return list(input_data["proxy_config"]["entries"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        directive = str(raw.get("Directive") or "unknown").lower()
        arguments = str(raw.get("Arguments") or "")
        kind = str(raw.get("Kind") or directive).lower()
        context = str(raw.get("Context") or "main")
        risk = "review"
        explanation = f"{self.ecosystem} {directive} in {context} requires review."
        if self.ecosystem == "nginx":
            risk, explanation = self._normalize_nginx(directive, arguments, context, kind)
        else:
            risk, explanation = self._normalize_haproxy(directive, arguments, context, kind)
        return ResourceChange(
            address=str(raw.get("Address") or f"{context}.{directive}"),
            resource_type=f"{self.ecosystem}_{kind.replace('-', '_')}",
            actions=("configure",),
            risk=risk,
            explanation=explanation,
        )

    def _normalize_nginx(
        self, directive: str, arguments: str, context: str, kind: str
    ) -> tuple[str, str]:
        lower = arguments.lower()
        if directive == "load_module" or directive.startswith(("lua_", "perl_")):
            return "dangerous", f"NGINX {directive} loads executable code into worker processes."
        if directive == "include":
            return "review", "NGINX include imports configuration outside this artifact."
        if directive == "user":
            root = arguments.split()[:1] in (["root"], ["0"])
            return ("dangerous" if root else "review"), "NGINX user sets worker identity."
        if directive == "listen":
            exposure = "dangerous" if _public_endpoint(arguments) else "review"
            return exposure, f"NGINX listen exposes endpoint '{arguments}'."
        if directive in {"proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass"}:
            return "dangerous", f"NGINX {directive} routes requests to '{arguments}'."
        if directive in {"proxy_ssl_verify", "grpc_ssl_verify"} and lower == "off":
            return "dangerous", f"NGINX {directive}=off disables upstream certificate verification."
        if directive == "ssl_protocols":
            legacy = bool(re.search(r"(?:^|\s)(?:sslv\d|tlsv1(?:\.0|\.1)?)(?:\s|$)", lower))
            return ("dangerous" if legacy else "safe"), "NGINX ssl_protocols selects TLS versions."
        if directive in {"ssl_certificate_key", "proxy_ssl_certificate_key", "ssl_password_file"}:
            return "dangerous", f"NGINX {directive} references private credential material."
        if directive in {"auth_basic_user_file", "auth_jwt_key_file", "auth_request"}:
            return "dangerous", f"NGINX {directive} configures an authentication trust boundary."
        if directive == "allow" and lower == "all":
            return "dangerous", "NGINX allow all opens the current access-control scope."
        if directive == "deny" and lower == "all":
            return "safe", "NGINX deny all closes the current access-control scope."
        if directive == "autoindex" and lower == "on":
            return "dangerous", "NGINX autoindex exposes directory listings."
        if directive in {"root", "alias"}:
            return "review", f"NGINX {directive} exposes host filesystem content."
        if directive in {"proxy_set_header", "add_header", "more_set_headers"}:
            sensitive = "authorization" in lower or "cookie" in lower
            return ("dangerous" if sensitive else "review"), f"NGINX {directive} mutates headers."
        if directive in {"resolver", "proxy_bind", "auth_request_set"}:
            return (
                "review",
                f"NGINX {directive} changes name resolution, source binding, or auth data.",
            )
        if kind == "effective_config_boundary":
            return (
                "review",
                "Effective NGINX behavior depends on includes, modules, and inheritance.",
            )
        return "review", f"NGINX {directive} in {context} requires review."

    def _normalize_haproxy(
        self, directive: str, arguments: str, context: str, kind: str
    ) -> tuple[str, str]:
        lower = arguments.lower()
        if directive in {"lua-load", "lua-load-per-thread", "module-load", "program"}:
            return "dangerous", f"HAProxy {directive} loads or runs executable code."
        if context.startswith("program ") and directive in {"command", "user", "group"}:
            return "dangerous", f"HAProxy program {directive} controls an external process."
        if directive in {"external-check", "external-check path", "external-check command"}:
            return "dangerous", f"HAProxy {directive} enables external health-check execution."
        if directive in {"user", "uid"}:
            root = lower in {"root", "0"}
            return (
                "dangerous" if root else "review",
                "HAProxy runtime user controls process identity.",
            )
        if directive == "chroot":
            return "safe", "HAProxy chroot constrains runtime filesystem visibility."
        if directive == "bind":
            risk = "dangerous" if _public_endpoint(arguments) else "review"
            return risk, f"HAProxy bind exposes endpoint '{arguments}'."
        if directive in {"server", "default-server", "server-template"}:
            if re.search(r"(?:^|\s)verify\s+none(?:\s|$)", lower):
                return "dangerous", "HAProxy upstream disables TLS certificate verification."
            return (
                "review",
                f"HAProxy {directive} configures an upstream endpoint and trust options.",
            )
        if directive in {"ssl-server-verify", "httpclient.ssl.verify"} and lower == "none":
            return "dangerous", f"HAProxy {directive} disables certificate verification."
        if directive in {"crt-base", "ca-base", "server-state-file", "load-server-state-from-file"}:
            return (
                "dangerous",
                f"HAProxy {directive} loads trust or runtime state outside this artifact.",
            )
        if directive == "stats" or directive.startswith("stats "):
            return (
                "dangerous",
                f"HAProxy {directive} exposes or authenticates a management surface.",
            )
        if directive in {"http-request", "http-response", "tcp-request", "tcp-response"}:
            executable = "use-service" in lower or "lua." in lower
            return (
                "dangerous" if executable else "review",
                f"HAProxy {directive} mutates traffic.",
            )
        if directive in {"use_backend", "default_backend", "redirect", "acl"}:
            return "review", f"HAProxy {directive} changes request routing or access conditions."
        if directive in {"setenv", "presetenv"}:
            sensitive = bool(re.search(r"(?:secret|token|password|credential|key)", lower))
            return (
                "dangerous" if sensitive else "review",
                f"HAProxy {directive} sets process environment.",
            )
        if kind == "effective_config_boundary":
            return (
                "review",
                "Effective HAProxy behavior depends on inheritance, files, and runtime state.",
            )
        return "review", f"HAProxy {directive} in {context} requires review."


class NginxAdapter(ProxyConfigAdapter):
    def __init__(self) -> None:
        super().__init__("nginx")


class HAProxyAdapter(ProxyConfigAdapter):
    def __init__(self) -> None:
        super().__init__("haproxy")


def analyze_proxy_config(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    config = data.get("proxy_config")
    ecosystem = str(config.get("ecosystem")) if isinstance(config, dict) else "proxy"
    adapter: ProxyConfigAdapter = NginxAdapter() if ecosystem == "nginx" else HAProxyAdapter()
    changes = adapter.analyze(data, tool_name=ecosystem)
    summary = PlanSummary(
        path=Path(f"{ecosystem}://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name=ecosystem)
    gate["adapter"] = ecosystem
    gate["total_changes"] = len(changes)
    return gate
