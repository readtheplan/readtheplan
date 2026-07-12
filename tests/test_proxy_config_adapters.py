from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.proxy_configs import (
    HAProxyAdapter,
    NginxAdapter,
    ProxyConfigInputError,
    parse_haproxy_config,
    parse_nginx_config,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(adapter, data) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)
    for change in adapter.analyze(data, tool_name=adapter.adapter_name):
        result[change.resource_type].append(change.risk)
    return result


def test_nginx_parser_preserves_nested_repeated_directives_and_risks() -> None:
    data = parse_nginx_config((FIXTURES / "nginx_risky.conf").read_text(encoding="utf-8"))
    risks = _risks(NginxAdapter(), data)
    entries = data["proxy_config"]["entries"]

    assert any(entry["Context"].endswith("location /") for entry in entries)
    assert risks["nginx_user"] == ["dangerous"]
    assert risks["nginx_load_module"] == ["dangerous"]
    assert risks["nginx_include"] == ["review"]
    assert risks["nginx_listen"] == ["dangerous"]
    assert risks["nginx_ssl_protocols"] == ["dangerous"]
    assert risks["nginx_ssl_certificate_key"] == ["dangerous"]
    assert risks["nginx_proxy_pass"] == ["dangerous"]
    assert risks["nginx_proxy_ssl_verify"] == ["dangerous"]
    assert risks["nginx_proxy_set_header"] == ["dangerous"]
    assert risks["nginx_autoindex"] == ["dangerous"]
    assert risks["nginx_effective_config_boundary"] == ["review"]


def test_nginx_loopback_modern_tls_and_deny_all() -> None:
    risks = _risks(
        NginxAdapter(),
        parse_nginx_config(
            "events {} http { server { listen 127.0.0.1:8080; "
            "ssl_protocols TLSv1.2 TLSv1.3; deny all; } }"
        ),
    )
    assert risks["nginx_listen"] == ["review"]
    assert risks["nginx_ssl_protocols"] == ["safe"]
    assert risks["nginx_deny"] == ["safe"]


def test_haproxy_parser_classifies_runtime_tls_routing_and_code() -> None:
    data = parse_haproxy_config(
        (FIXTURES / "haproxy_risky.cfg").read_text(encoding="utf-8")
    )
    risks = _risks(HAProxyAdapter(), data)

    assert risks["haproxy_user"] == ["dangerous"]
    assert risks["haproxy_lua_load"] == ["dangerous"]
    assert risks["haproxy_stats"] == ["dangerous", "dangerous"]
    assert risks["haproxy_ssl_server_verify"] == ["dangerous"]
    assert risks["haproxy_setenv"] == ["dangerous"]
    assert risks["haproxy_bind"] == ["dangerous"]
    assert risks["haproxy_http_request"] == ["review", "dangerous"]
    assert risks["haproxy_server"] == ["dangerous"]
    assert risks["haproxy_effective_config_boundary"] == ["review"]


def test_haproxy_chroot_loopback_and_verified_upstream() -> None:
    data = parse_haproxy_config(
        "global\n  chroot /var/empty\n  user haproxy\n"
        "frontend local\n  bind 127.0.0.1:8080\n"
        "backend app\n  server app1 10.0.0.2:443 ssl verify required ca-file /etc/ca.pem\n"
    )
    risks = _risks(HAProxyAdapter(), data)
    assert risks["haproxy_chroot"] == ["safe"]
    assert risks["haproxy_user"] == ["review"]
    assert risks["haproxy_bind"] == ["review"]
    assert risks["haproxy_server"] == ["review"]


@pytest.mark.parametrize(
    ("ecosystem", "fixture", "total"),
    [("nginx", "nginx_risky.conf", 19), ("haproxy", "haproxy_risky.cfg", 19)],
)
def test_proxy_cli_and_framework_baseline(capsys, ecosystem: str, fixture: str, total: int) -> None:
    assert main([ecosystem, "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == ecosystem
    assert payload["decision"] == "block"
    assert payload["total_changes"] == total
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize(
    ("parser", "source"),
    [
        (parse_nginx_config, ""),
        (parse_nginx_config, "http { server { listen 80; }"),
        (parse_nginx_config, "listen 80"),
        (parse_haproxy_config, ""),
        (parse_haproxy_config, "bind :80"),
        (parse_haproxy_config, "frontend\n  bind :80"),
    ],
)
def test_proxy_parsers_reject_invalid_input(parser, source: str) -> None:
    with pytest.raises(ProxyConfigInputError):
        parser(source)
