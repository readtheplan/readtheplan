from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.caddy import CaddyAdapter, CaddyInputError, parse_caddy_config
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(fixture: str) -> dict[str, list[str]]:
    data = parse_caddy_config((FIXTURES / fixture).read_text(encoding="utf-8"))
    result: dict[str, list[str]] = defaultdict(list)
    for change in CaddyAdapter().analyze(data, tool_name="caddy"):
        result[change.resource_type].append(change.risk)
    return result


def test_caddyfile_surfaces_admin_tls_proxy_filesystem_and_execution() -> None:
    risks = _risks("Caddyfile.risky")
    assert risks["caddy_admin_api"] == ["dangerous"]
    assert risks["caddy_wildcard_admin_origin"] == ["dangerous"]
    assert risks["caddy_automatic_https"] == ["dangerous"]
    assert risks["caddy_unrestricted_on_demand_tls"] == ["dangerous"]
    assert risks["caddy_proxy_trust"] == ["dangerous"]
    assert risks["caddy_credential_logging"] == ["dangerous"]
    assert risks["caddy_site"] == ["dangerous"]
    assert risks["caddy_reverse_proxy"] == ["review"]
    assert risks["caddy_plaintext_upstream"] == ["dangerous"]
    assert risks["caddy_insecure_upstream_tls"] == ["dangerous"]
    assert risks["caddy_client_certificate"] == ["dangerous"]
    assert risks["caddy_authentication"] == ["dangerous"]
    assert risks["caddy_file_server"] == ["dangerous"]
    assert risks["caddy_application_execution"] == ["dangerous"]
    assert risks["caddy_external_import"] == ["review"]
    assert risks["caddy_certificate_authority"] == ["dangerous"]


def test_native_json_surfaces_admin_handlers_tls_and_secrets() -> None:
    risks = _risks("caddy_risky.json")
    assert risks["caddy_admin_api"] == ["dangerous"]
    assert risks["caddy_wildcard_admin_origin"] == ["dangerous"]
    assert risks["caddy_certificate_storage"] == ["dangerous"]
    assert risks["caddy_public_listener"] == ["dangerous"]
    assert risks["caddy_proxy_trust"] == ["dangerous"]
    assert risks["caddy_credential_logging"] == ["dangerous"]
    assert risks["caddy_reverse_proxy"] == ["review"]
    assert risks["caddy_insecure_upstream_tls"] == ["dangerous"]
    assert risks["caddy_file_server"] == ["dangerous"]
    assert risks["caddy_extension_handler"] == ["review"]
    assert risks["caddy_unrestricted_on_demand_tls"] == ["dangerous"]
    assert risks["caddy_secret_material"] == ["dangerous"]


def test_secure_caddyfile_uses_automatic_https() -> None:
    data = parse_caddy_config("example.com {\n  reverse_proxy localhost:8080\n}\n")
    changes = CaddyAdapter().analyze(data, tool_name="caddy")
    kinds = {change.resource_type: change.risk for change in changes}
    assert kinds["caddy_site"] == "review"
    assert "caddy_plaintext_upstream" not in kinds
    assert "caddy_automatic_https" not in kinds


@pytest.mark.parametrize("source", ["", "foo bar", "example.com {", "{}", "[]"])
def test_parser_rejects_invalid_or_unrecognized_input(source: str) -> None:
    with pytest.raises(CaddyInputError):
        parse_caddy_config(source)


@pytest.mark.parametrize("fixture", ["Caddyfile.risky", "caddy_risky.json"])
def test_caddy_cli_supports_framework_checks(capsys, fixture: str) -> None:
    assert main(["caddy", "--framework", "soc2", str(FIXTURES / fixture)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "caddy"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
