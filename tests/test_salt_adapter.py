from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.salt import SaltAdapter, SaltInputError, parse_salt_sls
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_salt_static_sls_classification() -> None:
    data = parse_salt_sls((FIXTURES / "salt_states_risky.sls").read_text(encoding="utf-8"))
    adapter = detect_adapter(data)
    assert isinstance(adapter, SaltAdapter)

    changes = adapter.analyze(data, use_rules=False)
    by_type = {change.resource_type: change for change in changes}
    assert by_type["salt_pkg_installed"].risk == "review"
    assert by_type["salt_service_running"].risk == "review"
    assert by_type["salt_file_absent"].risk == "dangerous"
    assert by_type["salt_cmd_run"].risk == "dangerous"
    assert "Pillar/SDB" in by_type["salt_cmd_run"].explanation
    assert by_type["salt_test_nop"].risk == "safe"
    assert by_type["salt_meta_include"].risk == "review"


def test_salt_jinja_fallback_flags_render_time_execution() -> None:
    data = parse_salt_sls(
        """
{% set files = salt['cmd.run']('ls /srv/releases') %}
deploy:
  cmd.run:
    - name: /usr/local/bin/deploy
{% if files %}
marker:
  file.managed:
    - name: /tmp/deployed
{% endif %}
"""
    )
    changes = SaltAdapter().analyze(data, use_rules=False)
    by_type = {change.resource_type: change for change in changes}
    assert by_type["salt_cmd_run"].risk == "dangerous"
    assert by_type["salt_meta_dynamic_renderer"].risk == "review"
    assert by_type["salt_meta_render_command"].risk == "dangerous"


@pytest.mark.parametrize(
    ("state", "expected_risk"),
    [
        ("pkg.removed", "dangerous"),
        ("service.dead", "dangerous"),
        ("user.absent", "dangerous"),
        ("mount.mounted", "dangerous"),
        ("docker_container.running", "dangerous"),
        ("file.managed", "review"),
        ("test.succeed_without_changes", "safe"),
    ],
)
def test_salt_state_risk_boundaries(state: str, expected_risk: str) -> None:
    data = parse_salt_sls(f"example:\n  {state}: []\n")
    change = SaltAdapter().analyze(data, use_rules=False)[0]
    assert change.risk == expected_risk


def test_salt_duplicate_ids_are_rejected() -> None:
    with pytest.raises(SaltInputError, match="duplicate YAML key"):
        parse_salt_sls("example:\n  pkg.installed: []\nexample:\n  service.running: []\n")


def test_salt_exclude_only_file_requires_review() -> None:
    data = parse_salt_sls("exclude:\n  - sls: legacy\n")
    changes = SaltAdapter().analyze(data, use_rules=False)
    assert len(changes) == 1
    assert changes[0].resource_type == "salt_meta_exclude"
    assert changes[0].risk == "review"


def test_salt_extend_requires_resolved_highstate_review() -> None:
    data = parse_salt_sls(
        "extend:\n  nginx:\n    service.running:\n      - watch:\n        - file: nginx\n"
    )
    changes = SaltAdapter().analyze(data, use_rules=False)
    assert len(changes) == 1
    assert changes[0].resource_type == "salt_meta_extend"
    assert changes[0].risk == "review"
    assert "resolved highstate" in changes[0].explanation


def test_salt_cli_and_framework_baseline(capsys) -> None:
    assert (
        main(
            [
                "salt",
                "--framework",
                "soc2",
                str(FIXTURES / "salt_states_risky.sls"),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "salt"
    assert payload["decision"] == "block"
    assert payload["total_changes"] == 6
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize("source", ["", "[]", "plain: yaml", "broken: [yaml"])
def test_salt_parser_rejects_non_state_input(source: str) -> None:
    with pytest.raises(SaltInputError):
        parse_salt_sls(source)
