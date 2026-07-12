from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.systemd import (
    SystemdUnitAdapter,
    SystemdUnitInputError,
    parse_systemd_unit,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(source: str) -> dict[str, list[str]]:
    changes = SystemdUnitAdapter().analyze(parse_systemd_unit(source), tool_name="systemd")
    by_type: dict[str, list[str]] = defaultdict(list)
    for change in changes:
        by_type[change.resource_type].append(change.risk)
    return by_type


def test_risky_service_classifies_execution_identity_credentials_and_sandbox() -> None:
    risks = _risks((FIXTURES / "systemd_risky.service").read_text(encoding="utf-8"))

    assert risks["systemd_execstart"] == ["dangerous"]
    assert risks["systemd_environment"] == ["dangerous"]
    assert risks["systemd_loadcredential"] == ["dangerous"]
    assert risks["systemd_ambientcapabilities"] == ["dangerous"]
    assert risks["systemd_nonewprivileges"] == ["dangerous"]
    assert risks["systemd_readwritepaths"] == ["dangerous"]
    assert risks["systemd_deviceallow"] == ["dangerous"]
    assert risks["systemd_runtime_identity"] == ["dangerous"]
    assert risks["systemd_restart_loop"] == ["dangerous"]
    assert risks["systemd_merge_boundary"] == ["review"]


def test_hardened_service_and_reset_directives_are_preserved() -> None:
    source = """
[Service]
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=CAP_NET_ADMIN
CapabilityBoundingSet=
Environment=MODE=production
ExecStart=/usr/bin/example \\
  --foreground
Restart=on-failure
RestartSec=10s
"""
    data = parse_systemd_unit(source)
    entries = data["systemd_unit"]["entries"]
    addresses = [entry["Address"] for entry in entries]
    risks = _risks(source)

    assert "Service.CapabilityBoundingSet[0]" in addresses
    assert "Service.CapabilityBoundingSet[1]" in addresses
    assert risks["systemd_dynamicuser"] == ["safe"]
    assert risks["systemd_nonewprivileges"] == ["safe"]
    assert risks["systemd_protectsystem"] == ["safe"]
    assert risks["systemd_capabilityboundingset"] == ["dangerous", "safe"]
    assert "systemd_runtime_identity" not in risks
    assert "systemd_restart_loop" not in risks


def test_socket_timer_mount_and_path_units_surface_activation_boundaries() -> None:
    socket_risks = _risks("[Socket]\nListenStream=0.0.0.0:8080\nSocketMode=0666\nAccept=yes\n")
    timer_risks = _risks("[Timer]\nOnCalendar=daily\nPersistent=yes\nWakeSystem=yes\n")
    mount_risks = _risks("[Mount]\nWhat=/dev/sdb1\nWhere=/srv/data\nType=ext4\n")
    path_risks = _risks("[Path]\nPathChanged=/etc/example.conf\n")

    assert socket_risks["systemd_listenstream"] == ["dangerous"]
    assert socket_risks["systemd_socketmode"] == ["dangerous"]
    assert socket_risks["systemd_activated_unit_boundary"] == ["review"]
    assert timer_risks["systemd_wakesystem"] == ["dangerous"]
    assert timer_risks["systemd_triggered_unit_boundary"] == ["review"]
    assert mount_risks["systemd_what"] == ["dangerous"]
    assert path_risks["systemd_pathchanged"] == ["review"]


def test_systemd_cli_and_framework_baseline(capsys) -> None:
    assert main(["systemd", "--framework", "soc2", str(FIXTURES / "systemd_risky.service")]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "systemd"
    assert payload["decision"] == "block"
    assert payload["total_changes"] == 30
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize(
    "source",
    ["", "Description=no section", "[Unit]\nDescription=no typed section", "[Service]\ninvalid"],
)
def test_parser_rejects_invalid_or_untyped_units(source: str) -> None:
    with pytest.raises(SystemdUnitInputError):
        parse_systemd_unit(source)
