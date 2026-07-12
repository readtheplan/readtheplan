from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.cloud_init import (
    CloudInitAdapter,
    CloudInitInputError,
    parse_cloud_init,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cloud_config_classifies_bootstrap_risks() -> None:
    data = parse_cloud_init(
        (FIXTURES / "cloud_init_risky.yml").read_text(encoding="utf-8")
    )
    changes = CloudInitAdapter().analyze(data, tool_name="cloud-init")
    by_type: dict[str, list[str]] = defaultdict(list)
    for change in changes:
        by_type[change.resource_type].append(change.risk)

    assert by_type["cloud_init_package_update"] == ["review"]
    assert by_type["cloud_init_packages"] == ["review"]
    assert by_type["cloud_init_user"] == ["review", "dangerous"]
    assert by_type["cloud_init_ssh_pwauth"] == ["dangerous"]
    assert by_type["cloud_init_disable_root"] == ["dangerous"]
    assert by_type["cloud_init_ssh_keys"] == ["dangerous"]
    assert by_type["cloud_init_write_file"] == ["dangerous", "dangerous"]
    assert by_type["cloud_init_bootcmd"] == ["dangerous"]
    assert by_type["cloud_init_runcmd"] == ["dangerous", "dangerous"]
    assert by_type["cloud_init_disk_setup"] == ["dangerous"]
    assert by_type["cloud_init_power_state"] == ["dangerous"]
    assert by_type["cloud_init_final_message"] == ["safe"]
    assert by_type["cloud_init_unknown_module"] == ["review"]
    assert by_type["cloud_init_merge_boundary"] == ["review"]
    assert by_type["cloud_init_jinja"] == ["review"]


@pytest.mark.parametrize(
    ("source", "resource_type", "risk"),
    [
        ("#!/bin/sh\necho hello\n", "cloud_init_script", "dangerous"),
        ("#cloud-boothook\necho early\n", "cloud_init_boothook", "dangerous"),
        ("#include\nhttps://example.test/user-data\n", "cloud_init_include", "dangerous"),
        (
            'Content-Type: multipart/mixed; boundary="x"\n',
            "cloud_init_multipart",
            "dangerous",
        ),
        (
            '#cloud-config-archive\n- type: "text/x-shellscript"\n  content: echo hi\n',
            "cloud_init_archive",
            "dangerous",
        ),
        ("#part-handler\ndef list_types(): return []\n", "cloud_init_part_handler", "dangerous"),
    ],
)
def test_cloud_init_executable_and_container_formats(
    source: str, resource_type: str, risk: str
) -> None:
    changes = CloudInitAdapter().analyze(parse_cloud_init(source), tool_name="cloud-init")
    assert changes[0].resource_type == resource_type
    assert changes[0].risk == risk


def test_cloud_init_duplicate_keys_are_rejected() -> None:
    with pytest.raises(CloudInitInputError, match="duplicate YAML key"):
        parse_cloud_init("#cloud-config\nruncmd: []\nruncmd: []\n")


def test_cloud_init_empty_include_is_rejected() -> None:
    with pytest.raises(CloudInitInputError, match="contains no URLs"):
        parse_cloud_init("#include\n")


def test_cloud_init_cli_and_framework_baseline(capsys) -> None:
    assert (
        main(
            [
                "cloud-init",
                "--framework",
                "soc2",
                str(FIXTURES / "cloud_init_risky.yml"),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "cloud-init"
    assert payload["decision"] == "block"
    assert payload["total_changes"] == 20
    assert payload["risk_counts"] == {
        "dangerous": 11,
        "irreversible": 0,
        "review": 8,
        "safe": 1,
    }
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize("source", ["", "packages: [curl]", "hello world"])
def test_cloud_init_rejects_unmarked_input(source: str) -> None:
    with pytest.raises(CloudInitInputError):
        parse_cloud_init(source)
