from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.packer import (
    PackerInspectAdapter,
    PackerInspectError,
    parse_packer_inspect,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_packer_hcl_inspect_components_and_risks() -> None:
    data = parse_packer_inspect((FIXTURES / "packer_inspect_risky.txt").read_text(encoding="utf-8"))
    adapter = detect_adapter(data)
    assert isinstance(adapter, PackerInspectAdapter)
    inspect = data["packer_inspect"]
    assert inspect["mode"] == "hcl2"
    assert [build["name"] for build in inspect["builds"]] == [
        "cloud-image",
        "validation-only",
    ]
    assert inspect["builds"][0]["sources"] == ["amazon-ebs.production"]
    assert inspect["builds"][0]["provisioners"] == ["file", "shell", "ansible"]
    assert inspect["builds"][0]["post_processors"] == ["manifest", "docker-push"]

    changes = adapter.analyze(data, use_rules=False)
    by_type: dict[str, list[str]] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change.risk)
    assert by_type["packer_secret_input"] == ["dangerous"]
    assert by_type["packer_unresolved_variable"] == ["review"]
    assert by_type["packer_builder"] == ["dangerous", "review"]
    assert by_type["packer_provisioner"] == ["review", "dangerous", "dangerous", "safe"]
    assert by_type["packer_post_processor"] == ["safe", "dangerous"]
    assert by_type["packer_inspection_limit"] == ["review"]


def test_packer_machine_readable_ui_output() -> None:
    source = "\n".join(
        [
            "1700000000,,ui,say,Packer Inspect: HCL2 mode",
            "1700000000,,ui,say,> builds:",
            "1700000000,,ui,say,> image:",
            "1700000000,,ui,say,sources:",
            "1700000000,,ui,say,azure-arm.production",
            "1700000000,,ui,say,provisioners:",
            "1700000000,,ui,say,powershell",
            "1700000000,,ui,say,post-processors:",
            "1700000000,,ui,say,manifest",
            "1700000000,,ui,message,description%!(PACKER_COMMA)ignored",
        ]
    )
    data = parse_packer_inspect(source)
    build = data["packer_inspect"]["builds"][0]
    assert build["name"] == "image"
    assert build["sources"] == ["azure-arm.production"]
    assert build["provisioners"] == ["powershell"]
    assert build["post_processors"] == ["manifest"]


def test_packer_legacy_json_inspect() -> None:
    data = parse_packer_inspect(
        """
Packer Inspect: JSON mode
Required variables:
  token
Optional variables and their defaults:
Builders:
  docker
Provisioners:
  shell
"""
    )
    inspect = data["packer_inspect"]
    assert inspect["mode"] == "json"
    assert inspect["unknown_variables"] == 1
    assert inspect["builds"] == [
        {
            "name": "legacy-json",
            "sources": ["docker"],
            "provisioners": ["shell"],
            "post_processors": [],
        }
    ]


def test_packer_empty_builds_require_review() -> None:
    data = parse_packer_inspect("Packer Inspect: HCL2 mode\n> builds:\n")
    changes = PackerInspectAdapter().analyze(data, use_rules=False)
    assert [change.resource_type for change in changes] == [
        "packer_unresolved",
        "packer_inspection_limit",
    ]
    assert [change.risk for change in changes] == ["review", "review"]


def test_packer_cli_and_framework_baseline(capsys) -> None:
    assert (
        main(
            [
                "packer",
                "--framework",
                "soc2",
                str(FIXTURES / "packer_inspect_risky.txt"),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "packer"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize("source", ["", "not packer", json.dumps({"builds": []})])
def test_packer_parser_rejects_invalid_input(source: str) -> None:
    with pytest.raises(PackerInspectError):
        parse_packer_inspect(source)
