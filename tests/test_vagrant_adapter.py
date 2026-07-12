from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.vagrant import (
    VagrantAdapter,
    VagrantInputError,
    parse_vagrantfile,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_vagrantfile_classifies_static_dsl_and_ruby_boundaries() -> None:
    data = parse_vagrantfile(
        (FIXTURES / "Vagrantfile.risky").read_text(encoding="utf-8")
    )
    changes = VagrantAdapter().analyze(data, tool_name="Vagrant")
    by_type: dict[str, list[str]] = defaultdict(list)
    for change in changes:
        by_type[change.resource_type].append(change.risk)

    assert by_type["vagrant_box"] == ["dangerous"]
    assert by_type["vagrant_box_url"] == ["dangerous"]
    assert by_type["vagrant_provider"] == ["review"]
    assert by_type["vagrant_provisioner"] == ["dangerous", "dangerous"]
    assert by_type["vagrant_network"] == ["dangerous", "dangerous"]
    assert by_type["vagrant_synced_folder"] == ["dangerous", "review"]
    assert by_type["vagrant_private_key"] == ["dangerous"]
    assert by_type["vagrant_trigger"] == ["dangerous", "dangerous"]
    assert by_type["vagrant_ruby_command"] == ["dangerous"]
    assert by_type["vagrant_ruby_dependency"] == ["dangerous"]
    assert by_type["vagrant_provider_customization"] == ["review"]
    assert by_type["vagrant_machine"] == ["review"]
    assert by_type["vagrant_ruby_boundary"] == ["review"]


def test_pinned_box_and_loopback_forward_are_review() -> None:
    data = parse_vagrantfile(
        '''
Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  config.vm.box_version = "12.20250126.1"
  config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"
end
'''
    )
    changes = VagrantAdapter().analyze(data, tool_name="Vagrant")
    assert [change.risk for change in changes] == ["review", "review", "review"]


def test_disabled_synced_folder_is_not_reported() -> None:
    data = parse_vagrantfile(
        'Vagrant.configure("2") { |config| '
        'config.vm.synced_folder ".", "/vagrant", disabled: true }'
    )
    changes = VagrantAdapter().analyze(data, tool_name="Vagrant")
    assert [change.resource_type for change in changes] == ["vagrant_ruby_boundary"]


def test_vagrant_cli_and_framework_baseline(capsys) -> None:
    assert (
        main(
            [
                "vagrant",
                "--framework",
                "soc2",
                str(FIXTURES / "Vagrantfile.risky"),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "vagrant"
    assert payload["decision"] == "block"
    assert payload["total_changes"] == 17
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize("source", ["", "puts 'hello'", "terraform plan"])
def test_vagrant_parser_rejects_non_vagrant_input(source: str) -> None:
    with pytest.raises(VagrantInputError):
        parse_vagrantfile(source)
