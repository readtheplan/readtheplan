from __future__ import annotations

import json

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.ansible import AnsibleAdapter, analyze_ansible
from readtheplan.cli import main


def _playbook(*tasks: dict) -> dict:
    return {"plays": [{"name": "web", "hosts": "all", "tasks": list(tasks)}]}


def test_detects_and_classifies_ansible_tasks() -> None:
    data = _playbook(
        {"name": "inspect", "ansible.builtin.debug": {"msg": "hello"}},
        {"name": "remove config", "file": {"path": "/etc/app", "state": "absent"}},
        {"name": "restart", "systemd": {"name": "app", "state": "restarted"}},
        {"name": "run migration", "shell": "./migrate.sh"},
    )
    adapter = detect_adapter(data)
    assert isinstance(adapter, AnsibleAdapter)

    changes = adapter.analyze(data, tool_name="Ansible")
    assert [change.risk for change in changes] == [
        "safe",
        "dangerous",
        "dangerous",
        "dangerous",
    ]
    assert changes[0].resource_type == "ansible_debug"
    assert changes[1].address == "web.tasks[1]"


def test_ansible_nested_blocks_and_roles_are_not_silently_skipped() -> None:
    data = {
        "plays": [
            {
                "hosts": "all",
                "roles": ["baseline"],
                "tasks": [
                    {
                        "name": "guarded work",
                        "block": [{"name": "copy", "template": {"src": "a", "dest": "b"}}],
                        "rescue": [{"name": "recover", "command": "restore"}],
                    }
                ],
            }
        ]
    }
    changes = AnsibleAdapter().analyze(data, use_rules=False)
    assert {change.resource_type for change in changes} == {
        "ansible_include_role",
        "ansible_template",
        "ansible_command",
    }


def test_ansible_gate_uses_shared_contract() -> None:
    gate = analyze_ansible(_playbook({"shell": "terraform apply -auto-approve"}))
    assert gate["schema"] == "rtp-agent-gate-v1"
    assert gate["decision"] == "block"
    assert "Ansible" in gate["reason"]


def test_ansible_cli_reads_yaml(tmp_path, capsys) -> None:
    playbook = tmp_path / "playbook.yml"
    playbook.write_text(
        "- hosts: all\n  tasks:\n    - name: inspect\n      debug:\n        msg: ok\n",
        encoding="utf-8",
    )
    assert main(["ansible", str(playbook)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "proceed"


def test_ansible_cli_rejects_non_playbook(tmp_path, capsys) -> None:
    source = tmp_path / "vars.yml"
    source.write_text("region: us-east-1\n", encoding="utf-8")
    assert main(["ansible", str(source)]) == 1
    assert "not recognized" in capsys.readouterr().err
