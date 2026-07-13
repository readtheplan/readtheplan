from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from readtheplan.adapters import ansible as ansible_module
from readtheplan.adapters import detect_adapter
from readtheplan.adapters.ansible import (
    AnsibleAdapter,
    AnsibleInputError,
    analyze_ansible,
    parse_ansible,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


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
    assert changes[1].address == "playbook[0].tasks[1]"


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
    assert main(["ansible", "--framework", "soc2", str(playbook)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "proceed"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


def test_ansible_cli_rejects_non_playbook(tmp_path, capsys) -> None:
    source = tmp_path / "vars.yml"
    source.write_text("region: us-east-1\n", encoding="utf-8")
    assert main(["ansible", str(source)]) == 1
    assert "not an Ansible playbook or reusable task list" in capsys.readouterr().err


def test_parses_and_analyzes_role_task_files_with_redacted_output() -> None:
    path = FIXTURES / "ansible_role_content_risky" / "roles" / "application" / "tasks" / "main.yml"
    data = parse_ansible(path.read_text(encoding="utf-8"), filename=str(path))

    assert data["ansible_artifact_type"] == "task_file"
    assert data["ansible_metadata"] == {
        "artifact_type": "task_file",
        "task_count": 11,
        "handler_count": 0,
        "dynamic_count": 2,
    }
    gate = analyze_ansible(data)
    encoded = json.dumps(gate)
    assert gate["decision"] == "block"
    assert gate["total_changes"] == 11
    assert gate["risk_counts"] == {
        "safe": 0,
        "review": 4,
        "dangerous": 7,
        "irreversible": 0,
    }
    assert "runtime include conditions" in encoded
    assert "dynamically loads" in encoded
    assert "statically imports" in encoded
    for secret in (
        "fixture-task-token-do-not-leak",
        "fixture-environment-token-do-not-leak",
        "fixture-handler-topic-do-not-leak",
        "downloads.example.invalid",
    ):
        assert secret not in encoded


def test_parses_and_analyzes_role_handler_files_with_global_scope_boundary() -> None:
    path = (
        FIXTURES / "ansible_role_content_risky" / "roles" / "application" / "handlers" / "main.yml"
    )
    data = parse_ansible(path.read_text(encoding="utf-8"), filename=str(path))
    gate = analyze_ansible(data)
    encoded = json.dumps(gate)

    assert gate["artifact_type"] == "handler_file"
    assert gate["task_count"] == 0
    assert gate["handler_count"] == 4
    assert gate["dynamic_count"] == 2
    assert gate["total_changes"] == 5
    assert gate["risk_counts"] == {
        "safe": 0,
        "review": 3,
        "dangerous": 2,
        "irreversible": 0,
    }
    assert "play-wide handler namespace" in encoded
    assert "notification topic" in encoded
    assert "fixture-handler-name-do-not-leak" not in encoded
    assert "fixture-handler-message-do-not-leak" not in encoded
    assert "fixture-recursive-notification-do-not-leak" not in encoded


def test_review_role_content_does_not_overstate_danger() -> None:
    root = FIXTURES / "ansible_role_content_review" / "roles" / "observer"
    task_data = parse_ansible(
        (root / "tasks" / "main.yml").read_text(encoding="utf-8"),
        filename=str(root / "tasks" / "main.yml"),
    )
    handler_data = parse_ansible(
        (root / "handlers" / "main.yml").read_text(encoding="utf-8"),
        filename=str(root / "handlers" / "main.yml"),
    )

    assert Counter(change.risk for change in AnsibleAdapter().analyze(task_data)) == {
        "safe": 1,
        "review": 4,
    }
    assert Counter(change.risk for change in AnsibleAdapter().analyze(handler_data)) == {
        "review": 2
    }


def test_generic_reusable_task_list_is_accepted_by_explicit_ansible_gate() -> None:
    data = parse_ansible("- ansible.builtin.debug:\n    msg: ok\n", filename="checks.yml")
    assert data["ansible_artifact_type"] == "task_file"
    assert data["ansible_metadata"]["task_count"] == 1


def test_playbook_parser_preserves_multi_document_and_nonrecursive_alias_support() -> None:
    playbook = parse_ansible(
        """
---
- hosts: web
  tasks:
    - debug: &debug_args
        msg: ok
    - debug: *debug_args
---
- import_playbook: hardening.yml
""",
        filename="playbook.yml",
    )
    assert playbook["ansible_artifact_type"] == "playbook"
    assert len(playbook["plays"]) == 2
    assert playbook["ansible_metadata"]["task_count"] == 2
    assert analyze_ansible(playbook)["total_changes"] == 3


def test_task_level_args_and_runtime_controls_are_analyzed() -> None:
    data = parse_ansible(
        """
- ansible.builtin.get_url: https://example.invalid/package
  args:
    validate_certs: false
- ansible.builtin.debug:
    msg: inspect
  vars:
    api_token: fixture-vars-token-do-not-leak
- ansible.builtin.debug:
    msg: inspect
  with_community_lookup:
    - item
- ansible.builtin.meta: flush_handlers
""",
        filename="roles/example/tasks/main.yml",
    )
    gate = analyze_ansible(data)
    encoded = json.dumps(gate)

    assert gate["risk_counts"] == {
        "safe": 0,
        "review": 3,
        "dangerous": 2,
        "irreversible": 0,
    }
    assert "TLS certificate validation is disabled" in encoded
    assert "credential-like task variables" in encoded
    assert "lookup plugin" in encoded
    assert "handler timing" in encoded
    assert "fixture-vars-token-do-not-leak" not in encoded


def test_role_tasks_classify_sensitive_filesystem_and_remote_api_mutations() -> None:
    data = parse_ansible(
        """
- ansible.builtin.copy:
    content: 'deploy ALL=(ALL) NOPASSWD: ALL'
    dest: /etc/sudoers.d/deploy
- ansible.builtin.file:
    path: /srv/shared
    state: directory
    mode: '0777'
- ansible.builtin.uri:
    url: https://api.example.invalid/deploy
    method: POST
- ansible.builtin.template:
    src: application.conf.j2
    dest: /etc/application.conf
""",
        filename="roles/example/tasks/main.yml",
    )
    gate = analyze_ansible(data)
    encoded = json.dumps(gate)

    assert gate["risk_counts"] == {
        "safe": 0,
        "review": 2,
        "dangerous": 3,
        "irreversible": 0,
    }
    assert "host security" in encoded
    assert "world-writable" in encoded
    assert "mutating remote API request" in encoded
    assert "/etc/sudoers" not in encoded
    assert "api.example.invalid" not in encoded


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("- shell: first\n  shell: second\n", "duplicate YAML key"),
        ("- shell: first\n  command: second\n", "multiple task actions"),
        ("- name: missing action\n", "does not define a task action or block"),
        ("- !!python/object/apply:os.system ['echo unsafe']\n", "invalid YAML syntax"),
        ("- action: {}\n", "must name a module"),
        ("- shell: first\n  block: []\n", "both an action and a block"),
        ("- &loop\n  block:\n    - *loop\n", "recursive YAML alias"),
        ("- debug:\n    msg: ok\x00\n", "NUL byte"),
    ],
)
def test_rejects_malformed_or_unsafe_task_content(source: str, message: str) -> None:
    with pytest.raises(AnsibleInputError, match=message):
        parse_ansible(source, filename="roles/example/tasks/main.yml")


def test_rejects_play_shape_in_role_task_context() -> None:
    source = "- hosts: all\n  tasks:\n    - debug: {}\n"
    with pytest.raises(AnsibleInputError, match="cannot contain plays"):
        parse_ansible(source, filename="roles/example/handlers/main.yml")


def test_rejects_play_without_target_hosts() -> None:
    source = "- tasks:\n    - debug: {}\n"
    with pytest.raises(AnsibleInputError, match="missing hosts"):
        parse_ansible(source, filename="playbook.yml")


def test_yaml_errors_do_not_echo_source_content() -> None:
    secret = "fixture-invalid-yaml-secret-do-not-leak"
    with pytest.raises(AnsibleInputError) as error:
        parse_ansible(
            f"- debug:\n    msg: [{secret}\n",
            filename="roles/example/tasks/main.yml",
        )
    assert str(error.value) == "invalid YAML syntax"
    assert secret not in str(error.value)


@pytest.mark.parametrize(
    ("limit", "value", "source", "message"),
    [
        ("_MAX_SOURCE_BYTES", 20, "- debug:\n    msg: this-is-too-long\n", "source size"),
        ("_MAX_SOURCE_LINES", 2, "- debug:\n    msg: ok\n", "source line"),
        ("_MAX_YAML_NODES", 3, "- debug:\n    msg: ok\n", "node count"),
        (
            "_MAX_NESTING_DEPTH",
            2,
            "- block:\n    - block:\n        - debug: {}\n",
            "nesting depth",
        ),
        ("_MAX_TASKS", 1, "- debug: {}\n- debug: {}\n", "task count"),
        ("_MAX_DOCUMENTS", 1, "---\n[]\n---\n[]\n", "document count"),
    ],
)
def test_enforces_parser_limits(
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
    value: int,
    source: str,
    message: str,
) -> None:
    monkeypatch.setattr(ansible_module, limit, value)
    with pytest.raises(AnsibleInputError, match=message):
        parse_ansible(source, filename="roles/example/tasks/main.yml")


def test_parser_never_executes_task_source(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("source was executed")

    monkeypatch.setattr(subprocess, "run", fail)
    data = parse_ansible(
        "- ansible.builtin.shell: 'echo fixture-command-do-not-run'\n",
        filename="roles/example/tasks/main.yml",
    )
    assert data["ansible_artifact_type"] == "task_file"


def test_ansible_cli_accepts_role_task_and_handler_files(capsys) -> None:
    root = FIXTURES / "ansible_role_content_risky" / "roles" / "application"
    for relative, artifact_type, total in (
        (Path("tasks/main.yml"), "task_file", 11),
        (Path("handlers/main.yml"), "handler_file", 5),
    ):
        assert main(["ansible", str(root / relative)]) == 2
        payload = json.loads(capsys.readouterr().out)
        assert payload["artifact_type"] == artifact_type
        assert payload["total_changes"] == total
