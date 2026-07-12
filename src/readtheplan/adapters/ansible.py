from __future__ import annotations

from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_TASK_METADATA = {
    "always",
    "any_errors_fatal",
    "args",
    "become",
    "become_flags",
    "become_method",
    "become_user",
    "block",
    "changed_when",
    "check_mode",
    "collections",
    "connection",
    "debugger",
    "delegate_facts",
    "delegate_to",
    "diff",
    "environment",
    "failed_when",
    "ignore_errors",
    "ignore_unreachable",
    "loop",
    "loop_control",
    "name",
    "no_log",
    "notify",
    "poll",
    "register",
    "rescue",
    "retries",
    "run_once",
    "tags",
    "throttle",
    "timeout",
    "until",
    "vars",
    "when",
    "with_items",
}

_SAFE_MODULES = {"assert", "debug", "fail", "meta", "set_fact", "stat"}
_DANGEROUS_MODULES = {
    "command",
    "expect",
    "iptables",
    "nftables",
    "raw",
    "reboot",
    "script",
    "shell",
    "ufw",
}


def _short_module_name(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower()


def _module_and_args(task: dict[str, Any]) -> tuple[str, Any] | None:
    for key, value in task.items():
        if key not in _TASK_METADATA and not key.startswith("with_"):
            return _short_module_name(key), value
    return None


class AnsibleAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "ansible"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        plays = input_data.get("plays")
        return isinstance(plays, list) and any(
            isinstance(play, dict) and any(key in play for key in ("tasks", "roles", "hosts"))
            for play in plays
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for play_index, play in enumerate(input_data.get("plays", [])):
            if not isinstance(play, dict):
                continue
            play_name = str(play.get("name") or play.get("hosts") or f"play-{play_index + 1}")
            for section in ("pre_tasks", "tasks", "post_tasks", "handlers"):
                self._extract_tasks(
                    play.get(section, []),
                    changes,
                    prefix=f"{play_name}.{section}",
                )
            for role_index, role in enumerate(play.get("roles", []) or []):
                role_name = role if isinstance(role, str) else role.get("role", "<unknown>")
                changes.append(
                    {
                        "Module": "include_role",
                        "Args": role,
                        "Name": f"role {role_name}",
                        "Address": f"{play_name}.roles[{role_index}]",
                    }
                )
        return changes

    def _extract_tasks(
        self,
        tasks: Any,
        changes: list[dict[str, Any]],
        *,
        prefix: str,
    ) -> None:
        if not isinstance(tasks, list):
            return
        for index, task in enumerate(tasks):
            if not isinstance(task, dict):
                continue
            address = f"{prefix}[{index}]"
            task_name = str(task.get("name") or address)
            module = _module_and_args(task)
            if module:
                changes.append(
                    {
                        "Module": module[0],
                        "Args": module[1],
                        "Name": task_name,
                        "Address": address,
                    }
                )
            for nested in ("block", "rescue", "always"):
                self._extract_tasks(
                    task.get(nested, []),
                    changes,
                    prefix=f"{address}.{nested}",
                )

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        module = str(raw.get("Module", "unknown"))
        args = raw.get("Args")
        state = str(args.get("state", "")).lower() if isinstance(args, dict) else ""
        risk = "review"
        explanation = (
            f"Ansible module '{module}' changes managed configuration; "
            "review inputs and scope."
        )

        if module in _SAFE_MODULES:
            risk = "safe"
            explanation = f"Ansible module '{module}' is observational or controls playbook flow."
        elif module in _DANGEROUS_MODULES:
            risk = "dangerous"
            explanation = (
                f"Ansible module '{module}' can execute arbitrary or "
                "connectivity-changing operations."
            )
        elif module in {"file", "package", "user"} and state in {"absent", "removed"}:
            risk = "dangerous"
            explanation = f"Ansible module '{module}' removes managed state ({state})."
        elif module in {"service", "systemd"} and state in {"stopped", "restarted"}:
            risk = "dangerous"
            explanation = f"Ansible module '{module}' changes service availability ({state})."
        elif module in {"include_role", "import_role", "include_tasks", "import_tasks"}:
            explanation = (
                f"Ansible '{module}' references tasks not expanded in this artifact. "
                "Review the included content."
            )

        return ResourceChange(
            address=str(raw.get("Address", raw.get("Name", "<unknown>"))),
            resource_type=f"ansible_{module}",
            actions=("execute",),
            risk=risk,
            explanation=explanation,
        )


def analyze_ansible(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = AnsibleAdapter().analyze(data, tool_name="Ansible")
    summary = PlanSummary(
        path=Path("ansible://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    return agent_gate_to_dict(summary, catalog=catalog, tool_name="Ansible")
