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
_IDENTITY_MODULES = {
    "authorized_key",
    "group",
    "mount",
    "pam_limits",
    "selinux",
    "seboolean",
    "sudoers",
    "sysctl",
    "user",
}
_SUPPLY_CHAIN_MODULES = {
    "apt_key",
    "apt_repository",
    "dnf",
    "dnf5",
    "gem",
    "get_url",
    "git",
    "npm",
    "package",
    "pip",
    "rpm_key",
    "unarchive",
    "uri",
    "yum",
    "yum_repository",
}
_INCLUDE_MODULES = {"include_role", "import_role", "include_tasks", "import_tasks"}
_SENSITIVE_TOKENS = ("password", "passwd", "secret", "token", "private_key", "api_key")


def _short_module_name(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower()


def _module_and_args(task: dict[str, Any]) -> tuple[str, Any] | None:
    for action_key in ("action", "local_action"):
        action = task.get(action_key)
        if isinstance(action, str) and action.strip():
            module, _, arguments = action.strip().partition(" ")
            return _short_module_name(module), arguments
        if isinstance(action, dict):
            module = action.get("module")
            if isinstance(module, str) and module.strip():
                arguments = {key: value for key, value in action.items() if key != "module"}
                return _short_module_name(module), arguments
    for key, value in task.items():
        if key not in _TASK_METADATA and not key.startswith("with_"):
            return _short_module_name(key), value
    return None


def _contains_sensitive_value(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            any(token in str(key).lower() for token in _SENSITIVE_TOKENS)
            or _contains_sensitive_value(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_value(item) for item in value)
    return False


def _disabled_tls_validation(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    for key, item in value.items():
        if str(key).lower() in {"validate_certs", "verify_ssl"} and item is False:
            return True
        if _disabled_tls_validation(item):
            return True
    return False


class AnsibleAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "ansible"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        plays = input_data.get("plays")
        return isinstance(plays, list) and any(
            isinstance(play, dict)
            and any(key in play for key in ("tasks", "roles", "hosts", "import_playbook"))
            for play in plays
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for play_index, play in enumerate(input_data.get("plays", [])):
            if not isinstance(play, dict):
                continue
            play_name = str(play.get("name") or play.get("hosts") or f"play-{play_index + 1}")
            if "import_playbook" in play:
                changes.append(
                    {
                        "Module": "import_playbook",
                        "Args": play.get("import_playbook"),
                        "Name": f"import {play.get('import_playbook')}",
                        "Address": f"playbook[{play_index}]",
                        "TaskMeta": {},
                    }
                )
                continue
            play_controls = {
                key: play[key]
                for key in (
                    "hosts",
                    "become",
                    "become_user",
                    "connection",
                    "remote_user",
                    "serial",
                    "strategy",
                    "vars_files",
                    "module_defaults",
                )
                if key in play
            }
            if set(play_controls) - {"hosts"}:
                changes.append(
                    {
                        "Module": "play",
                        "Args": play_controls,
                        "Name": play_name,
                        "Address": f"playbook[{play_index}]",
                        "TaskMeta": play_controls,
                    }
                )
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
                        "TaskMeta": role if isinstance(role, dict) else {},
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
                        "TaskMeta": {
                            key: task[key]
                            for key in _TASK_METADATA | {"local_action"}
                            if key in task
                        },
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
        metadata = raw.get("TaskMeta")
        metadata = metadata if isinstance(metadata, dict) else {}
        state = str(args.get("state", "")).lower() if isinstance(args, dict) else ""
        risk = "review"
        explanation = (
            f"Ansible module '{module}' changes managed configuration; review inputs and scope."
        )

        if module == "play":
            findings = ["defines the target and execution policy for a play"]
            hosts = str(args.get("hosts", "")) if isinstance(args, dict) else ""
            if hosts in {"all", "*"}:
                findings.append("targets every inventory host")
            if metadata.get("become") is True:
                findings.append("enables privilege escalation")
                risk = "dangerous"
            if metadata.get("connection") == "local":
                findings.append("executes against the controller host")
                risk = "dangerous"
            if metadata.get("strategy") == "free":
                findings.append("allows hosts to advance independently")
            if metadata.get("vars_files"):
                findings.append("loads variables from external files")
            explanation = f"This Ansible play {'; '.join(findings)}. Review scope and controls."
        elif module in _SAFE_MODULES:
            risk = "safe"
            explanation = f"Ansible module '{module}' is observational or controls playbook flow."
        elif module in _DANGEROUS_MODULES:
            risk = "dangerous"
            explanation = (
                f"Ansible module '{module}' can execute arbitrary or "
                "connectivity-changing operations."
            )
        elif module in {"file", "package", "user", "group"} and state in {
            "absent",
            "removed",
            "purged",
        }:
            risk = "dangerous"
            explanation = f"Ansible module '{module}' removes managed state ({state})."
        elif module in {"service", "systemd"} and state in {"stopped", "restarted"}:
            risk = "dangerous"
            explanation = f"Ansible module '{module}' changes service availability ({state})."
        elif module in _IDENTITY_MODULES:
            risk = "dangerous"
            explanation = (
                f"Ansible module '{module}' changes identity, privilege, kernel, mount, "
                "or host security state."
            )
        elif module in _SUPPLY_CHAIN_MODULES:
            explanation = (
                f"Ansible module '{module}' installs or retrieves external content; "
                "review source trust, pinning, checksums, TLS, and execution effects."
            )
            if _disabled_tls_validation(args):
                risk = "dangerous"
                explanation += " TLS certificate validation is disabled."
        elif module in _INCLUDE_MODULES | {"import_playbook"}:
            explanation = (
                f"Ansible '{module}' references tasks not expanded in this artifact. "
                "Review the included content."
            )

        control_findings: list[str] = []
        if metadata.get("become") is True and module != "play":
            control_findings.append("runs with privilege escalation")
            risk = "dangerous"
        if metadata.get("delegate_to") in {"localhost", "127.0.0.1"} or "local_action" in metadata:
            control_findings.append("executes on the controller host")
            risk = "dangerous"
        if metadata.get("check_mode") is False:
            control_findings.append("forces execution even during check mode")
            risk = "dangerous"
        if metadata.get("ignore_errors") is True or metadata.get("ignore_unreachable") is True:
            control_findings.append("continues after execution failures")
        if metadata.get("run_once") is True:
            control_findings.append("runs once despite a potentially broad host target")
        if (
            _contains_sensitive_value(metadata.get("environment"))
            and metadata.get("no_log") is not True
        ):
            control_findings.append("provides credential-like environment values without no_log")
            risk = "dangerous"
        if _contains_sensitive_value(args) and metadata.get("no_log") is not True:
            control_findings.append("uses credential-like module inputs without no_log")
            risk = "dangerous"
        if control_findings:
            explanation += f" Task controls also {'; '.join(control_findings)}."

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
