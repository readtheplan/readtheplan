from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_LINES = 100_000
_MAX_YAML_NODES = 100_000
_MAX_NESTING_DEPTH = 100
_MAX_DOCUMENTS = 100
_MAX_TASKS = 5_000

_TASK_METADATA = {
    "always",
    "any_errors_fatal",
    "args",
    "async",
    "action",
    "become",
    "become_exe",
    "become_flags",
    "become_method",
    "become_user",
    "block",
    "changed_when",
    "check_mode",
    "collections",
    "connection",
    "debugger",
    "delay",
    "delegate_facts",
    "delegate_to",
    "diff",
    "environment",
    "failed_when",
    "ignore_errors",
    "ignore_unreachable",
    "loop",
    "loop_control",
    "local_action",
    "module_defaults",
    "name",
    "no_log",
    "notify",
    "poll",
    "port",
    "register",
    "remote_user",
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
    "listen",
}

_SAFE_MODULES = {"assert", "debug", "fail", "set_fact", "stat"}
_DANGEROUS_MODULES = {
    "command",
    "expect",
    "firewalld",
    "iptables",
    "nftables",
    "raw",
    "reboot",
    "script",
    "shell",
    "ufw",
    "win_command",
    "win_powershell",
    "win_reboot",
    "win_shell",
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
    "apk",
    "apt",
    "dnf",
    "dnf5",
    "gem",
    "get_url",
    "git",
    "npm",
    "pacman",
    "package",
    "pip",
    "rpm_key",
    "unarchive",
    "uri",
    "yum",
    "yum_repository",
    "zypper",
}
_INCLUDE_MODULES = {"include_role", "import_role", "include_tasks", "import_tasks"}
_LOCAL_CONTENT_MODULES = {"assemble", "blockinfile", "copy", "lineinfile", "replace", "template"}
_FILE_MUTATION_MODULES = _LOCAL_CONTENT_MODULES | {"file", "win_copy", "win_file", "win_template"}
_SENSITIVE_TOKENS = ("password", "passwd", "secret", "token", "private_key", "api_key")
_DYNAMIC_MARKERS = ("{{", "{%", "{#", "lookup(", "query(")
_ROLE_CONTENT_RE = re.compile(r"(?:^|/)roles/[^/]+/(tasks|handlers)/.+[.]ya?ml$")
_SENSITIVE_PATH_PREFIXES = (
    "/boot",
    "/etc/cron",
    "/etc/pam",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/systemd",
    "/root/.ssh",
    "/usr/lib/systemd",
    "/var/spool/cron",
    "c:\\windows\\system32\\drivers\\etc",
)


class AnsibleInputError(ValueError):
    """Raised when Ansible YAML is unsafe, malformed, or structurally ambiguous."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError as exc:
            raise AnsibleInputError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise AnsibleInputError("duplicate YAML key")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _validate_source_limits(source: str) -> None:
    if "\x00" in source:
        raise AnsibleInputError("input contains a NUL byte")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise AnsibleInputError("source size limit exceeded")
    if source.count("\n") + 1 > _MAX_SOURCE_LINES:
        raise AnsibleInputError("source line limit exceeded")


def _validate_yaml_events(source: str) -> None:
    nodes = 0
    depth = 0
    documents = 0
    try:
        for event in yaml.parse(source, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.events.DocumentStartEvent):
                documents += 1
                if documents > _MAX_DOCUMENTS:
                    raise AnsibleInputError("YAML document count limit exceeded")
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                nodes += 1
                depth += 1
                if depth > _MAX_NESTING_DEPTH:
                    raise AnsibleInputError("nesting depth limit exceeded")
            elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
            elif isinstance(event, (yaml.events.ScalarEvent, yaml.events.AliasEvent)):
                nodes += 1
            if nodes > _MAX_YAML_NODES:
                raise AnsibleInputError("YAML node count limit exceeded")
    except AnsibleInputError:
        raise
    except (yaml.YAMLError, RecursionError) as exc:
        raise AnsibleInputError("invalid YAML syntax") from exc


def _validate_object_graph(value: Any) -> None:
    visits = 0

    def walk(item: Any, depth: int, active: set[int]) -> None:
        nonlocal visits
        visits += 1
        if visits > _MAX_YAML_NODES:
            raise AnsibleInputError("YAML node count limit exceeded")
        if depth > _MAX_NESTING_DEPTH:
            raise AnsibleInputError("nesting depth limit exceeded")
        if not isinstance(item, (dict, list)):
            return
        marker = id(item)
        if marker in active:
            raise AnsibleInputError("input contains a recursive YAML alias")
        active.add(marker)
        try:
            if isinstance(item, dict):
                if not all(isinstance(key, str) for key in item):
                    raise AnsibleInputError("YAML mapping keys must be strings")
                for key, child in item.items():
                    walk(key, depth + 1, active)
                    walk(child, depth + 1, active)
            else:
                for child in item:
                    walk(child, depth + 1, active)
        finally:
            active.remove(marker)

    walk(value, 0, set())


def _role_content_kind(filename: str | None) -> str | None:
    if not filename:
        return None
    normalized = filename.replace("\\", "/").casefold().lstrip("./")
    match = _ROLE_CONTENT_RE.search(normalized)
    if not match:
        return None
    return "handler_file" if match.group(1) == "handlers" else "task_file"


def _task_action_keys(task: dict[str, Any]) -> list[str]:
    return [key for key in task if key not in _TASK_METADATA and not key.startswith("with_")]


def _validate_task_list(tasks: Any, *, label: str, counter: list[int]) -> None:
    if not isinstance(tasks, list):
        raise AnsibleInputError(f"{label} must be a YAML list")
    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            raise AnsibleInputError(f"{label}[{index}] must be a mapping")
        counter[0] += 1
        if counter[0] > _MAX_TASKS:
            raise AnsibleInputError("task count limit exceeded")
        action_keys = _task_action_keys(task)
        special_actions = [key for key in ("action", "local_action") if key in task]
        if len(action_keys) + len(special_actions) > 1:
            raise AnsibleInputError(f"{label}[{index}] defines multiple task actions")
        for key in special_actions:
            action = task[key]
            valid = isinstance(action, str) and bool(action.strip())
            valid = valid or (
                isinstance(action, dict)
                and isinstance(action.get("module"), str)
                and bool(action["module"].strip())
            )
            if not valid:
                raise AnsibleInputError(f"{label}[{index}].{key} must name a module")
        nested = [key for key in ("block", "rescue", "always") if key in task]
        if (action_keys or special_actions) and "block" in task:
            raise AnsibleInputError(f"{label}[{index}] defines both an action and a block")
        if not action_keys and not special_actions and "block" not in task:
            raise AnsibleInputError(f"{label}[{index}] does not define a task action or block")
        for key in nested:
            _validate_task_list(
                task[key],
                label=f"{label}[{index}].{key}",
                counter=counter,
            )


def _looks_like_play(item: Any) -> bool:
    return isinstance(item, dict) and any(
        key in item
        for key in ("hosts", "roles", "tasks", "pre_tasks", "post_tasks", "import_playbook")
    )


def _validate_plays(plays: list[Any]) -> None:
    task_counter = [0]
    for index, play in enumerate(plays):
        if not isinstance(play, dict):
            raise AnsibleInputError(f"playbook[{index}] must be a mapping")
        if "import_playbook" in play:
            if not isinstance(play["import_playbook"], str) or not play["import_playbook"].strip():
                raise AnsibleInputError(f"playbook[{index}].import_playbook must be a string")
            continue
        if not _looks_like_play(play):
            raise AnsibleInputError(f"playbook[{index}] is not a recognizable Ansible play")
        if "hosts" not in play:
            raise AnsibleInputError(f"playbook[{index}] is missing hosts")
        for section in ("pre_tasks", "tasks", "post_tasks", "handlers"):
            if section in play:
                _validate_task_list(
                    play[section],
                    label=f"playbook[{index}].{section}",
                    counter=task_counter,
                )
        if "roles" in play and not isinstance(play["roles"], list):
            raise AnsibleInputError(f"playbook[{index}].roles must be a list")


def _count_tasks(tasks: Any) -> int:
    if not isinstance(tasks, list):
        return 0
    return sum(
        1 + sum(_count_tasks(task.get(key)) for key in ("block", "rescue", "always"))
        for task in tasks
        if isinstance(task, dict)
    )


def _iter_tasks(tasks: Any):
    if not isinstance(tasks, list):
        return
    for task in tasks:
        if not isinstance(task, dict):
            continue
        yield task
        for key in ("block", "rescue", "always"):
            yield from _iter_tasks(task.get(key))


def _contains_dynamic_value(value: Any, memo: dict[int, bool] | None = None) -> bool:
    memo = {} if memo is None else memo
    if isinstance(value, str):
        lowered = value.casefold()
        return any(marker in lowered for marker in _DYNAMIC_MARKERS)
    if isinstance(value, dict):
        marker = id(value)
        if marker in memo:
            return memo[marker]
        memo[marker] = False
        result = any(
            _contains_dynamic_value(key, memo) or _contains_dynamic_value(item, memo)
            for key, item in value.items()
        )
        memo[marker] = result
        return result
    if isinstance(value, list):
        marker = id(value)
        if marker in memo:
            return memo[marker]
        memo[marker] = False
        result = any(_contains_dynamic_value(item, memo) for item in value)
        memo[marker] = result
        return result
    return False


def _task_is_dynamic(task: dict[str, Any], memo: dict[int, bool]) -> bool:
    if any(key in task for key in ("when", "changed_when", "failed_when", "until", "loop")):
        return True
    if any(key.startswith("with_") for key in task):
        return True
    return any(
        _contains_dynamic_value(key, memo) or _contains_dynamic_value(value, memo)
        for key, value in task.items()
        if key not in {"block", "rescue", "always"}
    )


def _task_metadata(artifact_type: str, items: list[Any]) -> dict[str, int | str]:
    dynamic_memo: dict[int, bool] = {}
    if artifact_type == "playbook":
        task_count = 0
        handler_count = 0
        dynamic_count = 0
        for play in items:
            if not isinstance(play, dict):
                continue
            for section in ("pre_tasks", "tasks", "post_tasks"):
                task_count += _count_tasks(play.get(section))
            handler_count += _count_tasks(play.get("handlers"))
            dynamic_count += sum(
                1
                for section in ("pre_tasks", "tasks", "post_tasks", "handlers")
                for task in _iter_tasks(play.get(section))
                if _task_is_dynamic(task, dynamic_memo)
            )
        return {
            "artifact_type": artifact_type,
            "task_count": task_count,
            "handler_count": handler_count,
            "dynamic_count": dynamic_count,
        }
    count = _count_tasks(items)
    return {
        "artifact_type": artifact_type,
        "task_count": 0 if artifact_type == "handler_file" else count,
        "handler_count": count if artifact_type == "handler_file" else 0,
        "dynamic_count": sum(
            1 for task in _iter_tasks(items) if _task_is_dynamic(task, dynamic_memo)
        ),
    }


def parse_ansible(source: str, filename: str | None = None) -> dict[str, Any]:
    """Parse an Ansible playbook, reusable task file, or role handler file safely."""
    _validate_source_limits(source)
    _validate_yaml_events(source)
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))
    except AnsibleInputError:
        raise
    except (yaml.YAMLError, RecursionError) as exc:
        raise AnsibleInputError("invalid YAML syntax") from exc
    if not documents or all(document is None for document in documents):
        raise AnsibleInputError("input is empty")
    for document in documents:
        _validate_object_graph(document)

    context_kind = _role_content_kind(filename)
    if context_kind:
        if len(documents) != 1 or not isinstance(documents[0], list):
            raise AnsibleInputError("role task and handler files must contain one YAML task list")
        if any(_looks_like_play(item) for item in documents[0]):
            raise AnsibleInputError("role task and handler files cannot contain plays")
        counter = [0]
        _validate_task_list(documents[0], label=context_kind, counter=counter)
        return {
            "ansible_tasks": documents[0],
            "ansible_artifact_type": context_kind,
            "ansible_metadata": _task_metadata(context_kind, documents[0]),
        }

    plays: list[Any] = []
    for document in documents:
        if isinstance(document, list) and all(_looks_like_play(item) for item in document):
            plays.extend(document)
        elif isinstance(document, dict) and _looks_like_play(document):
            plays.append(document)
        else:
            plays = []
            break
    if plays:
        _validate_plays(plays)
        return {
            "plays": plays,
            "ansible_artifact_type": "playbook",
            "ansible_metadata": _task_metadata("playbook", plays),
        }

    if len(documents) == 1 and isinstance(documents[0], list):
        counter = [0]
        _validate_task_list(documents[0], label="task_file", counter=counter)
        return {
            "ansible_tasks": documents[0],
            "ansible_artifact_type": "task_file",
            "ansible_metadata": _task_metadata("task_file", documents[0]),
        }
    raise AnsibleInputError("input is not an Ansible playbook or reusable task list")


def _short_module_name(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower()


def _combined_task_args(task: dict[str, Any], module_args: Any) -> Any:
    common_args = task.get("args")
    if not isinstance(common_args, dict):
        return module_args
    if isinstance(module_args, dict):
        return {**common_args, **module_args}
    if module_args is None or module_args == "":
        return dict(common_args)
    return {"_raw_params": module_args, **common_args}


def _module_and_args(task: dict[str, Any]) -> tuple[str, Any, str] | None:
    for action_key in ("action", "local_action"):
        action = task.get(action_key)
        if isinstance(action, str) and action.strip():
            module, _, arguments = action.strip().partition(" ")
            return _short_module_name(module), _combined_task_args(task, arguments), module
        if isinstance(action, dict):
            module = action.get("module")
            if isinstance(module, str) and module.strip():
                arguments = {key: value for key, value in action.items() if key != "module"}
                return _short_module_name(module), _combined_task_args(task, arguments), module
    for key, value in task.items():
        if key not in _TASK_METADATA and not key.startswith("with_"):
            return _short_module_name(key), _combined_task_args(task, value), key
    return None


def _contains_sensitive_value(value: Any, memo: dict[int, bool] | None = None) -> bool:
    memo = {} if memo is None else memo
    if isinstance(value, str):
        lowered = value.casefold()
        return any(token in lowered for token in _SENSITIVE_TOKENS)
    if isinstance(value, dict):
        marker = id(value)
        if marker in memo:
            return memo[marker]
        memo[marker] = False
        result = any(
            any(token in str(key).lower() for token in _SENSITIVE_TOKENS)
            or _contains_sensitive_value(item, memo)
            for key, item in value.items()
        )
        memo[marker] = result
        return result
    if isinstance(value, list):
        marker = id(value)
        if marker in memo:
            return memo[marker]
        memo[marker] = False
        result = any(_contains_sensitive_value(item, memo) for item in value)
        memo[marker] = result
        return result
    return False


def _disabled_tls_validation(value: Any, memo: dict[int, bool] | None = None) -> bool:
    memo = {} if memo is None else memo
    if isinstance(value, list):
        marker = id(value)
        if marker in memo:
            return memo[marker]
        memo[marker] = False
        result = any(_disabled_tls_validation(item, memo) for item in value)
        memo[marker] = result
        return result
    if not isinstance(value, dict):
        return False
    marker = id(value)
    if marker in memo:
        return memo[marker]
    memo[marker] = False
    for key, item in value.items():
        if str(key).lower() in {"validate_certs", "verify_ssl"} and item is False:
            memo[marker] = True
            return True
        if _disabled_tls_validation(item, memo):
            memo[marker] = True
            return True
    return False


def _sensitive_destination(args: Any) -> bool:
    if not isinstance(args, dict):
        return False
    for key in ("dest", "destination", "name", "path"):
        value = args.get(key)
        if not isinstance(value, str):
            continue
        normalized = value.strip().replace("/", "\\").casefold()
        unix_normalized = value.strip().replace("\\", "/").casefold()
        if any(
            unix_normalized == prefix or unix_normalized.startswith(f"{prefix}/")
            for prefix in _SENSITIVE_PATH_PREFIXES
            if prefix.startswith("/")
        ):
            return True
        if normalized.startswith("c:\\windows\\system32\\drivers\\etc"):
            return True
    return False


def _world_writable_mode(args: Any) -> bool:
    if not isinstance(args, dict):
        return False
    mode = args.get("mode")
    if isinstance(mode, int):
        digits = f"{mode:o}"
    elif isinstance(mode, str):
        digits = mode.strip().lower().removeprefix("0o")
        if "a+w" in digits or "o+w" in digits:
            return True
    else:
        return False
    return len(digits) >= 3 and digits[-1] in {"2", "3", "6", "7"}


class AnsibleAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "ansible"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        artifact_type = input_data.get("ansible_artifact_type")
        tasks = input_data.get("ansible_tasks")
        if artifact_type in {"task_file", "handler_file"}:
            return isinstance(tasks, list) and bool(tasks)
        plays = input_data.get("plays")
        return isinstance(plays, list) and any(
            isinstance(play, dict)
            and any(key in play for key in ("tasks", "roles", "hosts", "import_playbook"))
            for play in plays
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        dynamic_memo: dict[int, bool] = {}
        artifact_type = str(input_data.get("ansible_artifact_type") or "playbook")
        if artifact_type in {"task_file", "handler_file"}:
            changes.append(
                {
                    "Module": f"{artifact_type}_boundary",
                    "Args": {},
                    "Name": artifact_type,
                    "Address": artifact_type,
                    "TaskMeta": {},
                }
            )
            self._extract_tasks(
                input_data.get("ansible_tasks", []),
                changes,
                prefix=(
                    "handler-file.handlers"
                    if artifact_type == "handler_file"
                    else "task-file.tasks"
                ),
                is_handler=artifact_type == "handler_file",
                dynamic_memo=dynamic_memo,
            )
            return changes
        for play_index, play in enumerate(input_data.get("plays", [])):
            if not isinstance(play, dict):
                continue
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
                        "Name": f"play-{play_index + 1}",
                        "Address": f"playbook[{play_index}]",
                        "TaskMeta": play_controls,
                    }
                )
            for section in ("pre_tasks", "tasks", "post_tasks", "handlers"):
                self._extract_tasks(
                    play.get(section, []),
                    changes,
                    prefix=f"playbook[{play_index}].{section}",
                    is_handler=section == "handlers",
                    dynamic_memo=dynamic_memo,
                )
            for role_index, role in enumerate(play.get("roles", []) or []):
                role_name = role if isinstance(role, str) else "<role>"
                changes.append(
                    {
                        "Module": "include_role",
                        "Args": role,
                        "Name": f"role {role_name}",
                        "Address": f"playbook[{play_index}].roles[{role_index}]",
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
        is_handler: bool = False,
        dynamic_memo: dict[int, bool] | None = None,
    ) -> None:
        dynamic_memo = {} if dynamic_memo is None else dynamic_memo
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
                        "ModuleRef": module[2],
                        "Name": task_name,
                        "Address": address,
                        "TaskMeta": {
                            key: task[key]
                            for key in _TASK_METADATA | {"local_action"}
                            if key in task
                        },
                        "IsHandler": is_handler,
                        "HasDynamicValues": _task_is_dynamic(task, dynamic_memo),
                        "HasLookupLoop": any(key.startswith("with_") for key in task),
                    }
                )
            for nested in ("block", "rescue", "always"):
                self._extract_tasks(
                    task.get(nested, []),
                    changes,
                    prefix=f"{address}.{nested}",
                    is_handler=is_handler,
                    dynamic_memo=dynamic_memo,
                )

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        module = str(raw.get("Module", "unknown"))
        args = raw.get("Args")
        module_ref = str(raw.get("ModuleRef") or module)
        metadata = raw.get("TaskMeta")
        metadata = metadata if isinstance(metadata, dict) else {}
        state = str(args.get("state", "")).lower() if isinstance(args, dict) else ""
        risk = "review"
        explanation = (
            f"Ansible module '{module}' changes managed configuration; review inputs and scope."
        )

        if module == "task_file_boundary":
            explanation = (
                "This reusable Ansible task file is analyzed without its importing play or role; "
                "target hosts, inherited variables and tags, privilege, collection search paths, "
                "and runtime include conditions remain caller-controlled review boundaries."
            )
        elif module == "handler_file_boundary":
            explanation = (
                "This Ansible handler file is imported into a play-wide handler namespace; "
                "notification routing, name collisions, insertion order, caller privilege and "
                "targets, and runtime variables remain review boundaries."
            )
        elif module == "play":
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
        elif module == "meta":
            explanation = (
                "Ansible 'meta' changes play execution flow, handler timing, inventory, facts, "
                "or connection state; review the selected operation and caller context."
            )
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
        elif module in _FILE_MUTATION_MODULES and _sensitive_destination(args):
            risk = "dangerous"
            explanation = (
                f"Ansible module '{module}' mutates a host security, identity, boot, scheduler, "
                "or service-manager path."
            )
        elif module in _FILE_MUTATION_MODULES and _world_writable_mode(args):
            risk = "dangerous"
            explanation = f"Ansible module '{module}' creates a world-writable filesystem object."
        elif module in {"service", "systemd"} and state in {"stopped", "restarted"}:
            risk = "dangerous"
            explanation = f"Ansible module '{module}' changes service availability ({state})."
        elif module in _IDENTITY_MODULES:
            risk = "dangerous"
            explanation = (
                f"Ansible module '{module}' changes identity, privilege, kernel, mount, "
                "or host security state."
            )
        elif (
            module == "uri"
            and isinstance(args, dict)
            and str(args.get("method", "GET")).upper() in {"DELETE", "PATCH", "POST", "PUT"}
        ):
            risk = "dangerous"
            explanation = (
                "Ansible module 'uri' performs a potentially mutating remote API request; "
                "review destination trust, authentication, payload, and rollback."
            )
        elif module in _SUPPLY_CHAIN_MODULES:
            explanation = (
                f"Ansible module '{module}' installs or retrieves external content; "
                "review source trust, pinning, checksums, TLS, and execution effects."
            )
            if _disabled_tls_validation(args):
                risk = "dangerous"
                explanation += " TLS certificate validation is disabled."
        elif module in _LOCAL_CONTENT_MODULES:
            explanation = (
                f"Ansible module '{module}' mutates managed files using content whose role-local "
                "source, template rendering, variables, and target state are not expanded here."
            )
        elif module == "include_vars":
            explanation = (
                "Ansible 'include_vars' loads external variable data whose contents, precedence, "
                "and Vault decryption are not expanded from this file."
            )
        elif module in _INCLUDE_MODULES | {"import_playbook"}:
            reuse_mode = (
                "dynamically loads" if module.startswith("include_") else "statically imports"
            )
            explanation = (
                f"Ansible '{module}' {reuse_mode} external automation content that is not "
                "expanded from this file. Review the referenced content and inherited controls."
            )

        control_findings: list[str] = []
        if metadata.get("become") is True and module != "play":
            control_findings.append("runs with privilege escalation")
            risk = "dangerous"
        if str(metadata.get("become_user") or "").casefold() in {
            "root",
            "administrator",
            "system",
        }:
            control_findings.append("selects a privileged become identity")
            if metadata.get("become") is True:
                risk = "dangerous"
        if str(metadata.get("remote_user") or "").casefold() in {
            "root",
            "administrator",
            "system",
        }:
            control_findings.append("connects directly as a privileged identity")
            risk = "dangerous"
        delegate = str(metadata.get("delegate_to") or "").casefold()
        if delegate in {"localhost", "127.0.0.1", "::1"} or "local_action" in metadata:
            control_findings.append("executes on the controller host")
            risk = "dangerous"
        elif metadata.get("delegate_to"):
            control_findings.append("changes the execution target through delegation")
            if risk == "safe":
                risk = "review"
        if str(metadata.get("connection") or "").casefold() == "local":
            control_findings.append("selects the local connection plugin")
            risk = "dangerous"
        if metadata.get("check_mode") is False:
            control_findings.append("forces execution even during check mode")
            risk = "dangerous"
        if metadata.get("ignore_errors") is True or metadata.get("ignore_unreachable") is True:
            control_findings.append("continues after execution failures")
            if risk == "safe":
                risk = "review"
        if metadata.get("run_once") is True:
            control_findings.append("runs once despite a potentially broad host target")
        if metadata.get("notify"):
            control_findings.append("can enqueue one or more globally scoped handlers after change")
            if risk == "safe":
                risk = "review"
        if metadata.get("listen"):
            control_findings.append("subscribes this handler to a play-wide notification topic")
            if risk == "safe":
                risk = "review"
        if metadata.get("changed_when") is not None:
            control_findings.append("overrides change detection and can alter handler execution")
            if risk == "safe":
                risk = "review"
        if metadata.get("failed_when") is not None:
            control_findings.append("overrides task failure detection")
            if risk == "safe":
                risk = "review"
        if metadata.get("any_errors_fatal") is True:
            control_findings.append("propagates an unhandled failure across all targeted hosts")
            if risk == "safe":
                risk = "review"
        async_value = metadata.get("async")
        if async_value is not None and str(async_value) != "0":
            control_findings.append("runs asynchronously beyond normal task sequencing")
            if risk == "safe":
                risk = "review"
        if metadata.get("until") is not None or metadata.get("retries") is not None:
            control_findings.append("can repeat the action until a runtime condition is met")
            if risk == "safe":
                risk = "review"
        if metadata.get("diff") is False:
            control_findings.append("suppresses diff evidence for this task")
            if risk == "safe":
                risk = "review"
        if metadata.get("no_log") is True:
            control_findings.append("suppresses task output and audit evidence")
            if risk == "safe":
                risk = "review"
        if metadata.get("module_defaults"):
            control_findings.append("inherits module arguments that are not visible on this task")
            if risk == "safe":
                risk = "review"
        if raw.get("HasDynamicValues"):
            control_findings.append(
                "depends on Jinja or lookup expressions resolved only at runtime"
            )
            if risk == "safe":
                risk = "review"
        if raw.get("IsHandler"):
            control_findings.append(
                "is a handler whose execution depends on play-wide notification and failure flow"
            )
            if risk == "safe":
                risk = "review"
        if raw.get("HasLookupLoop"):
            control_findings.append("invokes a lookup plugin to produce loop inputs")
            if risk == "safe":
                risk = "review"
        if "." not in module_ref and module not in {
            "play",
            "task_file_boundary",
            "handler_file_boundary",
        }:
            control_findings.append(
                "uses an unqualified action name whose implementation can be overridden by role, "
                "collection, or configured plugin search paths"
            )
        if (
            _contains_sensitive_value(metadata.get("environment"))
            and metadata.get("no_log") is not True
        ):
            control_findings.append("provides credential-like environment values without no_log")
            risk = "dangerous"
        if _contains_sensitive_value(metadata.get("vars")) and metadata.get("no_log") is not True:
            control_findings.append("defines credential-like task variables without no_log")
            risk = "dangerous"
        if (
            module not in {"play", "task_file_boundary", "handler_file_boundary"}
            and _contains_sensitive_value(args)
            and metadata.get("no_log") is not True
        ):
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
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Ansible")
    gate["adapter"] = "ansible"
    gate["total_changes"] = len(changes)
    metadata = data.get("ansible_metadata")
    if not isinstance(metadata, dict):
        artifact_type = str(data.get("ansible_artifact_type") or "playbook")
        items = data.get("plays") if artifact_type == "playbook" else data.get("ansible_tasks")
        metadata = _task_metadata(artifact_type, items if isinstance(items, list) else [])
    for key in ("artifact_type", "task_count", "handler_count", "dynamic_count"):
        if isinstance(metadata.get(key), (str, int)):
            gate[key] = metadata[key]
    return gate
