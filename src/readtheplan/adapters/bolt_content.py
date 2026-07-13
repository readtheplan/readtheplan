from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import Any

import yaml


class BoltContentInputError(ValueError):
    """Raised when Bolt task metadata or YAML plan input is unsafe or malformed."""


_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_LINES = 100_000
_MAX_NODES = 100_000
_MAX_DEPTH = 100
_MAX_STEPS = 2_000
_MAX_PARAMETERS = 2_000
_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|client.?secret|api.?key|credential)",
    re.IGNORECASE,
)
_UNCONSTRAINED_TYPE = re.compile(r"^(?:Optional\[)?String(?:\[[^]]+\])?\]?$", re.IGNORECASE)
_INJECTION_PARAMETER = re.compile(
    r"(?:command|script|argument|option|mode|path|file|directory|destination|source|query|url)",
    re.IGNORECASE,
)
_DYNAMIC = re.compile(r"(?:\$\{|\$[a-z_]|\{\{|<%|\b(?:file|system|puppetdb)::)", re.IGNORECASE)
_PRIVILEGED = re.compile(r"^(?:root|administrator|system|nt authority\\system)$", re.IGNORECASE)
_TASK_TOP_KEYS = {
    "description",
    "files",
    "implementations",
    "input_method",
    "name",
    "parameters",
    "private",
    "puppet_task_version",
    "remote",
    "supports_noop",
}
_TASK_PARAMETER_KEYS = {"default", "description", "sensitive", "type"}
_TASK_IMPLEMENTATION_KEYS = {"files", "name", "requirements"}
_PLAN_TOP_KEYS = {"description", "parameters", "private", "return", "steps"}
_PLAN_PARAMETER_KEYS = {"default", "description", "type"}
_STEP_ACTIONS = {
    "command",
    "download",
    "eval",
    "message",
    "plan",
    "resources",
    "script",
    "task",
    "upload",
    "verbose",
}
_COMMON_STEP_KEYS = {"description", "name"}
_STEP_KEYS = {
    "command": _COMMON_STEP_KEYS | {"catch_errors", "command", "env_vars", "run_as", "targets"},
    "task": _COMMON_STEP_KEYS | {"catch_errors", "noop", "parameters", "run_as", "targets", "task"},
    "script": _COMMON_STEP_KEYS
    | {
        "arguments",
        "catch_errors",
        "env_vars",
        "pwsh_params",
        "run_as",
        "script",
        "targets",
    },
    "download": _COMMON_STEP_KEYS
    | {"catch_errors", "destination", "download", "run_as", "targets"},
    "upload": _COMMON_STEP_KEYS | {"catch_errors", "destination", "run_as", "targets", "upload"},
    "plan": _COMMON_STEP_KEYS | {"catch_errors", "parameters", "plan", "run_as", "targets"},
    "resources": _COMMON_STEP_KEYS | {"catch_errors", "noop", "resources", "run_as", "targets"},
    "eval": {"eval", "name"},
    "message": {"message"},
    "verbose": {"verbose"},
}
_REQUIRED_STEP_KEYS = {
    "command": {"command", "targets"},
    "task": {"task", "targets"},
    "script": {"script", "targets"},
    "download": {"destination", "download", "targets"},
    "upload": {"destination", "targets", "upload"},
    "plan": {"plan"},
    "resources": {"resources", "targets"},
    "eval": {"eval"},
    "message": {"message"},
    "verbose": {"verbose"},
}
_COMMAND_PATTERNS = {
    "destructive": re.compile(
        r"(?:^|\s)(?:rm\s+-[^\n]*r|Remove-Item\b[^\n]*-Recurse|mkfs\b|dd\s+if=|"
        r"shutdown\b|reboot\b|Stop-Computer\b)",
        re.IGNORECASE,
    ),
    "download": re.compile(
        r"(?:^|\s)(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b", re.IGNORECASE
    ),
    "dynamic_execution": re.compile(
        r"(?:^|\s)(?:eval|exec|Invoke-Expression|Start-Process|bash\s+-c|sh\s+-c|"
        r"powershell(?:\.exe)?\s+-(?:e|enc|encodedcommand))\b|\|\s*(?:bash|sh)\b",
        re.IGNORECASE,
    ),
    "privilege": re.compile(r"(?:^|\s)(?:sudo|su|runas)\b", re.IGNORECASE),
    "remote_access": re.compile(r"(?:^|\s)(?:ssh|scp|sftp|winrs)\b", re.IGNORECASE),
    "unsafe_permissions": re.compile(
        r"(?:chmod\s+(?:777|666)\b|icacls\b[^\n]*/grant\s+\*S-1-1-0:F)", re.IGNORECASE
    ),
}
_SENSITIVE_PATH = re.compile(
    r"(?:^|[/\\])(?:etc[/\\](?:shadow|sudoers)|\.ssh|\.gnupg|secrets?|credentials?)(?:[/\\]|$)",
    re.IGNORECASE,
)


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    keys: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in keys
        except TypeError as exc:
            raise BoltContentInputError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise BoltContentInputError(f"duplicate YAML key: {key}")
        keys.add(key)
    loader.flatten_mapping(node)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BoltContentInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _source_checks(source: str, label: str) -> None:
    if not source.strip():
        raise BoltContentInputError(f"{label} input is empty")
    if "\x00" in source:
        raise BoltContentInputError(f"{label} input contains a NUL byte")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise BoltContentInputError(f"{label} input exceeds the 2 MiB source size limit")
    if source.count("\n") + 1 > _MAX_SOURCE_LINES:
        raise BoltContentInputError(f"{label} input exceeds the line count limit")


def _validate_tree(value: Any, label: str) -> None:
    nodes = 0
    active: set[int] = set()

    def visit(current: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_NODES:
            raise BoltContentInputError(f"{label} exceeds the node count limit")
        if depth > _MAX_DEPTH:
            raise BoltContentInputError(f"{label} exceeds the nesting depth limit")
        if not isinstance(current, (dict, list)):
            return
        marker = id(current)
        if marker in active:
            raise BoltContentInputError(f"{label} contains a recursive YAML alias")
        active.add(marker)
        try:
            if isinstance(current, dict):
                for key, child in current.items():
                    if not isinstance(key, str):
                        raise BoltContentInputError(f"{label} mapping keys must be strings")
                    visit(child, depth + 1)
            else:
                for child in current:
                    visit(child, depth + 1)
        finally:
            active.remove(marker)

    visit(value, 0)


def _filename_parts(filename: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in PurePosixPath(filename.replace("\\", "/")).parts)


def is_bolt_yaml_plan(filename: str) -> bool:
    parts = _filename_parts(filename)
    return bool(parts and parts[-1].endswith(".yaml") and "plans" in parts[:-1])


def is_bolt_task_metadata(filename: str) -> bool:
    parts = _filename_parts(filename)
    return bool(parts and parts[-1].endswith(".json") and "tasks" in parts[:-1])


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BoltContentInputError(f"{label} must be a mapping")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise BoltContentInputError(f"{label} must be a string list")
    return value


def parse_bolt_task_metadata(source: str) -> dict[str, Any]:
    label = "Bolt task metadata"
    _source_checks(source, label)
    try:
        document = json.loads(source, object_pairs_hook=_unique_object)
    except BoltContentInputError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise BoltContentInputError(f"invalid Bolt task metadata JSON: {exc}") from exc
    document = _mapping(document, label)
    _validate_tree(document, label)
    unknown = set(document) - _TASK_TOP_KEYS
    if unknown:
        raise BoltContentInputError(
            "unsupported Bolt task metadata key(s): " + ", ".join(sorted(unknown))
        )
    if not (set(document) & (_TASK_TOP_KEYS - {"description", "name"})):
        raise BoltContentInputError("input is not recognized as Bolt task metadata")
    if "puppet_task_version" in document and document["puppet_task_version"] != 1:
        raise BoltContentInputError("Bolt task metadata puppet_task_version must be 1")
    for key in ("private", "remote", "supports_noop"):
        if key in document and not isinstance(document[key], bool):
            raise BoltContentInputError(f"Bolt task metadata {key} must be a boolean")
    if "input_method" in document and document["input_method"] not in {
        "environment",
        "powershell",
        "stdin",
    }:
        raise BoltContentInputError(
            "Bolt task metadata input_method must be environment, powershell, or stdin"
        )
    parameters = document.get("parameters", {})
    parameters = _mapping(parameters, "Bolt task metadata parameters")
    if len(parameters) > _MAX_PARAMETERS:
        raise BoltContentInputError("Bolt task metadata exceeds the parameter count limit")
    for name, definition in parameters.items():
        if not _NAME.fullmatch(name):
            raise BoltContentInputError("Bolt task parameter names must be lowercase identifiers")
        definition = _mapping(definition, f"Bolt task parameter {name}")
        unknown = set(definition) - _TASK_PARAMETER_KEYS
        if unknown:
            raise BoltContentInputError(f"Bolt task parameter {name} contains unsupported fields")
        if "type" in definition and not isinstance(definition["type"], str):
            raise BoltContentInputError(f"Bolt task parameter {name} type must be a string")
        if "sensitive" in definition and not isinstance(definition["sensitive"], bool):
            raise BoltContentInputError(f"Bolt task parameter {name} sensitive must be a boolean")
    if "files" in document:
        _string_list(document["files"], "Bolt task metadata files")
    implementations = document.get("implementations", [])
    if not isinstance(implementations, list):
        raise BoltContentInputError("Bolt task metadata implementations must be a list")
    for index, implementation in enumerate(implementations, start=1):
        implementation = _mapping(implementation, f"Bolt task implementation {index}")
        if set(implementation) - _TASK_IMPLEMENTATION_KEYS:
            raise BoltContentInputError(
                f"Bolt task implementation {index} contains unsupported fields"
            )
        if not isinstance(implementation.get("name"), str) or not implementation["name"].strip():
            raise BoltContentInputError(f"Bolt task implementation {index} requires a name")
        for key in ("files", "requirements"):
            if key in implementation:
                _string_list(implementation[key], f"Bolt task implementation {index} {key}")
    return document


def parse_bolt_yaml_plan(source: str) -> dict[str, Any]:
    label = "Bolt YAML plan"
    _source_checks(source, label)
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except BoltContentInputError:
        raise
    except (yaml.YAMLError, RecursionError) as exc:
        raise BoltContentInputError(f"invalid Bolt YAML plan: {exc}") from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise BoltContentInputError("Bolt YAML plan must contain exactly one mapping")
    document = documents[0]
    _validate_tree(document, label)
    unknown = set(document) - _PLAN_TOP_KEYS
    if unknown:
        raise BoltContentInputError(
            "unsupported Bolt YAML plan key(s): " + ", ".join(sorted(unknown))
        )
    steps = document.get("steps")
    if not isinstance(steps, list) or not steps:
        raise BoltContentInputError("Bolt YAML plan steps must be a non-empty list")
    if len(steps) > _MAX_STEPS:
        raise BoltContentInputError("Bolt YAML plan exceeds the step count limit")
    parameters = document.get("parameters", {})
    parameters = _mapping(parameters, "Bolt YAML plan parameters")
    if len(parameters) > _MAX_PARAMETERS:
        raise BoltContentInputError("Bolt YAML plan exceeds the parameter count limit")
    for name, definition in parameters.items():
        if not _NAME.fullmatch(name):
            raise BoltContentInputError("Bolt plan parameter names must be lowercase identifiers")
        if definition is None:
            continue
        definition = _mapping(definition, f"Bolt plan parameter {name}")
        if set(definition) - _PLAN_PARAMETER_KEYS:
            raise BoltContentInputError(f"Bolt plan parameter {name} contains unsupported fields")
        if "type" in definition and not isinstance(definition["type"], str):
            raise BoltContentInputError(f"Bolt plan parameter {name} type must be a string")
    if "private" in document and not isinstance(document["private"], bool):
        raise BoltContentInputError("Bolt YAML plan private must be a boolean")
    for index, step in enumerate(steps, start=1):
        step = _mapping(step, f"Bolt YAML plan step {index}")
        actions = set(step) & _STEP_ACTIONS
        if len(actions) != 1:
            raise BoltContentInputError(
                f"Bolt YAML plan step {index} must contain exactly one action"
            )
        action = next(iter(actions))
        unknown = set(step) - _STEP_KEYS[action]
        if unknown:
            raise BoltContentInputError(
                f"Bolt YAML plan step {index} contains unsupported {action} fields"
            )
        missing = _REQUIRED_STEP_KEYS[action] - set(step)
        if missing:
            raise BoltContentInputError(
                f"Bolt YAML plan step {index} is missing required {action} fields"
            )
        for key in ("catch_errors", "noop"):
            if key in step and not isinstance(step[key], bool):
                raise BoltContentInputError(f"Bolt YAML plan step {index} {key} must be a boolean")
        for key in ("env_vars", "parameters", "pwsh_params"):
            if key in step and not isinstance(step[key], dict):
                raise BoltContentInputError(f"Bolt YAML plan step {index} {key} must be a mapping")
        if "arguments" in step and not isinstance(step["arguments"], list):
            raise BoltContentInputError(f"Bolt YAML plan step {index} arguments must be a list")
        if "arguments" in step and "pwsh_params" in step:
            raise BoltContentInputError(
                f"Bolt YAML plan step {index} cannot combine arguments and pwsh_params"
            )
        if action == "resources" and not isinstance(step["resources"], list):
            raise BoltContentInputError(f"Bolt YAML plan step {index} resources must be a list")
    return document


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _path_escapes(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return path.is_absolute() or ".." in path.parts or bool(re.match(r"^[A-Za-z]:/", normalized))


def _dynamic_count(value: Any) -> int:
    if isinstance(value, str):
        return int(bool(_DYNAMIC.search(value)))
    if isinstance(value, dict):
        return sum(_dynamic_count(child) for child in value.values())
    if isinstance(value, list):
        return sum(_dynamic_count(child) for child in value)
    return 0


def _literal_secret_count(value: Any) -> int:
    count = 0
    if isinstance(value, dict):
        for key, child in value.items():
            if (
                _SECRET.search(str(key))
                and isinstance(child, (str, int, float, bool))
                and not (isinstance(child, str) and _DYNAMIC.search(child))
            ):
                count += 1
            count += _literal_secret_count(child)
    elif isinstance(value, list):
        count += sum(_literal_secret_count(child) for child in value)
    return count


def _broad_targets(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().casefold() in {"*", "all"}
    return isinstance(value, list) and any(_broad_targets(item) for item in value)


def bolt_task_metadata_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    parameters = document.get("parameters", {})
    for index, (name, definition) in enumerate(parameters.items(), start=1):
        definition = definition if isinstance(definition, dict) else {}
        declared_type = str(definition.get("type", "String"))
        sensitive = bool(definition.get("sensitive")) or "Sensitive" in declared_type
        secret_named = bool(_SECRET.search(name))
        default_secret = secret_named and "default" in definition
        if secret_named:
            changes.append(
                _change(
                    f"bolt_task.parameters.{index}",
                    "bolt_task_sensitive_parameter",
                    "dangerous" if default_secret or not sensitive else "review",
                    "Bolt task metadata declares a secret-like parameter. "
                    + (
                        "It has a literal default or is not marked sensitive, so values can leak."
                        if default_secret or not sensitive
                        else (
                            "The parameter is explicitly marked sensitive; verify "
                            "implementation output handling."
                        )
                    ),
                )
            )
        if _INJECTION_PARAMETER.search(name) and _UNCONSTRAINED_TYPE.fullmatch(declared_type):
            changes.append(
                _change(
                    f"bolt_task.parameters.{index}.type",
                    "bolt_task_unconstrained_input",
                    "dangerous",
                    "Bolt task metadata accepts an unconstrained string for an execution, "
                    "path, or mode-like parameter; use an Enum, Pattern, or other bounded "
                    "Puppet type to reduce injection and traversal risk.",
                )
            )
    implementations = document.get("implementations", [])
    for index, implementation in enumerate(implementations, start=1):
        name = implementation["name"]
        requirements = implementation.get("requirements", [])
        unsafe_path = _path_escapes(name) or "/" in name.replace("\\", "/")
        changes.append(
            _change(
                f"bolt_task.implementations.{index}",
                "bolt_task_implementation",
                "dangerous" if unsafe_path or not requirements else "review",
                "Bolt selects an executable task implementation using target features. "
                + (
                    "The implementation path escapes its task directory or has no feature "
                    "requirements."
                    if unsafe_path or not requirements
                    else (
                        "Feature requirements constrain which targets can execute this "
                        "implementation."
                    )
                ),
            )
        )
        files = implementation.get("files", [])
        if files:
            changes.append(
                _change(
                    f"bolt_task.implementations.{index}.files",
                    "bolt_task_bundled_files",
                    "dangerous" if any(_path_escapes(item) for item in files) else "review",
                    f"Bolt copies {len(files)} implementation-specific supporting file(s) to "
                    "the target before execution; verify provenance, permissions, and path "
                    "confinement.",
                )
            )
    files = document.get("files", [])
    if files:
        changes.append(
            _change(
                "bolt_task.files",
                "bolt_task_bundled_files",
                "dangerous" if any(_path_escapes(item) for item in files) else "review",
                f"Bolt copies {len(files)} shared supporting file(s) to the target before task "
                "execution; verify provenance, permissions, and path confinement.",
            )
        )
    if document.get("remote"):
        changes.append(
            _change(
                "bolt_task.remote",
                "bolt_task_remote_execution",
                "dangerous",
                "Bolt permits this task to execute on a proxy target with the remote target "
                "object and connection data; verify that it never mutates the proxy and protects "
                "injected credentials.",
            )
        )
    if document.get("supports_noop"):
        changes.append(
            _change(
                "bolt_task.supports_noop",
                "bolt_task_noop_contract",
                "review",
                "Bolt advertises no-op support; verify every implementation honors the injected "
                "no-op metaparameter without changing target state.",
            )
        )
    else:
        changes.append(
            _change(
                "bolt_task.supports_noop",
                "bolt_task_noop_unavailable",
                "review",
                "Bolt task metadata does not advertise no-op support, so callers cannot preview "
                "its target changes through Bolt.",
            )
        )
    if "input_method" in document:
        changes.append(
            _change(
                "bolt_task.input_method",
                "bolt_task_input_contract",
                "review",
                "Bolt task metadata selects one parameter-delivery mechanism; verify the "
                "implementation parses structured input safely and does not expose values "
                "through process or environment inspection.",
            )
        )
    if document.get("private"):
        changes.append(
            _change(
                "bolt_task.private",
                "bolt_task_private_visibility",
                "review",
                "Bolt hides this task from default listings, but callers can still inspect and "
                "execute it by name.",
            )
        )
    return changes


def bolt_yaml_plan_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, (name, definition) in enumerate(document.get("parameters", {}).items(), start=1):
        definition = definition if isinstance(definition, dict) else {}
        declared_type = str(definition.get("type", "Any"))
        if _SECRET.search(name):
            sensitive = "Sensitive" in declared_type
            changes.append(
                _change(
                    f"bolt_plan.parameters.{index}",
                    "bolt_plan_sensitive_parameter",
                    "dangerous" if "default" in definition or not sensitive else "review",
                    "Bolt plan declares a secret-like parameter. "
                    + (
                        "It has a literal default or is not typed Sensitive, so plan output and "
                        "nested calls can expose it."
                        if "default" in definition or not sensitive
                        else (
                            "The Sensitive type protects normal display; verify every unwrap and "
                            "nested task boundary."
                        )
                    ),
                )
            )
    if document.get("private"):
        changes.append(
            _change(
                "bolt_plan.private",
                "bolt_plan_private_visibility",
                "review",
                "Bolt hides this plan from default listings, but it remains inspectable and "
                "executable by name.",
            )
        )
    base = {
        "command": ("bolt_plan_command", "dangerous", "runs an arbitrary command on targets"),
        "task": ("bolt_plan_task", "dangerous", "runs installed task code on targets"),
        "script": (
            "bolt_plan_script",
            "dangerous",
            "copies and executes a module script on targets",
        ),
        "download": ("bolt_plan_download", "review", "copies target files to the control host"),
        "upload": ("bolt_plan_upload", "dangerous", "copies module content onto targets"),
        "plan": ("bolt_plan_nested_plan", "dangerous", "runs another orchestration plan"),
        "eval": ("bolt_plan_expression", "review", "evaluates a Puppet expression locally"),
        "message": ("bolt_plan_output", "review", "writes plan data to user-visible output"),
        "verbose": ("bolt_plan_output", "review", "writes plan data to verbose output"),
    }
    for index, step in enumerate(document["steps"], start=1):
        action = next(iter(set(step) & _STEP_ACTIONS))
        address = f"bolt_plan.steps.{index}"
        if action == "resources":
            resources = step["resources"]
            noop = step.get("noop") is True
            if not resources:
                changes.append(
                    _change(
                        f"{address}.resources",
                        "bolt_plan_resources",
                        "review",
                        "Bolt resources step is empty and has no target effect.",
                    )
                )
            for resource_index, _resource in enumerate(resources, start=1):
                changes.append(
                    _change(
                        f"{address}.resources.{resource_index}",
                        "bolt_plan_resource",
                        "review" if noop else "dangerous",
                        "Bolt applies one resource through Puppet "
                        + (
                            "in no-op mode; verify the preview before promotion."
                            if noop
                            else (
                                "and can change target state after apply preparation installs or "
                                "loads Puppet content."
                            )
                        ),
                    )
                )
        else:
            kind, risk, effect = base[action]
            if action == "task" and step.get("noop") is True:
                risk = "review"
            changes.append(
                _change(
                    f"{address}.{action}",
                    kind,
                    risk,
                    f"Bolt YAML plan {effect}; referenced content and target state are resolved "
                    "at runtime.",
                )
            )
        if step.get("catch_errors") is True:
            changes.append(
                _change(
                    f"{address}.catch_errors",
                    "bolt_plan_failure_continuation",
                    "dangerous",
                    "Bolt continues the plan after this step fails, so later mutations can run "
                    "against partial or inconsistent state.",
                )
            )
        run_as = step.get("run_as")
        if isinstance(run_as, str) and run_as.strip():
            changes.append(
                _change(
                    f"{address}.run_as",
                    "bolt_plan_privilege",
                    "dangerous" if _PRIVILEGED.fullmatch(run_as.strip()) else "review",
                    "Bolt changes the execution identity for this step; verify transport support "
                    "and least-privilege authorization.",
                )
            )
        if _broad_targets(step.get("targets")):
            changes.append(
                _change(
                    f"{address}.targets",
                    "bolt_plan_target_scope",
                    "dangerous",
                    "Bolt targets the full inventory or a wildcard, expanding this operation's "
                    "blast radius.",
                )
            )
        dynamic = _dynamic_count(step)
        if dynamic:
            changes.append(
                _change(
                    f"{address}.expressions",
                    "bolt_plan_dynamic_expression",
                    "dangerous" if action == "eval" else "review",
                    f"Bolt evaluates {dynamic} dynamic Puppet expression field(s) for this step; "
                    "runtime parameters, functions, facts, and prior results determine effective "
                    "behavior.",
                )
            )
        secrets = _literal_secret_count(step)
        if secrets:
            changes.append(
                _change(
                    f"{address}.secrets",
                    "bolt_plan_literal_secret",
                    "dangerous",
                    f"Bolt plan step contains {secrets} literal value(s) under secret-like fields; "
                    "use Sensitive values or external secret plugins instead of source-controlled "
                    "literals.",
                )
            )
        if action == "command" and isinstance(step[action], str):
            for category, pattern in _COMMAND_PATTERNS.items():
                if pattern.search(step[action]):
                    changes.append(
                        _change(
                            f"{address}.command.{category}",
                            f"bolt_plan_command_{category}",
                            "dangerous",
                            "Bolt command content includes a high-impact execution pattern; review "
                            "the exact source locally before allowing target execution.",
                        )
                    )
        if action in {"script", "upload"}:
            source = step[action]
            if not isinstance(source, str) or _path_escapes(source):
                changes.append(
                    _change(
                        f"{address}.{action}.source",
                        "bolt_plan_source_path",
                        "dangerous",
                        "Bolt source content is dynamic, absolute, or escapes its module path; "
                        "confine executable and uploaded content to reviewed module files.",
                    )
                )
        if action in {"download", "upload"}:
            paths = (step.get(action), step.get("destination"))
            if any(_path_escapes(path) for path in paths):
                changes.append(
                    _change(
                        f"{address}.paths",
                        "bolt_plan_transfer_path",
                        "dangerous",
                        "Bolt file transfer uses an absolute or parent-escaping path; verify "
                        "controller and target filesystem boundaries.",
                    )
                )
            if any(isinstance(path, str) and _SENSITIVE_PATH.search(path) for path in paths):
                changes.append(
                    _change(
                        f"{address}.sensitive_path",
                        "bolt_plan_sensitive_file",
                        "dangerous",
                        "Bolt transfers a security-sensitive system, credential, or secret path; "
                        "verify authorization, destination permissions, and retained copies.",
                    )
                )
    return changes


def bolt_content_metadata(artifact_type: str, document: dict[str, Any]) -> dict[str, Any]:
    if artifact_type == "bolt_yaml_plan":
        return {
            "step_count": len(document["steps"]),
            "parameter_count": len(document.get("parameters", {})),
            "dynamic_count": _dynamic_count(document),
        }
    parameters = document.get("parameters", {})
    return {
        "parameter_count": len(parameters),
        "implementation_count": len(document.get("implementations", [])),
        "file_count": len(document.get("files", []))
        + sum(len(item.get("files", [])) for item in document.get("implementations", [])),
        "sensitive_parameter_count": sum(
            bool(definition.get("sensitive"))
            for definition in parameters.values()
            if isinstance(definition, dict)
        ),
    }
