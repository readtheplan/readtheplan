from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class PuppetProjectInputError(ValueError):
    """Raised when input is not recognizable Puppet project configuration."""


_CALL = re.compile(r"^\s*(?P<name>[a-z_][a-z0-9_]*)\s*(?P<args>.*?)\s*$", re.IGNORECASE)
_OPTION_KEY = re.compile(
    r"(?::(?P<rocket>[a-z_][a-z0-9_]*)\s*=>|(?P<modern>[a-z_][a-z0-9_]*)\s*:)[ \t]*",
    re.IGNORECASE,
)
_COMMIT = re.compile(r"[0-9a-f]{40,64}$", re.IGNORECASE)
_EXACT_VERSION = re.compile(r"v?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?$")
_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|client.?secret|api.?key|credential)",
    re.IGNORECASE,
)
_RUBY_EXECUTION = re.compile(
    r"(?:^|\W)(?:eval|exec|spawn|system|require|load|IO\.popen|Open3\.)\s*(?:\(|['\"])"
    r"|`[^`]+`|%x\s*\W"
)
_RUBY_DYNAMIC = re.compile(
    r"(?:ENV\s*\[|File\.|Dir\.|\#\{|\.each\b|\bif\b|\bunless\b|\bcase\b|\bbegin\b)"
)
_BUILTIN_DATA_HASHES = {"json_data", "yaml_data"}
_BUILTIN_LOOKUP_KEYS = {"eyaml_lookup_key"}
_PUPPET_CONFIG_SECTIONS = {"main", "server", "agent", "user"}
_PUPPET_CONFIG_SETTING = re.compile(
    r"^[ \t]*(?P<name>[a-z_][a-z0-9_]*)[ \t]*=[ \t]*(?P<value>.*)$",
    re.IGNORECASE,
)
_PUPPET_SECRET_SETTINGS = {
    "forge_authorization",
    "http_proxy_password",
    "password",
    "passphrase",
    "token",
}
_PUPPET_COMMAND_SETTINGS = {
    "config_version",
    "diff",
    "external_nodes",
    "postrun_command",
    "prerun_command",
    "trusted_external_command",
}
_PUPPET_CODE_PATH_SETTINGS = {
    "basemodulepath",
    "binder_config",
    "codedir",
    "default_manifest",
    "environmentpath",
    "factpath",
    "hiera_config",
    "libdir",
    "manifest",
    "modulepath",
    "pluginsource",
    "route_file",
    "vendormoduledir",
}
_PUPPET_ENDPOINT_SETTINGS = {
    "ca_server",
    "http_proxy_host",
    "report_server",
    "server",
    "server_list",
}
_PUPPET_IDENTITY_SETTINGS = {
    "certname",
    "node_name_fact",
    "node_name_value",
    "user",
    "group",
}
_PUPPET_TERMINUS_SETTINGS = {
    "catalog_cache_terminus",
    "catalog_terminus",
    "data_binding_terminus",
    "node_cache_terminus",
    "node_terminus",
    "storeconfigs_backend",
}
_PUPPET_BUILTIN_REPORTS = {"console", "http", "log", "puppetdb", "store"}
_METADATA_REQUIRED = {
    "author",
    "dependencies",
    "license",
    "name",
    "source",
    "summary",
    "version",
}


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    explicit_keys: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in explicit_keys
        except TypeError as exc:
            raise PuppetProjectInputError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise PuppetProjectInputError(f"duplicate YAML key: {key}")
        explicit_keys.add(key)
    loader.flatten_mapping(node)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PuppetProjectInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strip_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
        elif char == "#" and quote is None:
            return line[:index]
    return line


def _contains_unquoted(line: str, needle: str) -> bool:
    quote: str | None = None
    escaped = False
    for char in line:
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
        elif char == needle and quote is None:
            return True
    return False


def _read_quoted(text: str, start: int) -> tuple[str, int] | None:
    if start >= len(text) or text[start] not in {"'", '"'}:
        return None
    quote = text[start]
    value: list[str] = []
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == quote:
            return "".join(value), index + 1
        if char == "\\" and index + 1 < len(text):
            value.extend((char, text[index + 1]))
            index += 2
            continue
        value.append(char)
        index += 1
    return None


def _quoted_values(text: str) -> list[str]:
    values: list[str] = []
    index = 0
    while index < len(text):
        if text[index] not in {"'", '"'}:
            index += 1
            continue
        parsed = _read_quoted(text, index)
        if parsed is None:
            break
        value, index = parsed
        values.append(value)
    return values


def _options(text: str) -> dict[str, str]:
    options: dict[str, str] = {}
    for match in _OPTION_KEY.finditer(text):
        parsed = _read_quoted(text, match.end())
        if parsed is not None:
            key = match.group("rocket") or match.group("modern")
            options[key.lower()] = parsed[0]
    return options


def _parse_puppetfile(source: str) -> dict[str, Any]:
    calls: list[dict[str, Any]] = []
    dynamic: list[dict[str, Any]] = []
    buffered = ""
    buffered_line = 0
    for line_number, original in enumerate(source.splitlines(), start=1):
        line = _strip_comment(original).strip()
        if not line:
            continue
        if buffered:
            buffered = f"{buffered} {line}"
        else:
            buffered = line
            buffered_line = line_number
        if line.endswith(","):
            continue
        match = _CALL.match(buffered)
        if not match:
            dynamic.append({"line": buffered_line, "source": buffered})
            buffered = ""
            continue
        name = match.group("name").lower()
        args = match.group("args")
        if name in {"forge", "mod", "moduledir"}:
            calls.append(
                {
                    "name": name,
                    "args": args,
                    "values": _quoted_values(args),
                    "options": _options(args),
                    "line": buffered_line,
                }
            )
            if (
                _RUBY_EXECUTION.search(args)
                or _RUBY_DYNAMIC.search(args)
                or _contains_unquoted(args, ";")
            ):
                dynamic.append({"line": buffered_line, "source": args})
        else:
            dynamic.append({"line": buffered_line, "source": buffered})
        buffered = ""
    if buffered:
        dynamic.append({"line": buffered_line, "source": buffered})
    if not any(call["name"] in {"forge", "mod", "moduledir"} for call in calls):
        raise PuppetProjectInputError("input is not a recognized Puppetfile")
    return {"artifact_type": "puppetfile", "document": {"calls": calls, "dynamic": dynamic}}


def _parse_json(source: str) -> dict[str, Any] | None:
    if not source.lstrip().startswith("{"):
        return None
    try:
        document = json.loads(source, object_pairs_hook=_unique_object)
    except PuppetProjectInputError:
        raise
    except json.JSONDecodeError as exc:
        raise PuppetProjectInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise PuppetProjectInputError("Puppet project JSON must be an object")
    metadata_shape = {"name", "version"} <= set(document) and bool(
        {"author", "dependencies", "license", "source", "summary"} & set(document)
    )
    if metadata_shape:
        _validate_metadata(document)
        return {"artifact_type": "metadata", "document": document}
    if {"version", "hierarchy", "defaults", "default_hierarchy"} & set(document):
        _validate_hiera(document)
        return {"artifact_type": "hiera", "document": document}
    raise PuppetProjectInputError("JSON is not recognized as Puppet metadata or Hiera config")


def _validate_metadata(document: dict[str, Any]) -> None:
    for key in ("dependencies", "requirements", "operatingsystem_support"):
        if key in document and not isinstance(document[key], list):
            raise PuppetProjectInputError(f"metadata {key} must be a JSON list")
    for key in ("dependencies", "requirements"):
        for index, item in enumerate(document.get(key, []), start=1):
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise PuppetProjectInputError(f"metadata {key} item {index} must have a name")
            if "version_requirement" in item and not isinstance(item["version_requirement"], str):
                raise PuppetProjectInputError(
                    f"metadata {key} item {index} version_requirement must be a string"
                )


def _parse_hiera(source: str) -> dict[str, Any]:
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except PuppetProjectInputError:
        raise
    except yaml.YAMLError as exc:
        raise PuppetProjectInputError(str(exc)) from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise PuppetProjectInputError("Hiera input must contain one YAML mapping")
    document = documents[0]
    if not ({"version", "hierarchy", "defaults", "default_hierarchy"} & set(document)):
        raise PuppetProjectInputError("input is not recognized as hiera.yaml")
    _validate_hiera(document)
    return {"artifact_type": "hiera", "document": document}


def _parse_bolt_yaml(source: str, artifact_type: str) -> dict[str, Any]:
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except PuppetProjectInputError:
        raise
    except yaml.YAMLError as exc:
        raise PuppetProjectInputError(str(exc)) from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise PuppetProjectInputError("Bolt input must contain one YAML mapping")
    document = documents[0]
    if artifact_type == "bolt_project":
        for key in (
            "apply-settings",
            "future",
            "log",
            "module-install",
            "plugin-cache",
            "plugin-hooks",
            "plugins",
            "puppetdb",
            "puppetdb-instances",
        ):
            if key in document and not isinstance(document[key], dict):
                raise PuppetProjectInputError(f"Bolt project {key} must be a mapping")
        for key in ("disable-warnings", "modules", "plans", "policies", "tasks"):
            if key in document and not isinstance(document[key], list):
                raise PuppetProjectInputError(f"Bolt project {key} must be a list")
        if "modulepath" in document and not isinstance(document["modulepath"], (str, list)):
            raise PuppetProjectInputError("Bolt project modulepath must be a string or list")
    else:
        allowed = {"config", "facts", "features", "groups", "targets", "vars", "version"}
        unknown = set(document) - allowed
        if unknown:
            raise PuppetProjectInputError(
                "unsupported top-level Bolt inventory key(s): "
                + ", ".join(sorted(map(str, unknown)))
            )
        for key in ("config", "facts", "vars"):
            if key in document and not isinstance(document[key], dict):
                raise PuppetProjectInputError(f"Bolt inventory {key} must be a mapping")
        if "features" in document and not (
            isinstance(document["features"], list)
            or (
                isinstance(document["features"], dict)
                and isinstance(document["features"].get("_plugin"), str)
            )
        ):
            raise PuppetProjectInputError(
                "Bolt inventory features must be a list or plugin mapping"
            )
        for key in ("groups", "targets"):
            value = document.get(key, [])
            if not isinstance(value, (list, dict)):
                raise PuppetProjectInputError(
                    f"Bolt inventory {key} must be a list or plugin mapping"
                )
        _validate_bolt_inventory_group(document, "inventory", require_name=False)
    return {"artifact_type": artifact_type, "document": document}


def _validate_bolt_inventory_group(
    group: dict[str, Any], address: str, *, require_name: bool
) -> None:
    allowed = {"config", "facts", "features", "groups", "name", "targets", "vars"}
    if not require_name:
        allowed.add("version")
    unknown = set(group) - allowed
    if unknown:
        raise PuppetProjectInputError(
            f"unsupported Bolt {address} key(s): " + ", ".join(sorted(map(str, unknown)))
        )
    if require_name and not isinstance(group.get("name"), str):
        raise PuppetProjectInputError(f"Bolt {address} must have a string name")
    for key in ("config", "facts", "vars"):
        if key in group and not isinstance(group[key], dict):
            raise PuppetProjectInputError(f"Bolt {address} {key} must be a mapping")
    if "features" in group and not (
        isinstance(group["features"], list)
        or (
            isinstance(group["features"], dict)
            and isinstance(group["features"].get("_plugin"), str)
        )
    ):
        raise PuppetProjectInputError(
            f"Bolt {address} features must be a list or plugin mapping"
        )

    groups = group.get("groups", [])
    if isinstance(groups, dict):
        if not isinstance(groups.get("_plugin"), str):
            raise PuppetProjectInputError(f"Bolt {address} groups plugin must name _plugin")
    elif isinstance(groups, list):
        for index, child in enumerate(groups):
            if not isinstance(child, dict):
                raise PuppetProjectInputError(f"Bolt {address} group {index} must be a mapping")
            _validate_bolt_inventory_group(child, f"{address} group {index}", require_name=True)
    else:
        raise PuppetProjectInputError(f"Bolt {address} groups must be a list or plugin mapping")

    targets = group.get("targets", [])
    if isinstance(targets, dict):
        if not isinstance(targets.get("_plugin"), str):
            raise PuppetProjectInputError(f"Bolt {address} targets plugin must name _plugin")
    elif isinstance(targets, list):
        allowed_target = {"alias", "config", "facts", "features", "name", "uri", "vars"}
        for index, target in enumerate(targets):
            if isinstance(target, str):
                continue
            if not isinstance(target, dict):
                raise PuppetProjectInputError(
                    f"Bolt {address} target {index} must be a string or mapping"
                )
            unknown_target = set(target) - allowed_target
            if unknown_target:
                raise PuppetProjectInputError(
                    f"unsupported Bolt {address} target {index} key(s): "
                    + ", ".join(sorted(map(str, unknown_target)))
                )
            if not isinstance(target.get("name") or target.get("uri"), str):
                raise PuppetProjectInputError(
                    f"Bolt {address} target {index} must have a string name or uri"
                )
            for key in ("config", "facts", "vars"):
                if key in target and not isinstance(target[key], dict):
                    raise PuppetProjectInputError(
                        f"Bolt {address} target {index} {key} must be a mapping"
                    )
            if "features" in target and not (
                isinstance(target["features"], list)
                or (
                    isinstance(target["features"], dict)
                    and isinstance(target["features"].get("_plugin"), str)
                )
            ):
                raise PuppetProjectInputError(
                    f"Bolt {address} target {index} features must be a list or plugin mapping"
                )
    else:
        raise PuppetProjectInputError(f"Bolt {address} targets must be a list or plugin mapping")


def _parse_puppet_conf(source: str) -> dict[str, Any]:
    sections: dict[str, dict[str, dict[str, Any]]] = {}
    current_section: str | None = None
    setting_count = 0
    for line_number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("["):
            if line != line.lstrip():
                raise PuppetProjectInputError(
                    f"puppet.conf section on line {line_number} must not be indented"
                )
            section_match = re.fullmatch(r"\[(?P<name>[A-Za-z][A-Za-z0-9_-]*)\]", stripped)
            if section_match is None:
                raise PuppetProjectInputError(
                    f"invalid puppet.conf section declaration on line {line_number}"
                )
            current_section = section_match.group("name").lower()
            if current_section not in _PUPPET_CONFIG_SECTIONS:
                raise PuppetProjectInputError(
                    f"unsupported puppet.conf section {current_section!r} on line {line_number}"
                )
            if current_section in sections:
                raise PuppetProjectInputError(
                    f"duplicate puppet.conf section {current_section!r} on line {line_number}"
                )
            sections[current_section] = {}
            continue
        if current_section is None:
            raise PuppetProjectInputError(
                f"puppet.conf setting on line {line_number} appears before a section"
            )
        setting_match = _PUPPET_CONFIG_SETTING.fullmatch(line)
        if setting_match is None:
            raise PuppetProjectInputError(f"invalid puppet.conf setting on line {line_number}")
        name = setting_match.group("name").lower()
        if name in sections[current_section]:
            raise PuppetProjectInputError(
                f"duplicate puppet.conf setting {name!r} in section {current_section!r}"
            )
        sections[current_section][name] = {
            "value": setting_match.group("value").strip(),
            "line": line_number,
        }
        setting_count += 1
    if not sections or not setting_count:
        raise PuppetProjectInputError("input is not a populated puppet.conf")
    return {"artifact_type": "config", "document": {"sections": sections}}


def _validate_hiera(document: dict[str, Any]) -> None:
    unknown = set(document) - {"version", "defaults", "hierarchy", "default_hierarchy"}
    if unknown:
        raise PuppetProjectInputError(
            "unsupported top-level Hiera key(s): " + ", ".join(sorted(map(str, unknown)))
        )
    defaults = document.get("defaults", {})
    if not isinstance(defaults, dict):
        raise PuppetProjectInputError("Hiera defaults must be a mapping")
    _validate_hiera_functions(defaults, "defaults")
    if "options" in defaults and not isinstance(defaults["options"], dict):
        raise PuppetProjectInputError("Hiera defaults options must be a mapping")
    for key in ("hierarchy", "default_hierarchy"):
        levels = document.get(key, [])
        if not isinstance(levels, list):
            raise PuppetProjectInputError(f"Hiera {key} must be a list")
        for index, level in enumerate(levels, start=1):
            if not isinstance(level, dict):
                raise PuppetProjectInputError(f"Hiera {key} level {index} must be a mapping")
            _validate_hiera_functions(level, f"{key} level {index}")
            if "options" in level and not isinstance(level["options"], dict):
                raise PuppetProjectInputError(
                    f"Hiera {key} level {index} options must be a mapping"
                )
            for paths_key in ("paths", "globs"):
                if paths_key in level and not isinstance(level[paths_key], list):
                    raise PuppetProjectInputError(
                        f"Hiera {key} level {index} {paths_key} must be a list"
                    )
            if "mapped_paths" in level and (
                not isinstance(level["mapped_paths"], list) or len(level["mapped_paths"]) != 3
            ):
                raise PuppetProjectInputError(
                    f"Hiera {key} level {index} mapped_paths must contain exactly three items"
                )


def _validate_hiera_functions(values: dict[str, Any], address: str) -> None:
    functions = {"data_hash", "lookup_key", "data_dig"} & set(values)
    if len(functions) > 1:
        raise PuppetProjectInputError(
            f"Hiera {address} must select only one lookup function, found: "
            + ", ".join(sorted(functions))
        )


def parse_puppet_project(source: str, *, filename: str = "") -> dict[str, Any]:
    """Parse Puppet, Hiera, or Bolt project configuration without executing code."""
    if not source.strip():
        raise PuppetProjectInputError("input is empty")
    basename = Path(filename).name.casefold()
    if basename == "bolt-project.yaml":
        parsed = _parse_bolt_yaml(source, "bolt_project")
    elif basename in {"inventory.yaml", "inventory.yml"}:
        parsed = _parse_bolt_yaml(source, "bolt_inventory")
    else:
        parsed = _parse_json(source)
    if parsed is None:
        first = next(
            (
                line.strip()
                for line in source.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ),
            "",
        )
        if basename == "puppet.conf" or first.startswith("["):
            parsed = _parse_puppet_conf(source)
        elif first == "---" or re.match(r"^(?:version|defaults|hierarchy):", first):
            parsed = _parse_hiera(source)
        else:
            parsed = _parse_puppetfile(source)
    return {"puppet_project": parsed}


def _embedded_credential(value: str) -> bool:
    candidate = value.removeprefix("git+")
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _source_risks(source: str) -> tuple[str, list[str]]:
    risk = "review"
    reasons: list[str] = []
    if source.lower().startswith(("http://", "git://")):
        risk = "dangerous"
        reasons.append("It uses an unauthenticated plaintext transport.")
    if _embedded_credential(source):
        risk = "dangerous"
        reasons.append("The source URL embeds credentials that can leak in logs or metadata.")
    if source.startswith(("./", "../", "/", "file://", "git+file://")):
        reasons.append("It resolves executable content from the local filesystem.")
    return risk, reasons


def _path_escapes(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        path.is_absolute()
        or ".." in path.parts
        or bool(re.match(r"^[A-Za-z]:/", normalized))
        or bool(urlsplit(normalized).scheme)
    )


def _puppetfile_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for call in document["calls"]:
        name = call["name"]
        values = call["values"]
        options = call["options"]
        address = f"puppetfile.line.{call['line']}"
        if name == "forge":
            endpoint = values[0] if values else "<dynamic>"
            risk, reasons = _source_risks(endpoint)
            if endpoint == "<dynamic>":
                risk = "dangerous"
                reasons.append("The Forge endpoint is dynamic and cannot be resolved statically.")
            changes.append(
                _change(
                    address,
                    "forge_source",
                    risk,
                    f"Puppetfile downloads modules from Forge endpoint {endpoint!r}. "
                    + " ".join(reasons),
                )
            )
        elif name == "moduledir":
            target = values[0] if values else "<dynamic>"
            changes.append(
                _change(
                    address,
                    "module_directory",
                    "dangerous" if target == "<dynamic>" or _path_escapes(target) else "review",
                    f"Puppetfile installs module content under {target!r}; verify deployment "
                    "scope, ownership, and modulepath precedence.",
                )
            )
        elif name == "mod":
            module = values[0] if values else "<dynamic>"
            version = values[1] if len(values) > 1 and not options else ""
            source = options.get("git") or options.get("path") or ""
            revision = next(
                (
                    options[key]
                    for key in ("commit", "ref", "revision", "tag", "branch")
                    if key in options
                ),
                "",
            )
            risk, reasons = _source_risks(source)
            exact_forge = bool(version and _EXACT_VERSION.fullmatch(version))
            exact_git = bool(revision and _COMMIT.fullmatch(revision))
            if not exact_forge and not exact_git:
                risk = "dangerous"
                reasons.append("The module is not pinned to an exact Forge version or full commit.")
            if revision and not exact_git:
                risk = "dangerous"
                reasons.append("The Git revision is a mutable branch, tag, or abbreviated commit.")
            install_path = options.get("install_path", "")
            if install_path and _path_escapes(install_path):
                risk = "dangerous"
                reasons.append("The install_path escapes the environment module directory.")
            changes.append(
                _change(
                    address,
                    "module_dependency",
                    risk,
                    f"Puppet installs executable module/content {module!r}. " + " ".join(reasons),
                )
            )
    changes.extend(_dynamic_changes(document.get("dynamic", [])))
    return changes


def _dynamic_changes(dynamic: list[dict[str, Any]]) -> list[dict[str, str]]:
    if not dynamic:
        return []
    execution = [item for item in dynamic if _RUBY_EXECUTION.search(str(item["source"]))]
    remaining = [item for item in dynamic if item not in execution]
    changes: list[dict[str, str]] = []
    if execution:
        changes.append(
            _change(
                f"puppetfile.line.{execution[0]['line']}",
                "ruby_execution",
                "dangerous",
                "Puppetfile contains Ruby process/code-loading behavior; r10k or Code Manager "
                "executes this file while resolving environment content.",
            )
        )
    if remaining:
        changes.append(
            _change(
                f"puppetfile.line.{remaining[0]['line']}",
                "dynamic_ruby",
                "review",
                f"Puppetfile contains {len(remaining)} unexpanded Ruby expression(s); effective "
                "module resolution may differ at deployment time.",
            )
        )
    return changes


def _bounded_requirement(value: str) -> bool:
    text = value.strip()
    if _EXACT_VERSION.fullmatch(text.lstrip("= ")):
        return True
    lower = bool(re.search(r"(?:^|\s)(?:>=|>)\s*v?\d", text))
    upper = bool(re.search(r"(?:^|\s)(?:<=|<)\s*v?\d", text))
    pessimistic = bool(re.search(r"(?:^|\s)~>\s*v?\d", text))
    return lower and upper or pessimistic


def _metadata_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for key in sorted(_METADATA_REQUIRED - set(document)):
        changes.append(
            _change(
                f"metadata.{key}",
                "missing_metadata_field",
                "dangerous",
                f"Puppet module metadata omits required field {key!r}, weakening package "
                "identity or dependency resolution.",
            )
        )
    source = document.get("source")
    if isinstance(source, str) and source:
        risk, reasons = _source_risks(source)
        if reasons:
            changes.append(
                _change(
                    "metadata.source",
                    "module_source",
                    risk,
                    f"Puppet module publishes source endpoint {source!r}. " + " ".join(reasons),
                )
            )
    for kind in ("dependencies", "requirements"):
        for index, item in enumerate(document.get(kind, []), start=1):
            name = item["name"]
            requirement = str(item.get("version_requirement", "")).strip()
            bounded = _bounded_requirement(requirement)
            changes.append(
                _change(
                    f"metadata.{kind}.{index}.{name}",
                    "module_dependency" if kind == "dependencies" else "runtime_requirement",
                    "review" if bounded else "dangerous",
                    f"Puppet metadata declares {kind[:-1]} {name!r} with version requirement "
                    f"{requirement or '<missing>'!r}. "
                    + (
                        "The requirement is exact or has both compatibility bounds."
                        if bounded
                        else "The requirement is missing or unbounded."
                    ),
                )
            )
    operating_systems = document.get("operatingsystem_support", [])
    if operating_systems:
        changes.append(
            _change(
                "metadata.operatingsystem_support",
                "operating_system_support",
                "review",
                f"Puppet module declares compatibility with {len(operating_systems)} operating "
                "system family entry/entries; verify promoted node coverage.",
            )
        )
    return changes


def _hiera_function(level: dict[str, Any], defaults: dict[str, Any]) -> tuple[str, str]:
    for key in ("lookup_key", "data_hash", "data_dig"):
        if key in level:
            return key, str(level[key])
        if key in defaults:
            return key, str(defaults[key])
    return "data_hash", "yaml_data"


def _walk_secret_paths(value: Any, prefix: str = "") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if (
                _SECRET.search(path)
                and isinstance(child, (str, int, float, bool))
                and not _looks_like_file_reference(child)
            ):
                paths.append(path)
            paths.extend(_walk_secret_paths(child, path))
    elif isinstance(value, list):
        for child in value:
            paths.extend(_walk_secret_paths(child, prefix))
    return paths


def _walk_secret_file_paths(value: Any, prefix: str = "") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if _SECRET.search(path) and _looks_like_file_reference(child):
                paths.append(path)
            paths.extend(_walk_secret_file_paths(child, path))
    elif isinstance(value, list):
        for child in value:
            paths.extend(_walk_secret_file_paths(child, prefix))
    return paths


def _looks_like_file_reference(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return (
        "/" in value
        or "\\" in value
        or lowered.endswith((".key", ".pem", ".pkcs7", ".crt", ".cert"))
    )


def _hiera_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    version = document.get("version")
    if version != 5:
        changes.append(
            _change(
                "hiera.version",
                "legacy_hiera_version",
                "dangerous",
                f"Hiera configuration uses version {version!r}; version 5 is the supported "
                "environment/module configuration contract.",
            )
        )
    defaults = document.get("defaults", {})
    default_datadir = str(defaults.get("datadir", "data"))
    if _path_escapes(default_datadir):
        changes.append(
            _change(
                "hiera.defaults.datadir",
                "data_path_escape",
                "dangerous",
                f"Hiera default datadir {default_datadir!r} escapes the configuration directory.",
            )
        )
    default_options = defaults.get("options", {})
    default_secrets = _walk_secret_paths(default_options)
    default_secret_files = _walk_secret_file_paths(default_options)
    if default_secrets:
        changes.append(
            _change(
                "hiera.defaults.options",
                "backend_secret",
                "dangerous",
                "Hiera default backend options contain literal secret-like field(s): "
                + ", ".join(default_secrets[:3]),
            )
        )
    if default_secret_files:
        changes.append(
            _change(
                "hiera.defaults.options",
                "backend_credential_file",
                "review",
                "Hiera default backend options reference credential/key file(s): "
                + ", ".join(default_secret_files[:3])
                + ". Verify permissions and keep private material outside source control.",
            )
        )
    all_levels = [
        *document.get("hierarchy", []),
        *document.get("default_hierarchy", []),
    ]
    if not all_levels and ({"lookup_key", "data_hash", "data_dig"} & set(defaults)):
        function_kind, function = _hiera_function({}, defaults)
        builtin = (
            function in _BUILTIN_DATA_HASHES
            if function_kind == "data_hash"
            else function in _BUILTIN_LOOKUP_KEYS
        )
        changes.append(
            _change(
                f"hiera.defaults.{function_kind}",
                "data_backend",
                "review" if builtin else "dangerous",
                (
                    f"Hiera defaults select built-in {function_kind} {function!r}."
                    if builtin
                    else f"Hiera defaults execute custom {function_kind} {function!r} during "
                    "catalog data lookup."
                ),
            )
        )
    for hierarchy_kind in ("hierarchy", "default_hierarchy"):
        levels = document.get(hierarchy_kind, [])
        if levels and hierarchy_kind == "default_hierarchy":
            changes.append(
                _change(
                    "hiera.default_hierarchy",
                    "default_data_fallback",
                    "review",
                    "Hiera adds a module default hierarchy consulted after global, environment, "
                    "and normal module data sources do not return a value.",
                )
            )
        for index, level in enumerate(levels, start=1):
            address = f"hiera.{hierarchy_kind}.{index}"
            function_kind, function = _hiera_function(level, defaults)
            builtin = (
                function in _BUILTIN_DATA_HASHES
                if function_kind == "data_hash"
                else function in _BUILTIN_LOOKUP_KEYS
            )
            changes.append(
                _change(
                    f"{address}.{function_kind}",
                    "data_backend",
                    "review" if builtin else "dangerous",
                    (
                        f"Hiera hierarchy level uses built-in {function_kind} {function!r}."
                        if builtin
                        else f"Hiera hierarchy level executes custom {function_kind} {function!r} "
                        "during catalog data lookup."
                    ),
                )
            )
            paths: list[str] = []
            for key in ("path", "glob", "datadir"):
                if key in level:
                    paths.append(str(level[key]))
            for key in ("paths", "globs"):
                paths.extend(str(item) for item in level.get(key, []))
            if "mapped_paths" in level:
                mapped = level["mapped_paths"]
                if isinstance(mapped, list):
                    paths.extend(str(item) for item in mapped[1:])
            if not str(level.get("name", "")).strip():
                changes.append(
                    _change(
                        f"{address}.name",
                        "missing_hierarchy_name",
                        "dangerous",
                        "Hiera hierarchy level has no static name, weakening lookup traceability.",
                    )
                )
            if function_kind == "data_hash" and not paths:
                changes.append(
                    _change(
                        f"{address}.paths",
                        "missing_data_path",
                        "dangerous",
                        "File-backed Hiera hierarchy level has no path, paths, glob, globs, or "
                        "mapped_paths source.",
                    )
                )
            if any(_path_escapes(path) for path in paths):
                changes.append(
                    _change(
                        f"{address}.paths",
                        "data_path_escape",
                        "dangerous",
                        "Hiera hierarchy path escapes its configured data directory.",
                    )
                )
            elif paths:
                changes.append(
                    _change(
                        f"{address}.paths",
                        "data_source",
                        "review",
                        f"Hiera hierarchy level selects {len(paths)} ordered data path/glob "
                        "source(s); higher-priority values override later sources.",
                    )
                )
            options = level.get("options", {})
            if isinstance(options, dict):
                secrets = _walk_secret_paths(options)
                secret_files = _walk_secret_file_paths(options)
                if secrets:
                    changes.append(
                        _change(
                            f"{address}.options",
                            "backend_secret",
                            "dangerous",
                            "Hiera backend options contain literal secret-like field(s): "
                            + ", ".join(secrets[:3]),
                        )
                    )
                if secret_files:
                    changes.append(
                        _change(
                            f"{address}.options",
                            "backend_credential_file",
                            "review",
                            "Hiera backend options reference credential/key file(s): "
                            + ", ".join(secret_files[:3])
                            + ". Verify permissions and keep private material outside source "
                            "control.",
                        )
                    )
    return changes


def _puppet_config_enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "on", "true", "yes"}


def _puppet_config_disabled(value: str) -> bool:
    return value.strip().lower() in {"0", "false", "no", "none", "off"}


def _puppet_config_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    sections = document["sections"]
    for section, settings in sections.items():
        for name, setting in settings.items():
            value = str(setting["value"])
            lowered = value.strip().lower()
            address = f"puppet_conf.{section}.{name}"

            if name in _PUPPET_SECRET_SETTINGS and lowered not in {"", "none"}:
                indirect = value.lstrip().startswith("$")
                changes.append(
                    _change(
                        address,
                        "credential",
                        "review" if indirect else "dangerous",
                        (
                            "Puppet configuration references a credential through setting "
                            f"{name!r}; verify the referenced value is supplied outside source "
                            "control and protected from logs."
                            if indirect
                            else "Puppet configuration stores a literal credential in setting "
                            f"{name!r}; move it to a protected external secret source."
                        ),
                    )
                )
                continue

            if name == "autosign":
                if _puppet_config_disabled(value):
                    risk = "safe"
                    explanation = "Puppet CA certificate autosigning is explicitly disabled."
                elif _puppet_config_enabled(value):
                    risk = "dangerous"
                    explanation = (
                        "Puppet CA autosigns every certificate request, allowing unreviewed "
                        "nodes to receive trusted identities."
                    )
                else:
                    risk = "review"
                    explanation = (
                        "Puppet CA delegates certificate autosigning to a policy/configuration "
                        "file; verify its allowlist and permissions because executable files are "
                        "run for every certificate request."
                    )
                changes.append(_change(address, "certificate_autosign", risk, explanation))
                continue

            if name == "certificate_revocation":
                if _puppet_config_disabled(value):
                    risk = "dangerous"
                    explanation = "Puppet disables all certificate revocation checks."
                elif lowered == "leaf":
                    risk = "review"
                    explanation = (
                        "Puppet verifies only leaf certificate revocation and does not verify "
                        "revocation across the complete CA chain."
                    )
                else:
                    risk = "safe"
                    explanation = "Puppet enables certificate revocation checking for its CA chain."
                changes.append(_change(address, "certificate_revocation", risk, explanation))
                continue

            if name == "allow_duplicate_certs" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "duplicate_certificate_request",
                        "review",
                        "Puppet CA permits a new certificate request to replace an existing "
                        "request; retain explicit cleanup and signing approval controls.",
                    )
                )
                continue

            if name == "digest_algorithm":
                strong = lowered in {"sha224", "sha256", "sha384", "sha512"}
                changes.append(
                    _change(
                        address,
                        "content_digest",
                        "safe" if strong else "dangerous",
                        (
                            "Puppet uses a modern SHA-2 digest for managed file integrity."
                            if strong
                            else "Puppet uses a weak or unrecognized digest for managed file "
                            "integrity."
                        ),
                    )
                )
                continue

            if name in _PUPPET_COMMAND_SETTINGS and lowered not in {"", "none"}:
                risk = "review" if name == "diff" and lowered == "diff" else "dangerous"
                changes.append(
                    _change(
                        address,
                        "external_command",
                        risk,
                        f"Puppet setting {name!r} invokes an external command in a privileged "
                        "configuration workflow; review ownership, arguments, and executable "
                        "provenance.",
                    )
                )
                continue

            if name == "code" and value.strip():
                changes.append(
                    _change(
                        address,
                        "inline_code",
                        "dangerous",
                        "Puppet configuration injects inline manifest code directly into the "
                        "runtime instead of loading reviewed environment content.",
                    )
                )
                continue

            if name == "node_terminus" and lowered == "exec":
                changes.append(
                    _change(
                        address,
                        "external_node_classifier",
                        "dangerous",
                        "Puppet delegates node classification to an executable external node "
                        "classifier whose output controls classes, environments, and parameters.",
                    )
                )
                continue

            if name in _PUPPET_TERMINUS_SETTINGS and lowered not in {"", "none"}:
                builtins = {
                    "classifier",
                    "compiler",
                    "json",
                    "msgpack",
                    "plain",
                    "puppetdb",
                    "rest",
                    "yaml",
                }
                custom = lowered not in builtins
                changes.append(
                    _change(
                        address,
                        "runtime_backend",
                        "dangerous" if custom else "review",
                        (
                            f"Puppet setting {name!r} selects a custom runtime backend that can "
                            "load extension code or redirect authoritative data."
                            if custom
                            else f"Puppet setting {name!r} changes the backend responsible for "
                            "authoritative runtime data or cached state."
                        ),
                    )
                )
                continue

            if name == "reports" and value.strip():
                processors = {
                    item.strip().lower() for item in value.split(",") if item.strip()
                }
                custom = processors - _PUPPET_BUILTIN_REPORTS
                changes.append(
                    _change(
                        address,
                        "report_processors",
                        "dangerous" if custom else "review",
                        (
                            "Puppet loads one or more custom report processors as server-side "
                            "extension code."
                            if custom
                            else "Puppet forwards or persists run reports through configured "
                            "built-in processors; verify destinations and report-data exposure."
                        ),
                    )
                )
                continue

            if name == "reporturl" and value.strip():
                plaintext = lowered.startswith("http://")
                changes.append(
                    _change(
                        address,
                        "report_endpoint",
                        "dangerous" if plaintext else "review",
                        (
                            "Puppet sends report data to a plaintext HTTP endpoint."
                            if plaintext
                            else "Puppet sends report data to an external endpoint; verify TLS, "
                            "authentication, and data handling."
                        ),
                    )
                )
                continue

            if name == "http_debug" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "http_debug_logging",
                        "dangerous",
                        "Puppet logs HTTP requests and responses, which can expose catalog, fact, "
                        "certificate, or credential material.",
                    )
                )
                continue

            if name == "http_extra_headers" and value.strip() not in {"", "[]"}:
                secret_like = bool(_SECRET.search(value))
                changes.append(
                    _change(
                        address,
                        "http_headers",
                        "dangerous" if secret_like else "review",
                        (
                            "Puppet configuration places secret-like material in outbound HTTP "
                            "headers."
                            if secret_like
                            else "Puppet adds custom outbound HTTP headers; verify their trust "
                            "boundary and logging behavior."
                        ),
                    )
                )
                continue

            if name == "show_diff" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "content_diff_logging",
                        "dangerous",
                        "Puppet logs managed file content differences, which can expose secrets "
                        "or other sensitive configuration data.",
                    )
                )
                continue

            if name == "ignore_plugin_errors" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "plugin_error_bypass",
                        "dangerous",
                        "Puppet continues after plugin synchronization errors instead of failing "
                        "the run closed.",
                    )
                )
                continue

            if name == "use_cached_catalog" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "cached_catalog_only",
                        "dangerous",
                        "Puppet applies only its cached catalog without requesting current policy "
                        "or uploading current facts.",
                    )
                )
                continue

            if name == "usecacheonfailure" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "cached_catalog_fallback",
                        "review",
                        "Puppet can apply a previously cached catalog when current catalog "
                        "compilation fails; review stale-policy tolerance.",
                    )
                )
                continue

            if name == "strict_variables" and _puppet_config_disabled(value):
                changes.append(
                    _change(
                        address,
                        "undefined_variable_tolerance",
                        "dangerous",
                        "Puppet permits undefined variables instead of failing catalog evaluation.",
                    )
                )
                continue

            if name == "strict" and lowered == "off":
                changes.append(
                    _change(
                        address,
                        "validation_strictness",
                        "review",
                        "Puppet disables strict validation warnings for potentially unsafe or "
                        "deprecated behavior.",
                    )
                )
                continue

            if name == "preferred_serialization_format" and lowered == "pson":
                changes.append(
                    _change(
                        address,
                        "legacy_serialization",
                        "dangerous",
                        "Puppet prefers legacy PSON serialization, which cannot preserve all rich "
                        "catalog data safely.",
                    )
                )
                continue

            if name == "allow_pson_serialization" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "legacy_serialization",
                        "review",
                        "Puppet permits fallback to legacy PSON serialization when modern formats "
                        "cannot represent catalog data.",
                    )
                )
                continue

            if name in _PUPPET_CODE_PATH_SETTINGS and value.strip():
                changes.append(
                    _change(
                        address,
                        "code_source_path",
                        "review",
                        f"Puppet setting {name!r} changes a manifest, module, fact, plugin, route, "
                        "or data source path that can affect compiled catalogs and runtime code.",
                    )
                )
                continue

            if name in _PUPPET_ENDPOINT_SETTINGS and lowered not in {"", "none"}:
                changes.append(
                    _change(
                        address,
                        "service_endpoint",
                        "review",
                        f"Puppet setting {name!r} changes a server, CA, reporting, or proxy trust "
                        "boundary; verify identity, routing, and TLS expectations.",
                    )
                )
                continue

            if name in _PUPPET_IDENTITY_SETTINGS and value.strip():
                changes.append(
                    _change(
                        address,
                        "runtime_identity",
                        "review",
                        f"Puppet setting {name!r} changes certificate, node, user, or group "
                        "identity used for authorization and privileged execution.",
                    )
                )
                continue

            if name == "environment" and value.strip():
                global_environment = section == "main"
                changes.append(
                    _change(
                        address,
                        "environment_selection",
                        "dangerous" if global_environment else "review",
                        (
                            "Puppet sets environment globally even though agent, server, and user "
                            "contexts can require different code; move it to the intended "
                            "application-specific section."
                            if global_environment
                            else "Puppet pins the code environment for this application context; "
                            "verify environment assignment and promotion controls."
                        ),
                    )
                )
                continue

            if name in {"ca_ttl", "dns_alt_names", "ssl_client_header", "ssl_client_verify_header"}:
                changes.append(
                    _change(
                        address,
                        "certificate_identity",
                        "review",
                        f"Puppet setting {name!r} changes certificate lifetime, trusted names, or "
                        "reverse-proxy identity headers; review the CA and network trust model.",
                    )
                )
                continue

            if name in {"pluginsync", "report", "splay", "storeconfigs"} and _puppet_config_enabled(
                value
            ):
                changes.append(
                    _change(
                        address,
                        "runtime_integration",
                        "review",
                        f"Puppet enables {name!r}, changing plugin delivery, reporting, "
                        "scheduling, or exported-resource state behavior.",
                    )
                )
                continue

            if name == "runinterval" and value.strip():
                changes.append(
                    _change(
                        address,
                        "agent_schedule",
                        "review",
                        "Puppet changes the recurring agent enforcement interval; review rollout "
                        "load, convergence latency, and maintenance windows.",
                    )
                )
                continue

            if name == "noop" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "dry_run",
                        "safe",
                        "Puppet runs in no-op mode and reports proposed changes without enforcing "
                        "resource state.",
                    )
                )
                continue

            if name in {"tasks", "manage_internal_file_permissions"}:
                unsafe = (
                    name == "tasks" and _puppet_config_enabled(value)
                ) or (name == "manage_internal_file_permissions" and _puppet_config_disabled(value))
                if unsafe:
                    changes.append(
                        _change(
                            address,
                            "runtime_safety_control",
                            "dangerous",
                            f"Puppet setting {name!r} enables experimental execution or disables "
                            "protection of internal files.",
                        )
                    )

    return changes


_BOLT_BUILTIN_PLUGINS = {
    "aws_inventory",
    "azure_inventory",
    "env_var",
    "gcloud_inventory",
    "json",
    "pkcs7",
    "prompt",
    "puppetdb",
    "terraform",
    "vault",
    "yaml",
}
_BOLT_DYNAMIC_INVENTORY_PLUGINS = {
    "aws_inventory",
    "azure_inventory",
    "gcloud_inventory",
    "puppetdb",
    "terraform",
    "yaml",
}
_BOLT_PRIVILEGED_USERS = {"administrator", "root"}


def _bolt_address_segment(value: object) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", str(value))[:80] or "key"


def _bolt_walk(value: Any, address: str = "bolt") -> list[tuple[str, str, Any]]:
    found: list[tuple[str, str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_address = f"{address}.{_bolt_address_segment(key_text)}"
            found.append((child_address, key_text.casefold(), child))
            found.extend(_bolt_walk(child, child_address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_bolt_walk(child, f"{address}.{index}"))
    return found


def _bolt_plugin_changes(document: dict[str, Any], *, inventory: bool) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for address, key, value in _bolt_walk(document):
        if key != "_plugin" or not isinstance(value, str):
            continue
        plugin = value.casefold()
        if (
            inventory
            and plugin in _BOLT_DYNAMIC_INVENTORY_PLUGINS
            and (".targets._plugin" in address or ".groups._plugin" in address)
        ):
            risk = "dangerous"
            kind = "bolt_dynamic_inventory"
            explanation = (
                "Bolt executes a reference plugin while loading inventory to determine target "
                "scope. Review the query, credentials, returned targets, and plugin provenance."
            )
        elif plugin in _BOLT_BUILTIN_PLUGINS:
            risk = "review"
            kind = "bolt_reference_plugin"
            explanation = (
                "Bolt resolves a built-in reference plugin at runtime; verify its external data "
                "source, secret handling, and effective returned value."
            )
        else:
            risk = "dangerous"
            kind = "bolt_custom_plugin"
            explanation = (
                "Bolt resolves a module-provided or unknown plugin that can execute custom code "
                "on the controller. Verify the installed module and plugin implementation."
            )
        changes.append(_change(address, kind, risk, explanation))
    return changes


def _bolt_literal_secret_changes(document: dict[str, Any], root: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for address, key, value in _bolt_walk(document, root):
        if key == "token" and ".puppetdb" in address:
            continue
        if (not _SECRET.search(key) and key != "key-data") or key in {
            "private-key",
            "token-file",
        }:
            continue
        if isinstance(value, (str, int, float)):
            changes.append(
                _change(
                    address,
                    "bolt_literal_credential",
                    "dangerous",
                    "Bolt configuration contains literal credential material. Replace it with a "
                    "secret reference plugin or a protected credential file.",
                )
            )
    return changes


def _bolt_module_change(module: Any, index: int) -> dict[str, str]:
    address = f"bolt_project.modules.{index}"
    if isinstance(module, str):
        return _change(
            address,
            "bolt_module_dependency",
            "dangerous",
            "Bolt installs a module without an exact version requirement, so future resolution "
            "can change the code executed by tasks and plans.",
        )
    if not isinstance(module, dict):
        return _change(
            address,
            "bolt_module_dependency",
            "dangerous",
            "Bolt module dependency is not a static string or mapping and cannot be verified.",
        )
    source = module.get("git")
    requirement = module.get("version_requirement")
    ref = module.get("ref")
    if isinstance(source, str):
        source_risk, reasons = _source_risks(source)
        immutable = isinstance(ref, str) and bool(_COMMIT.fullmatch(ref))
        risk = "review" if immutable and source_risk == "review" else "dangerous"
        explanation = "Bolt installs a module from Git. " + " ".join(reasons)
        explanation += (
            " The ref is an immutable commit."
            if immutable
            else " The ref is absent or mutable; pin a full commit digest."
        )
        return _change(address, "bolt_module_dependency", risk, explanation)
    exact = isinstance(requirement, str) and bool(_EXACT_VERSION.fullmatch(requirement.strip()))
    return _change(
        address,
        "bolt_module_dependency",
        "review" if exact else "dangerous",
        "Bolt installs a Forge module with an exact version requirement."
        if exact
        else "Bolt installs a Forge module without an exact version requirement.",
    )


def _bolt_project_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes = [
        _bolt_module_change(module, index)
        for index, module in enumerate(document.get("modules", []))
    ]
    changes.extend(_bolt_plugin_changes(document, inventory=False))
    changes.extend(_bolt_literal_secret_changes(document, "bolt_project"))

    plugins = document.get("plugins", {})
    for index, _name in enumerate(plugins):
        changes.append(
            _change(
                f"bolt_project.plugins.{index}",
                "bolt_configured_plugin",
                "dangerous",
                "Bolt configures a plugin supplied by installed executable module content. "
                "Verify the module provenance, plugin hooks, and configuration schema.",
            )
        )

    modulepath = document.get("modulepath", [])
    paths = [modulepath] if isinstance(modulepath, str) else modulepath
    for index, path in enumerate(paths):
        if isinstance(path, str):
            changes.append(
                _change(
                    f"bolt_project.modulepath.{index}",
                    "bolt_module_path",
                    "dangerous" if _path_escapes(path) else "review",
                    "Bolt loads executable task, plan, and plugin content from a module path "
                    + ("outside the project." if _path_escapes(path) else "inside the project."),
                )
            )
    module_install = document.get("module-install", {})
    forge = module_install.get("forge", {}) if isinstance(module_install, dict) else {}
    if isinstance(forge, dict):
        endpoint = forge.get("baseurl")
        if isinstance(endpoint, str):
            changes.append(
                _change(
                    "bolt_project.module-install.forge.baseurl",
                    "bolt_module_endpoint",
                    "dangerous" if endpoint.casefold().startswith("http://") else "review",
                    "Bolt downloads modules from a plaintext Forge endpoint."
                    if endpoint.casefold().startswith("http://")
                    else "Bolt downloads modules from a configured Forge endpoint.",
                )
            )
    for address, key, value in _bolt_walk(document, "bolt_project"):
        if key in {"proxy", "server_urls", "service-url"}:
            urls = value if isinstance(value, list) else [value]
            if any(isinstance(url, str) and url.casefold().startswith("http://") for url in urls):
                changes.append(
                    _change(
                        address,
                        "bolt_plaintext_endpoint",
                        "dangerous",
                        "Bolt connects to a plaintext HTTP endpoint, exposing metadata or "
                        "credentials to interception.",
                    )
                )
            if any(isinstance(url, str) and _embedded_credential(url) for url in urls):
                changes.append(
                    _change(
                        address,
                        "bolt_embedded_credential",
                        "dangerous",
                        "Bolt endpoint or proxy URL embeds credentials that can leak through "
                        "configuration, logs, and process metadata.",
                    )
                )
        if key in {"cacert", "cert", "key", "token"} and ".puppetdb" in address:
            changes.append(
                _change(
                    address,
                    "bolt_credential_file_boundary",
                    "review",
                    "Bolt depends on an external PuppetDB trust or credential file.",
                )
            )
        if key == "trusted-external-command" and isinstance(value, str):
            changes.append(
                _change(
                    address,
                    "bolt_external_command",
                    "dangerous",
                    "Bolt executes an external controller command to produce trusted facts.",
                )
            )
        if key in {"evaltrace", "show_diff", "trace"} and value is True:
            changes.append(
                _change(
                    address,
                    "bolt_sensitive_output",
                    "dangerous",
                    "Bolt enables verbose apply output that can disclose sensitive resource "
                    "values or execution context.",
                )
            )
        if key == "log_level" and str(value).casefold() == "debug":
            changes.append(
                _change(
                    address,
                    "bolt_debug_logging",
                    "dangerous",
                    "Bolt enables debug apply logs that can persist sensitive execution details.",
                )
            )
        if key == "plugin" and ".plugin-hooks." in address and isinstance(value, str):
            run_as = document.get("plugin-hooks", {})
            changes.append(
                _change(
                    address,
                    "bolt_plugin_hook",
                    "dangerous" if "root" in str(run_as).casefold() else "review",
                    "Bolt configures a plugin hook that installs or prepares executable Puppet "
                    "content on targets.",
                )
            )
    return changes


def _bolt_inventory_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes = _bolt_plugin_changes(document, inventory=True)
    changes.extend(_bolt_literal_secret_changes(document, "bolt_inventory"))
    target_count = 0
    for address, key, value in _bolt_walk(document, "bolt_inventory"):
        if key == "targets" and isinstance(value, list):
            target_count += len(value)
            for index, target in enumerate(value):
                if not isinstance(target, str):
                    continue
                target_address = f"{address}.{index}"
                if target.casefold().startswith("http://"):
                    changes.append(
                        _change(
                            target_address,
                            "bolt_plaintext_transport",
                            "dangerous",
                            "Bolt connects to a target over plaintext HTTP.",
                        )
                    )
                if target.casefold().startswith("local://"):
                    changes.append(
                        _change(
                            target_address,
                            "bolt_transport",
                            "dangerous",
                            "Bolt target URI selects local controller execution.",
                        )
                    )
                if _embedded_credential(target):
                    changes.append(
                        _change(
                            target_address,
                            "bolt_embedded_credential",
                            "dangerous",
                            "Bolt target URI embeds credentials that can leak through "
                            "configuration, logs, and process metadata.",
                        )
                    )
        if (
            key in {"uri", "service-url"}
            and isinstance(value, str)
            and value.casefold().startswith("http://")
        ):
            changes.append(
                _change(
                    address,
                    "bolt_plaintext_transport",
                    "dangerous",
                    "Bolt connects to a target or service over plaintext HTTP.",
                )
            )
        if key in {"uri", "service-url"} and isinstance(value, str) and _embedded_credential(value):
            changes.append(
                _change(
                    address,
                    "bolt_embedded_credential",
                    "dangerous",
                    "Bolt target or service URL embeds credentials that can leak through "
                    "configuration, logs, and process metadata.",
                )
            )
        if key in {"host-key-check", "ssl-verify"} and value is False:
            changes.append(
                _change(
                    address,
                    "bolt_transport_verification",
                    "dangerous",
                    "Bolt disables SSH host-key or TLS certificate verification, allowing "
                    "endpoint impersonation.",
                )
            )
        if key == "ssl" and value is False:
            changes.append(
                _change(
                    address,
                    "bolt_plaintext_transport",
                    "dangerous",
                    "Bolt disables HTTPS for WinRM transport.",
                )
            )
        if key == "cleanup" and value is False:
            changes.append(
                _change(
                    address,
                    "bolt_remote_cleanup",
                    "review",
                    "Bolt leaves temporary executable files on targets after commands finish.",
                )
            )
        if (
            key in {"user", "run-as"}
            and isinstance(value, str)
            and value.casefold() in _BOLT_PRIVILEGED_USERS
        ):
            changes.append(
                _change(
                    address,
                    "bolt_privileged_identity",
                    "dangerous",
                    "Bolt logs in or executes commands with a highly privileged identity.",
                )
            )
        if key in {"run-as-command", "shell-command", "sudo-executable", "interpreters"}:
            changes.append(
                _change(
                    address,
                    "bolt_command_execution",
                    "dangerous",
                    "Bolt overrides a command, interpreter, or privilege-escalation executable "
                    "used on targets.",
                )
            )
        if key == "transport" and isinstance(value, str):
            risk = "dangerous" if value.casefold() == "local" else "review"
            changes.append(
                _change(
                    address,
                    "bolt_transport",
                    risk,
                    "Bolt selects local controller execution."
                    if risk == "dangerous"
                    else "Bolt selects a target transport; verify the effective inherited "
                    "connection policy.",
                )
            )
        if key in {"proxyjump", "private-key", "token-file", "cacert", "cert", "key"}:
            changes.append(
                _change(
                    address,
                    "bolt_credential_or_proxy_boundary",
                    "review",
                    "Bolt depends on an external credential, trust file, private key, or proxy "
                    "boundary.",
                )
            )
        if key in {
            "encryption-algorithms",
            "host-key-algorithms",
            "kex-algorithms",
            "mac-algorithms",
        }:
            encoded = " ".join(map(str, value if isinstance(value, list) else [value])).casefold()
            if any(marker in encoded for marker in ("cbc", "dss", "group1", "md5", "sha1")):
                changes.append(
                    _change(
                        address,
                        "bolt_legacy_ssh_algorithm",
                        "dangerous",
                        "Bolt enables legacy SSH algorithms that weaken transport security.",
                    )
                )
    if target_count:
        changes.append(
            _change(
                "bolt_inventory.targets",
                "bolt_target_scope",
                "review",
                f"Bolt inventory statically selects {target_count} target declaration(s); "
                "verify group inheritance and command targeting.",
            )
        )
    return changes


class PuppetProjectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "puppet-project"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        project = input_data.get("puppet_project")
        return (
            isinstance(project, dict)
            and project.get("artifact_type")
            in {"puppetfile", "metadata", "hiera", "config", "bolt_project", "bolt_inventory"}
            and isinstance(project.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        project = input_data["puppet_project"]
        artifact_type = project["artifact_type"]
        changes = {
            "puppetfile": _puppetfile_changes,
            "metadata": _metadata_changes,
            "hiera": _hiera_changes,
            "config": _puppet_config_changes,
            "bolt_project": _bolt_project_changes,
            "bolt_inventory": _bolt_inventory_changes,
        }[artifact_type](project["document"])
        if artifact_type.startswith("bolt_"):
            boundary = (
                "Effective Bolt behavior also depends on configuration precedence, command-line "
                "options, installed modules and plugins, resolved inventory data, target facts "
                "and variables, credential files, environment values, and the tasks, plans, "
                "commands, scripts, and Puppet code selected at runtime."
            )
            address = "bolt.effective_project"
        else:
            boundary = (
                "Effective Puppet behavior also depends on deployed module contents, transitive "
                "dependencies, environment/modulepath precedence, Code Manager or r10k settings, "
                "Hiera data files, eyaml keys, Puppet Server configuration, PuppetDB, facts, and "
                "compiler-side extensions."
            )
            address = "puppet.effective_project"
        changes.append(_change(address, "project_boundary", "review", boundary))
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"puppet_project_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_puppet_project(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")
    summary = PlanSummary(
        path=Path("puppet-project://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Puppet project")
    gate["adapter"] = "puppet-project"
    gate["artifact_type"] = data["puppet_project"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
