from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class ChefProjectInputError(ValueError):
    """Raised when input is not recognizable static Chef project configuration."""


_CALL = re.compile(r"^\s*(?P<name>[a-z_][a-z0-9_]*)\s*(?P<args>.*?)\s*$", re.IGNORECASE)
_SYMBOL = re.compile(r":(?P<value>[a-z_][a-z0-9_]*)", re.IGNORECASE)
_OPTION_KEY = re.compile(r"(?P<key>[a-z_][a-z0-9_]*)\s*:\s*", re.IGNORECASE)
_ATTRIBUTE = re.compile(
    r"^\s*(?P<kind>default|override)(?P<path>(?:\s*\[[^\]]+\])+?)\s*=\s*(?P<value>.+?)\s*$"
)
_ATTRIBUTE_KEY = re.compile(r"\[\s*(['\"]|:)(?P<key>[A-Za-z0-9_.-]+)(?:\1)?\s*\]")
_EXACT_VERSION = re.compile(r"(?:=\s*)?v?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?$")
_COMMIT = re.compile(r"[0-9a-f]{40,64}$", re.IGNORECASE)
_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|client.?secret|api.?key|credential)",
    re.IGNORECASE,
)
_RUBY_EXECUTION = re.compile(
    r"(?:^|\W)(?:eval|exec|spawn|system|require|load|from_file|instance_eval|class_eval|"
    r"module_eval|IO\.popen|Open3\.)\s*(?:\(|['\"])"
    r"|`[^`]+`|%x\s*\W"
)
_RUBY_DYNAMIC = re.compile(
    r"(?:ENV\s*\[|File\.|Dir\.|\#\{|\.each\b|\bif\b|\bunless\b|\bcase\b|\bbegin\b)"
)
_POLICY_CALLS = {
    "cookbook",
    "default_source",
    "include_policy",
    "name",
    "named_run_list",
    "run_list",
}
_METADATA_CALLS = {
    "chef_version",
    "depends",
    "description",
    "gem",
    "issues_url",
    "license",
    "maintainer",
    "maintainer_email",
    "name",
    "ohai_version",
    "privacy",
    "source_url",
    "supports",
    "version",
}
_BERKS_CALLS = {"cookbook", "metadata", "site", "solver", "source"}
_BERKS_ENTRY = re.compile(
    r"^  (?P<name>[A-Za-z0-9_.-]+)(?: \((?P<constraint>[^()]*)\))?$"
)
_BERKS_NESTED = re.compile(
    r"^    (?P<name>[A-Za-z0-9_.-]+)(?: \((?P<constraint>[^()]*)\))?$"
)
_BERKS_OPTION = re.compile(r"^    (?P<key>[A-Za-z_][A-Za-z0-9_-]*): (?P<value>.+)$")
_CONFIG_INDEXED = re.compile(
    r"^\s*(?P<scope>[A-Za-z_][A-Za-z0-9_:]*)\s*\[\s*"
    r"(?::(?P<symbol>[A-Za-z_][A-Za-z0-9_.-]*)|"
    r"(?P<quote>['\"])(?P<quoted>[A-Za-z_][A-Za-z0-9_.-]*)(?P=quote))"
    r"\s*\]\s*=\s*(?P<value>.+?)\s*$"
)
_CONFIG_SETTING = re.compile(
    r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*(?:(?:::|\.)[A-Za-z_][A-Za-z0-9_]*)*)"
    r"(?:\s*=\s*|\s+)(?P<value>.+?)\s*$"
)
_CONFIG_FILENAMES = {
    "client.rb": "client_config",
    "config.rb": "workstation_config",
    "knife.rb": "workstation_config",
    "solo.rb": "solo_config",
    "chef-server.rb": "server_config",
}
_SECRET_PATH_SETTINGS = {
    "client_key",
    "encrypted_data_bag_secret",
    "secret_file",
    "ssl_certificate_key",
    "ssl_client_key",
    "validation_key",
}
_PATH_SETTINGS = {
    "chef_repo_path",
    "client_d_dir",
    "cookbook_path",
    "data_bag_path",
    "environment_path",
    "file_backup_path",
    "file_cache_path",
    "json_attribs",
    "lockfile",
    "node_path",
    "role_path",
    "sandbox_path",
    "syntax_check_cache_path",
    "trusted_certs_dir",
}
_MAX_CONFIG_STATEMENT = 1_000_000


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ChefProjectInputError(f"duplicate JSON key: {key}")
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
            options[match.group("key").lower()] = parsed[0]
    return options


def _is_quoted_literal(value: str) -> bool:
    parsed = _read_quoted(value, 0)
    return parsed is not None and not value[parsed[1] :].strip()


def _parse_ruby(source: str) -> dict[str, Any]:
    calls: list[dict[str, Any]] = []
    attributes: list[dict[str, str]] = []
    dynamic: list[dict[str, Any]] = []
    for line_number, original in enumerate(source.splitlines(), start=1):
        line = _strip_comment(original).strip()
        if not line:
            continue
        attribute = _ATTRIBUTE.match(line)
        if attribute:
            keys = [
                match.group("key") for match in _ATTRIBUTE_KEY.finditer(attribute.group("path"))
            ]
            attributes.append(
                {
                    "kind": attribute.group("kind"),
                    "path": ".".join(keys) or attribute.group("path"),
                    "value": attribute.group("value"),
                    "line": str(line_number),
                }
            )
            value = attribute.group("value")
            if _RUBY_EXECUTION.search(value) or _RUBY_DYNAMIC.search(value):
                dynamic.append({"line": line_number, "source": value})
            continue
        match = _CALL.match(line)
        if not match:
            dynamic.append({"line": line_number, "source": line})
            continue
        name = match.group("name").lower()
        args = match.group("args")
        if name in _POLICY_CALLS | _METADATA_CALLS:
            calls.append(
                {
                    "name": name,
                    "args": args,
                    "values": _quoted_values(args),
                    "symbols": [item.group("value") for item in _SYMBOL.finditer(args)],
                    "options": _options(args),
                    "line": line_number,
                }
            )
            if (
                _RUBY_EXECUTION.search(args)
                or _RUBY_DYNAMIC.search(args)
                or _contains_unquoted(args, ";")
            ):
                dynamic.append({"line": line_number, "source": args})
        else:
            dynamic.append({"line": line_number, "source": line})
    policy_markers = {call["name"] for call in calls} & {
        "cookbook",
        "default_source",
        "include_policy",
        "named_run_list",
        "run_list",
    }
    metadata_markers = {call["name"] for call in calls} & {
        "chef_version",
        "depends",
        "gem",
        "ohai_version",
        "privacy",
        "supports",
    }
    call_names = {call["name"] for call in calls}
    metadata_shape = {"name", "version"} <= call_names and bool(
        call_names
        & {"description", "issues_url", "license", "maintainer", "maintainer_email", "source_url"}
    )
    if policy_markers and metadata_markers:
        raise ChefProjectInputError("input mixes Policyfile.rb and metadata.rb directives")
    if policy_markers:
        artifact_type = "policyfile"
    elif metadata_markers or metadata_shape:
        artifact_type = "metadata"
    else:
        raise ChefProjectInputError("input is not a recognized Policyfile.rb or metadata.rb")
    return {
        "artifact_type": artifact_type,
        "document": {"calls": calls, "attributes": attributes, "dynamic": dynamic},
    }


def _ruby_argument_parts(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
            continue
        if quote is not None:
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _berks_options(parts: list[str]) -> dict[str, str]:
    options: dict[str, str] = {}
    for part in parts:
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)", part, re.DOTALL)
        if not match:
            continue
        key = match.group(1).casefold()
        if key in options:
            raise ChefProjectInputError(f"duplicate Berksfile option: {key}")
        value = match.group(2).strip()
        quoted = _read_quoted(value, 0)
        if quoted is not None and not value[quoted[1] :].strip():
            options[key] = quoted[0]
            continue
        symbol = re.fullmatch(r":([A-Za-z_][A-Za-z0-9_.-]*)", value)
        if symbol:
            options[key] = symbol.group(1)
    return options


def _parse_berksfile(source: str) -> dict[str, Any]:
    calls: list[dict[str, Any]] = []
    dynamic: list[dict[str, Any]] = []
    groups: list[tuple[str, ...]] = []
    for line_number, original in enumerate(source.splitlines(), start=1):
        line = _strip_comment(original).strip()
        if not line:
            continue
        group = re.fullmatch(r"group\s+(.+?)\s+do", line, re.IGNORECASE)
        if group:
            names = [*_quoted_values(group.group(1))]
            names.extend(match.group("value") for match in _SYMBOL.finditer(group.group(1)))
            if not names:
                dynamic.append({"line": line_number, "source": line})
                groups.append(("<dynamic>",))
            else:
                groups.append(tuple(names))
            continue
        if line.casefold() == "end":
            if not groups:
                raise ChefProjectInputError(f"Berksfile has unmatched end at line {line_number}")
            groups.pop()
            continue
        match = _CALL.match(line)
        if not match or match.group("name").casefold() not in _BERKS_CALLS:
            dynamic.append({"line": line_number, "source": line})
            continue
        name = match.group("name").casefold()
        args = match.group("args")
        parts = _ruby_argument_parts(args)
        positionals: list[str] = []
        for part in parts:
            if re.match(r"[A-Za-z_][A-Za-z0-9_]*\s*:", part):
                break
            quoted = _read_quoted(part, 0)
            if quoted is not None and not part[quoted[1] :].strip():
                positionals.append(quoted[0])
        calls.append(
            {
                "name": name,
                "args": args,
                "values": _quoted_values(args),
                "positionals": positionals,
                "symbols": [item.group("value") for item in _SYMBOL.finditer(args)],
                "options": _berks_options(parts),
                "groups": tuple(name for frame in groups for name in frame),
                "line": line_number,
            }
        )
        if (
            _RUBY_EXECUTION.search(args)
            or _RUBY_DYNAMIC.search(args)
            or _contains_unquoted(args, ";")
        ):
            dynamic.append({"line": line_number, "source": args})
    if groups:
        raise ChefProjectInputError("Berksfile contains an unterminated group block")
    if not calls or not {call["name"] for call in calls} & {"cookbook", "metadata", "source"}:
        raise ChefProjectInputError("input is not a recognized Berksfile")
    return {
        "artifact_type": "berksfile",
        "document": {"calls": calls, "dynamic": dynamic},
    }


def _parse_legacy_berks_lock(source: str) -> dict[str, Any]:
    try:
        document = json.loads(source, object_pairs_hook=_unique_object)
    except ChefProjectInputError:
        raise
    except json.JSONDecodeError as exc:
        raise ChefProjectInputError(str(exc)) from exc
    dependencies = document.get("dependencies") if isinstance(document, dict) else None
    if not isinstance(dependencies, dict):
        raise ChefProjectInputError("legacy Berksfile lock must contain a dependencies object")
    direct: list[dict[str, Any]] = []
    graph: list[dict[str, Any]] = []
    for name, details in dependencies.items():
        if not isinstance(name, str) or not isinstance(details, dict):
            raise ChefProjectInputError("legacy Berksfile dependencies must be named objects")
        version = str(details.get("locked_version", "")).strip()
        options = {
            str(key): str(value)
            for key, value in details.items()
            if key != "locked_version" and isinstance(value, (str, int, float, bool))
        }
        direct.append({"name": name, "constraint": ">= 0.0.0", "options": options})
        graph.append({"name": name, "version": version, "dependencies": []})
    return {
        "artifact_type": "berks_lock",
        "document": {"direct": direct, "graph": graph, "legacy_format": True},
    }


def _parse_berks_lock(source: str) -> dict[str, Any]:
    if source.lstrip().startswith("{"):
        return _parse_legacy_berks_lock(source)
    direct: list[dict[str, Any]] = []
    graph: list[dict[str, Any]] = []
    direct_names: set[str] = set()
    graph_names: set[str] = set()
    sections: set[str] = set()
    state = ""
    current_direct: dict[str, Any] | None = None
    current_graph: dict[str, Any] | None = None
    for line_number, raw in enumerate(source.splitlines(), start=1):
        if not raw.strip():
            continue
        if raw in {"DEPENDENCIES", "GRAPH"}:
            if raw in sections:
                raise ChefProjectInputError(f"duplicate Berksfile lock section: {raw}")
            sections.add(raw)
            state = raw
            current_direct = None
            current_graph = None
            continue
        if not state:
            raise ChefProjectInputError(
                f"Berksfile lock content precedes a section at line {line_number}"
            )
        if state == "DEPENDENCIES":
            option = _BERKS_OPTION.fullmatch(raw)
            if option:
                if current_direct is None:
                    raise ChefProjectInputError(
                        f"Berksfile lock option has no dependency at line {line_number}"
                    )
                key = option.group("key").casefold()
                if key in current_direct["options"]:
                    raise ChefProjectInputError(
                        f"duplicate Berksfile lock option at line {line_number}"
                    )
                current_direct["options"][key] = option.group("value")
                continue
            entry = _BERKS_ENTRY.fullmatch(raw)
            if not entry:
                raise ChefProjectInputError(
                    f"invalid Berksfile lock dependency at line {line_number}"
                )
            name = entry.group("name")
            if name in direct_names:
                raise ChefProjectInputError(f"duplicate Berksfile dependency: {name}")
            direct_names.add(name)
            current_direct = {
                "name": name,
                "constraint": entry.group("constraint") or "",
                "options": {},
            }
            direct.append(current_direct)
            continue
        nested = _BERKS_NESTED.fullmatch(raw)
        if nested:
            if current_graph is None:
                raise ChefProjectInputError(
                    f"Berksfile lock graph edge has no parent at line {line_number}"
                )
            current_graph["dependencies"].append(
                {
                    "name": nested.group("name"),
                    "constraint": nested.group("constraint") or "",
                }
            )
            dependency_names = [item["name"] for item in current_graph["dependencies"]]
            if len(dependency_names) != len(set(dependency_names)):
                raise ChefProjectInputError(
                    f"duplicate Berksfile graph dependency at line {line_number}"
                )
            continue
        entry = _BERKS_ENTRY.fullmatch(raw)
        if not entry or entry.group("constraint") is None:
            raise ChefProjectInputError(f"invalid Berksfile lock graph at line {line_number}")
        name = entry.group("name")
        if name in graph_names:
            raise ChefProjectInputError(f"duplicate Berksfile graph entry: {name}")
        graph_names.add(name)
        current_graph = {
            "name": name,
            "version": entry.group("constraint"),
            "dependencies": [],
        }
        graph.append(current_graph)
    if sections != {"DEPENDENCIES", "GRAPH"}:
        raise ChefProjectInputError("Berksfile lock must contain DEPENDENCIES and GRAPH sections")
    return {
        "artifact_type": "berks_lock",
        "document": {"direct": direct, "graph": graph, "legacy_format": False},
    }


def _parse_lock(source: str) -> dict[str, Any] | None:
    if not source.lstrip().startswith("{"):
        return None
    try:
        document = json.loads(source, object_pairs_hook=_unique_object)
    except ChefProjectInputError:
        raise
    except json.JSONDecodeError as exc:
        raise ChefProjectInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise ChefProjectInputError("Policyfile lock must be a JSON object")
    markers = {"revision_id", "cookbook_locks", "solution_dependencies", "run_list"}
    if len(markers & set(document)) < 2:
        raise ChefProjectInputError("JSON is not recognized as a Policyfile.lock.json document")
    cookbook_locks = document.get("cookbook_locks", {})
    if not isinstance(cookbook_locks, dict):
        raise ChefProjectInputError("cookbook_locks must be a JSON object")
    for name, lock in cookbook_locks.items():
        if not isinstance(name, str) or not isinstance(lock, dict):
            raise ChefProjectInputError("each cookbook lock must be a named JSON object")
        if "source_options" in lock and not isinstance(lock["source_options"], dict):
            raise ChefProjectInputError(
                f"source_options for cookbook lock {name!r} must be a JSON object"
            )
    for key in ("run_list", "named_run_lists"):
        if key in document and not isinstance(document[key], (list, dict)):
            raise ChefProjectInputError(f"{key} must be a JSON list or object")
    return {"artifact_type": "lock", "document": document}


def _config_artifact_type(filename: str) -> str:
    normalized = filename.replace("\\", "/").casefold()
    path = Path(normalized)
    name = path.name
    if name in _CONFIG_FILENAMES:
        if name != "config.rb" or not filename or any(
            part in {".chef", "chef", "workstation"} for part in path.parts[:-1]
        ):
            return _CONFIG_FILENAMES[name]
        # An explicitly supplied config.rb is the documented Workstation/knife filename.
        return "workstation_config"
    for part, artifact_type in {
        "client.d": "client_config",
        "config.d": "workstation_config",
        "solo.d": "solo_config",
    }.items():
        if part in path.parts and name.endswith(".rb"):
            return artifact_type
    return ""


def _config_statements(source: str) -> list[tuple[int, str]]:
    statements: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 0
    depth = 0
    quote: str | None = None
    escaped = False
    length = 0
    for line_number, original in enumerate(source.splitlines(), start=1):
        line = _strip_comment(original).strip()
        if not line:
            continue
        if not buffer:
            start_line = line_number
        buffer.append(line)
        length += len(line)
        if length > _MAX_CONFIG_STATEMENT:
            raise ChefProjectInputError(
                f"Chef configuration statement exceeds {_MAX_CONFIG_STATEMENT} characters"
            )
        for char in line:
            if escaped:
                escaped = False
                continue
            if char == "\\" and quote:
                escaped = True
                continue
            if char in {"'", '"'}:
                quote = None if quote == char else char if quote is None else quote
                continue
            if quote is None:
                if char in "([{":
                    depth += 1
                elif char in ")]}" and depth > 0:
                    depth -= 1
        if quote is None and depth == 0 and not line.endswith("\\"):
            statements.append((start_line, " ".join(buffer)))
            buffer = []
            length = 0
    if buffer:
        statements.append((start_line, " ".join(buffer)))
    return statements


def _config_value(value: str) -> dict[str, Any]:
    value = value.strip()
    if (
        _RUBY_EXECUTION.search(value)
        or _RUBY_DYNAMIC.search(value)
        or re.search(r"#\{|<%|\$\{", value)
    ):
        return {"kind": "dynamic", "value": "", "raw": value}
    quoted = _read_quoted(value, 0)
    if quoted is not None and not value[quoted[1] :].strip():
        return {"kind": "string", "value": quoted[0], "raw": value}
    symbol = re.fullmatch(r":([A-Za-z_][A-Za-z0-9_.-]*)", value)
    if symbol:
        return {"kind": "symbol", "value": symbol.group(1), "raw": value}
    if value.casefold() in {"true", "false"}:
        return {"kind": "boolean", "value": value.casefold() == "true", "raw": value}
    if value.casefold() == "nil":
        return {"kind": "nil", "value": None, "raw": value}
    if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", value):
        return {"kind": "number", "value": value, "raw": value}
    if (value.startswith("[") and value.endswith("]")) or re.fullmatch(
        r"%w[({\[].*[)}\]]", value, re.DOTALL
    ):
        return {
            "kind": "array",
            "value": _quoted_values(value),
            "raw": value,
        }
    if re.fullmatch(r"[A-Z][A-Za-z0-9_:]*", value):
        return {"kind": "constant", "value": value, "raw": value}
    return {"kind": "dynamic", "value": "", "raw": value}


def _parse_runtime_config(source: str, artifact_type: str) -> dict[str, Any]:
    settings: list[dict[str, Any]] = []
    dynamic: list[dict[str, Any]] = []
    previous: dict[str, str] = {}
    for line_number, statement in _config_statements(source):
        if _RUBY_EXECUTION.search(statement) or _contains_unquoted(statement, ";"):
            dynamic.append({"line": line_number, "source": statement})
            continue
        indexed = _CONFIG_INDEXED.match(statement)
        if indexed:
            scope = indexed.group("scope").casefold()
            key = (indexed.group("symbol") or indexed.group("quoted")).casefold()
            canonical = key if scope == "chef::config" else f"{scope}.{key}"
            raw_value = indexed.group("value")
        else:
            direct = _CONFIG_SETTING.match(statement)
            if not direct:
                dynamic.append({"line": line_number, "source": statement})
                continue
            canonical = direct.group("name").replace("::", ".").casefold()
            raw_value = direct.group("value")
        parsed_value = _config_value(raw_value)
        prior = previous.get(canonical)
        setting = {
            "name": canonical,
            "line": line_number,
            "value": parsed_value,
            "duplicate": prior is not None,
            "conflicting": prior is not None and prior != parsed_value["raw"],
        }
        settings.append(setting)
        previous[canonical] = parsed_value["raw"]
        if parsed_value["kind"] == "dynamic":
            dynamic.append({"line": line_number, "source": parsed_value["raw"]})
    if not settings and not dynamic:
        raise ChefProjectInputError("Chef runtime configuration contains no settings")
    return {
        "artifact_type": artifact_type,
        "document": {"settings": settings, "dynamic": dynamic},
    }


def parse_chef_project(source: str, *, filename: str = "") -> dict[str, Any]:
    """Parse static Chef project/runtime files without executing Ruby."""
    if not source.strip():
        raise ChefProjectInputError("input is empty")
    basename = Path(filename.replace("\\", "/")).name.casefold() if filename else ""
    if basename == "berksfile":
        return {"chef_project": _parse_berksfile(source)}
    if basename == "berksfile.lock":
        return {"chef_project": _parse_berks_lock(source)}
    artifact_type = _config_artifact_type(filename)
    parsed = (
        _parse_runtime_config(source, artifact_type)
        if artifact_type
        else _parse_lock(source) or _parse_ruby(source)
    )
    return {"chef_project": parsed}


def _embedded_credential(value: str) -> bool:
    candidate = value.removeprefix("git+")
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    return bool(parsed.username or parsed.password)


def _source_risks(source: str, *, revision: str = "") -> tuple[str, list[str]]:
    risk = "review"
    reasons: list[str] = []
    lowered = source.lower()
    if lowered.startswith(("http://", "git://")):
        risk = "dangerous"
        reasons.append("It uses an unauthenticated plaintext transport.")
    if _embedded_credential(source):
        risk = "dangerous"
        reasons.append("The source URL embeds credentials that can leak in logs or metadata.")
    if source.startswith(("./", "../", "/", "file://", "git+file://")):
        reasons.append("It resolves executable cookbook content from the local filesystem.")
    if revision and not _COMMIT.fullmatch(revision):
        risk = "dangerous"
        reasons.append("Its Git revision is a mutable branch, tag, or abbreviated commit.")
    return risk, reasons


def _berks_location_risks(options: dict[str, str]) -> tuple[str, list[str]]:
    source_key = next((key for key in ("git", "github", "path") if key in options), "")
    source = options.get(source_key, "")
    revision_key = next(
        (key for key in ("revision", "ref", "commit", "tag", "branch") if key in options),
        "",
    )
    revision = options.get(revision_key, "")
    risk, reasons = _source_risks(source, revision=revision)
    if source_key in {"git", "github"} and not _COMMIT.fullmatch(revision):
        risk = "dangerous"
        reasons.append("The Git source is not pinned to a full immutable commit.")
    if revision_key in {"branch", "tag"}:
        risk = "dangerous"
        reasons.append("A branch or tag can resolve to different cookbook content over time.")
    if source_key == "path":
        reasons.append("The cookbook resolves local content outside this Berksfile.")
    if re.search(
        r"(?:^|[?&])(?:access.?key|api.?key|password|secret|token)=",
        source,
        re.IGNORECASE,
    ):
        risk = "dangerous"
        reasons.append("The source URL query embeds a secret-like credential.")
    if any(_SECRET.search(key) and value for key, value in options.items()):
        risk = "dangerous"
        reasons.append("A source option contains a literal secret-like value.")
    return risk, reasons


def _exact_version_value(value: str) -> str:
    text = value.strip()
    if not _EXACT_VERSION.fullmatch(text):
        return ""
    text = re.sub(r"^=\s*", "", text)
    return text.removeprefix("v")


def _berksfile_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes = [
        _change(
            "berksfile.workflow",
            "berkshelf_legacy_workflow",
            "review",
            "Chef classifies Berkshelf as a legacy dependency workflow and recommends migrating "
            "to Policyfiles for immutable resolution and promotion.",
        )
    ]
    calls = document["calls"]
    source_calls = [call for call in calls if call["name"] in {"site", "source"}]
    for index, call in enumerate(source_calls, start=1):
        endpoint = call["positionals"][0] if call["positionals"] else ""
        risk, reasons = _source_risks(endpoint)
        if not endpoint:
            risk = "dangerous"
            reasons.append("The source endpoint is not a static quoted value.")
        if call["name"] == "site":
            risk = "dangerous"
            reasons.append(
                "The obsolete site directive weakens compatibility and migration safety."
            )
        if re.search(
            r"(?:^|[?&])(?:access.?key|api.?key|password|secret|token)=",
            endpoint,
            re.IGNORECASE,
        ):
            risk = "dangerous"
            reasons.append("The source URL query embeds a secret-like credential.")
        changes.append(
            _change(
                f"berksfile.source.{index}",
                "berkshelf_source",
                risk,
                "Berkshelf searches this ordered cookbook source for executable dependencies. "
                + " ".join(reasons),
            )
        )
    if len(source_calls) > 1:
        changes.append(
            _change(
                "berksfile.source_order",
                "berkshelf_source_precedence",
                "review",
                "Berkshelf stops at the first source containing a suitable cookbook; review "
                "private/public source order and dependency-confusion exposure.",
            )
        )
    requires_default_source = any(
        call["name"] == "metadata"
        or (
            call["name"] == "cookbook"
            and not {"git", "github", "path"} & set(call["options"])
        )
        for call in calls
    )
    if not source_calls and requires_default_source:
        changes.append(
            _change(
                "berksfile.source",
                "berkshelf_missing_source",
                "dangerous",
                "Berksfile has dependencies that require an ordered cookbook source but declares "
                "none statically.",
            )
        )
    for call in calls:
        address = f"berksfile.line.{call['line']}"
        if call["name"] == "metadata":
            changes.append(
                _change(
                    address,
                    "berkshelf_metadata_dependency",
                    "review",
                    "Berkshelf imports dependencies from adjacent metadata.rb; its effective "
                    "constraints and dynamic Ruby behavior are outside this file.",
                )
            )
        elif call["name"] == "solver":
            changes.append(
                _change(
                    address,
                    "berkshelf_solver",
                    "review",
                    "Berksfile selects a dependency solver; review compatibility with the Chef "
                    "Server resolver and reproducibility across Workstation versions.",
                )
            )
        elif call["name"] == "cookbook":
            positionals = call["positionals"]
            version = positionals[1] if len(positionals) > 1 else ""
            options = call["options"]
            risk, reasons = _berks_location_risks(options)
            revision = next(
                (
                    options[key]
                    for key in ("revision", "ref", "commit")
                    if key in options
                ),
                "",
            )
            if not _EXACT_VERSION.fullmatch(version) and not _COMMIT.fullmatch(revision):
                risk = "dangerous"
                reasons.append(
                    "The cookbook is not pinned to one exact version or full Git commit."
                )
            groups = set(call["groups"])
            inline_group = options.get("group", "")
            if inline_group:
                groups.add(inline_group)
            if groups:
                reasons.append(
                    "Group selection can exclude this dependency from install, vendor, or upload."
                )
            changes.append(
                _change(
                    address,
                    "berkshelf_cookbook_dependency",
                    risk,
                    "Berkshelf installs executable cookbook content. " + " ".join(reasons),
                )
            )
    changes.extend(_dynamic_changes(document.get("dynamic", []), "Berksfile"))
    changes.append(
        _change(
            "berksfile.effective_resolution",
            "berkshelf_boundary",
            "review",
            "Effective resolution also depends on Berksfile.lock, adjacent metadata.rb, source "
            "indexes, transitive cookbook metadata, group flags, Workstation/Berkshelf versions, "
            "credentials, cache state, and runtime Ruby evaluation.",
        )
    )
    return changes


def _berks_lock_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = [
        _change(
            "berks_lock.workflow",
            "berkshelf_legacy_workflow",
            "review",
            "This lock belongs to the legacy Berkshelf workflow; plan migration to a Policyfile "
            "while preserving cookbook resolution and promotion behavior.",
        )
    ]
    if document.get("legacy_format"):
        changes.append(
            _change(
                "berks_lock.format",
                "berkshelf_legacy_lock_format",
                "dangerous",
                "The lock uses Berkshelf's obsolete JSON format, which upstream treats as "
                "untrustworthy and converts with a warning.",
            )
        )
    graph = document.get("graph", [])
    graph_by_name = {item["name"]: item for item in graph}
    for index, dependency in enumerate(document.get("direct", []), start=1):
        options = dependency.get("options", {})
        risk, reasons = _berks_location_risks(options)
        locked = graph_by_name.get(dependency["name"])
        if locked is None:
            risk = "dangerous"
            reasons.append("The direct dependency has no resolved graph entry.")
        elif not _EXACT_VERSION.fullmatch(str(locked.get("version", ""))):
            risk = "dangerous"
            reasons.append("The resolved version is missing or not an exact semantic version.")
        else:
            reasons.append("The dependency resolves to one exact cookbook version.")
            constraint = str(dependency.get("constraint", ""))
            if _exact_version_value(constraint) and _exact_version_value(
                constraint
            ) != _exact_version_value(str(locked.get("version", ""))):
                risk = "dangerous"
                reasons.append("The resolved version conflicts with the exact direct constraint.")
        changes.append(
            _change(
                f"berks_lock.direct.{index}",
                "berkshelf_direct_dependency",
                risk,
                "Berksfile.lock records a direct executable cookbook dependency. "
                + " ".join(reasons),
            )
        )
    graph_names = set(graph_by_name)
    for index, item in enumerate(graph, start=1):
        version = str(item.get("version", ""))
        missing = [
            dependency["name"]
            for dependency in item.get("dependencies", [])
            if dependency["name"] not in graph_names
        ]
        mismatched = [
            dependency["name"]
            for dependency in item.get("dependencies", [])
            if dependency["name"] in graph_by_name
            and _exact_version_value(str(dependency.get("constraint", "")))
            and _exact_version_value(str(dependency.get("constraint", "")))
            != _exact_version_value(str(graph_by_name[dependency["name"]].get("version", "")))
        ]
        risk = "review"
        reasons = ["The graph resolves executable cookbook content to a fixed version."]
        if not _EXACT_VERSION.fullmatch(version):
            risk = "dangerous"
            reasons = ["The graph entry has a missing or non-exact resolved version."]
        if missing:
            risk = "dangerous"
            reasons.append(
                f"The entry references {len(missing)} dependency graph node(s) that are absent."
            )
        if mismatched:
            risk = "dangerous"
            reasons.append(
                f"The entry has {len(mismatched)} exact dependency constraint(s) that conflict "
                "with resolved graph versions."
            )
        changes.append(
            _change(
                f"berks_lock.graph.{index}",
                "berkshelf_resolved_cookbook",
                risk,
                " ".join(reasons),
            )
        )
    changes.append(
        _change(
            "berks_lock.integrity_boundary",
            "berkshelf_lock_integrity_boundary",
            "review",
            "Berksfile.lock pins versions and graph edges but does not record cookbook content "
            "digests; source contents, cache integrity, deleted/replaced releases, metadata, and "
            "the manifest-to-lock freshness check remain external.",
        )
    )
    return changes


def _policy_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    calls = document["calls"]
    call_names = {call["name"] for call in calls}
    if "name" not in call_names:
        changes.append(
            _change(
                "policyfile.name",
                "missing_policy_name",
                "dangerous",
                "Policyfile.rb has no static policy name, so promotion identity is incomplete.",
            )
        )
    if "run_list" not in call_names:
        changes.append(
            _change(
                "policyfile.run_list",
                "missing_run_list",
                "dangerous",
                "Policyfile.rb has no static run_list defining the recipes applied to nodes.",
            )
        )
    for call in calls:
        name = call["name"]
        values = call["values"]
        address = f"policyfile.line.{call['line']}"
        if name in {"run_list", "named_run_list"}:
            changes.append(
                _change(
                    address,
                    "policy_run_list",
                    "review",
                    f"Chef policy selects {max(len(values), 1)} recipe/run-list item(s) to "
                    "converge on associated nodes.",
                )
            )
        elif name == "default_source":
            source_type = call["symbols"][0] if call["symbols"] else "dynamic"
            endpoint = values[0] if values else ""
            risk, reasons = _source_risks(endpoint)
            if (
                source_type == "dynamic"
                or not endpoint
                and source_type
                not in {
                    "chef_repo",
                    "chef_server",
                    "supermarket",
                }
            ):
                risk = "dangerous"
                reasons.append("The default cookbook source is dynamic or not statically resolved.")
            changes.append(
                _change(
                    address,
                    "default_cookbook_source",
                    risk,
                    f"Chef resolves unspecified cookbooks from {source_type!r}. "
                    + " ".join(reasons),
                )
            )
        elif name == "cookbook":
            cookbook = values[0] if values else "<dynamic>"
            version = values[1] if len(values) > 1 else ""
            options = call["options"]
            source_key = next(
                (key for key in ("git", "github", "path", "supermarket") if key in options),
                "",
            )
            source = options.get(source_key, "")
            revision = next(
                (
                    options[key]
                    for key in ("revision", "ref", "commit", "tag", "branch")
                    if key in options
                ),
                "",
            )
            risk, reasons = _source_risks(source, revision=revision)
            immutable_version = bool(version and _EXACT_VERSION.fullmatch(version))
            immutable_git = bool(revision and _COMMIT.fullmatch(revision))
            if not immutable_version and not immutable_git:
                risk = "dangerous"
                reasons.append("The cookbook is not pinned to an exact version or full Git commit.")
            if source_key == "github" and not revision:
                risk = "dangerous"
                reasons.append("The GitHub cookbook source has no immutable revision.")
            if source_key == "path":
                reasons.append("The cookbook resolves local project content outside this file.")
            changes.append(
                _change(
                    address,
                    "cookbook_dependency",
                    risk,
                    f"Chef policy installs executable cookbook {cookbook!r}. " + " ".join(reasons),
                )
            )
        elif name == "include_policy":
            policy = values[0] if values else "<dynamic>"
            options = call["options"]
            revision = next(
                (options[key] for key in ("revision", "ref", "commit") if key in options),
                "",
            )
            source = next((options[key] for key in ("git", "path", "remote") if key in options), "")
            risk, reasons = _source_risks(source, revision=revision)
            if "git" in options and not _COMMIT.fullmatch(revision):
                risk = "dangerous"
                reasons.append("The included policy Git source is not pinned to a full commit.")
            changes.append(
                _change(
                    address,
                    "included_policy",
                    risk,
                    f"Chef merges policy {policy!r} before this policy's run-list. "
                    + " ".join(reasons),
                )
            )
    changes.extend(_attribute_changes(document.get("attributes", []), "policyfile"))
    changes.extend(_dynamic_changes(document.get("dynamic", []), "Policyfile.rb"))
    return changes


def _metadata_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    call_names = {call["name"] for call in document["calls"]}
    for required in ("name", "version"):
        if required not in call_names:
            changes.append(
                _change(
                    f"metadata.{required}",
                    f"missing_cookbook_{required}",
                    "dangerous",
                    f"Cookbook metadata has no static {required}, so package identity is "
                    "incomplete.",
                )
            )
    for call in document["calls"]:
        name = call["name"]
        values = call["values"]
        address = f"metadata.line.{call['line']}"
        if name == "depends":
            cookbook = values[0] if values else "<dynamic>"
            constraint = values[1] if len(values) > 1 else ""
            exact = bool(constraint and _EXACT_VERSION.fullmatch(constraint))
            changes.append(
                _change(
                    address,
                    "cookbook_dependency",
                    "review" if exact else "dangerous",
                    f"Cookbook metadata depends on executable cookbook {cookbook!r}. "
                    + (
                        "The dependency uses an exact version constraint."
                        if exact
                        else "The dependency is unpinned or uses a mutable version range."
                    ),
                )
            )
        elif name == "gem":
            gem = values[0] if values else "<dynamic>"
            constraint = values[1] if len(values) > 1 else ""
            exact = bool(constraint and _EXACT_VERSION.fullmatch(constraint))
            changes.append(
                _change(
                    address,
                    "gem_dependency",
                    "review" if exact else "dangerous",
                    f"Chef installs Ruby gem {gem!r} before loading cookbook code. "
                    + (
                        "The gem uses an exact version constraint."
                        if exact
                        else "The gem is unpinned or uses a mutable version range."
                    ),
                )
            )
        elif name in {"chef_version", "ohai_version", "supports"}:
            changes.append(
                _change(
                    address,
                    "compatibility_constraint",
                    "review",
                    f"Cookbook metadata declares {name.replace('_', ' ')} compatibility; verify "
                    "the constraint matches every promoted node fleet.",
                )
            )
        elif name == "privacy" and re.search(r"\bfalse\b", call["args"], re.IGNORECASE):
            changes.append(
                _change(
                    address,
                    "public_cookbook_upload",
                    "dangerous",
                    "Cookbook privacy is disabled, allowing upload to a public Supermarket where "
                    "server policy permits it.",
                )
            )
        elif name in {"source_url", "issues_url"} and values:
            risk, reasons = _source_risks(values[0])
            if reasons:
                changes.append(
                    _change(
                        address,
                        "metadata_endpoint",
                        risk,
                        f"Cookbook metadata publishes {name.replace('_', ' ')} {values[0]!r}. "
                        + " ".join(reasons),
                    )
                )
    changes.extend(_dynamic_changes(document.get("dynamic", []), "metadata.rb"))
    return changes


def _attribute_changes(attributes: list[dict[str, str]], prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for attribute in attributes:
        path = attribute["path"]
        value = attribute["value"].strip()
        literal = bool(
            _is_quoted_literal(value) or re.fullmatch(r"[-+]?\d+(?:\.\d+)?|true|false|nil", value)
        )
        secret = bool(_SECRET.search(path))
        risk = "dangerous" if secret and literal else "review"
        explanation = (
            f"Chef {attribute['kind']} attribute {path!r} contains a literal secret-like value."
            if risk == "dangerous"
            else f"Chef {attribute['kind']} attribute {path!r} changes policy behavior on nodes."
        )
        changes.append(
            _change(
                f"{prefix}.attribute.{attribute['line']}",
                "secret_attribute" if secret else "policy_attribute",
                risk,
                explanation,
            )
        )
    return changes


def _dynamic_changes(dynamic: list[dict[str, Any]], artifact: str) -> list[dict[str, str]]:
    if not dynamic:
        return []
    execution = [item for item in dynamic if _RUBY_EXECUTION.search(str(item["source"]))]
    expression = [item for item in dynamic if _RUBY_DYNAMIC.search(str(item["source"]))]
    changes: list[dict[str, str]] = []
    if execution:
        changes.append(
            _change(
                f"{artifact}.line.{execution[0]['line']}",
                "ruby_execution",
                "dangerous",
                f"{artifact} contains Ruby process/code-loading behavior; Chef executes this file "
                "while resolving project configuration.",
            )
        )
    remaining = len(dynamic) - len(execution)
    if expression or remaining > 0:
        first = next((item for item in dynamic if item not in execution), dynamic[0])
        changes.append(
            _change(
                f"{artifact}.line.{first['line']}",
                "dynamic_ruby",
                "review",
                f"{artifact} contains {remaining or len(expression)} unexpanded Ruby "
                "expression(s); "
                "effective project configuration may differ at runtime.",
            )
        )
    return changes


def _lock_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    revision = str(document.get("revision_id", "")).strip()
    changes.append(
        _change(
            "policy_lock.revision_id",
            "policy_revision",
            "review" if revision else "dangerous",
            (
                "Policyfile lock records an immutable policy revision identifier."
                if revision
                else "Policyfile lock has no revision_id, weakening promotion identity."
            ),
        )
    )
    run_list = document.get("run_list", [])
    if run_list:
        changes.append(
            _change(
                "policy_lock.run_list",
                "policy_run_list",
                "review",
                f"Resolved Chef policy converges {len(run_list)} run-list item(s) on "
                "associated nodes.",
            )
        )
    locks = document.get("cookbook_locks", {})
    for name, lock in locks.items():
        identifier = str(lock.get("identifier", "")).strip()
        version = str(lock.get("version", "")).strip()
        source_options = lock.get("source_options", {})
        source_options = source_options if isinstance(source_options, dict) else {}
        source = str(
            source_options.get("git")
            or source_options.get("remote")
            or source_options.get("path")
            or ""
        )
        revision_value = str(source_options.get("revision") or source_options.get("commit") or "")
        risk, reasons = _source_risks(source, revision=revision_value)
        if not identifier:
            risk = "dangerous"
            reasons.append("The resolved cookbook has no content identifier.")
        if source_options.get("git") and not _COMMIT.fullmatch(revision_value):
            risk = "dangerous"
            reasons.append("The resolved Git cookbook is not pinned to a full commit.")
        changes.append(
            _change(
                f"policy_lock.cookbook.{name}",
                "resolved_cookbook",
                risk,
                f"Policyfile lock resolves executable cookbook {name!r} at version "
                f"{version or '<unknown>'!r} with content identifier "
                f"{identifier or '<missing>'!r}. " + " ".join(reasons),
            )
        )
    for kind in ("default_attributes", "override_attributes"):
        attributes = document.get(kind, {})
        if isinstance(attributes, dict) and attributes:
            secret_keys = [key for key in _walk_keys(attributes) if _SECRET.search(key)]
            changes.append(
                _change(
                    f"policy_lock.{kind}",
                    "secret_attribute" if secret_keys else "policy_attribute",
                    "dangerous" if secret_keys else "review",
                    (
                        f"Resolved policy {kind.replace('_', ' ')} contain secret-like key(s): "
                        + ", ".join(secret_keys[:3])
                        if secret_keys
                        else f"Resolved policy {kind.replace('_', ' ')} change node behavior."
                    ),
                )
            )
    return changes


def _walk_keys(value: Any, prefix: str = "") -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            keys.append(path)
            keys.extend(_walk_keys(child, path))
    elif isinstance(value, list):
        for child in value:
            keys.extend(_walk_keys(child, prefix))
    return keys


def _setting_text(setting: dict[str, Any]) -> str:
    value = setting["value"]
    scalar = value.get("value")
    if isinstance(scalar, bool):
        return "true" if scalar else "false"
    if scalar is None:
        return "nil"
    return str(scalar).casefold()


def _runtime_setting_change(
    setting: dict[str, Any], artifact_type: str
) -> dict[str, str]:
    name = str(setting["name"])
    key = name.rsplit(".", maxsplit=1)[-1]
    value = setting["value"]
    kind = str(value["kind"])
    text = _setting_text(setting)
    risk = "review"
    reasons: list[str] = []

    if setting["conflicting"]:
        risk = "dangerous"
        reasons.append("A later assignment overrides a different value in the same file.")
    elif setting["duplicate"]:
        reasons.append("The setting is assigned more than once in the same file.")

    if _SECRET.search(key) or key.endswith("_pass"):
        if key in _SECRET_PATH_SETTINGS:
            reasons.append("It selects a credential, key, certificate, or secret file boundary.")
        elif kind == "dynamic":
            reasons.append("Credential-bearing input is resolved dynamically at runtime.")
        else:
            risk = "dangerous"
            reasons.append("It contains literal credential or authentication material.")

    if key in _PATH_SETTINGS:
        reasons.append("It changes a filesystem input, cache, lock, or content boundary.")

    if kind == "string":
        raw_text = str(value["value"])
        try:
            endpoint = urlsplit(raw_text)
        except ValueError:
            endpoint = None
        if endpoint and endpoint.scheme:
            if endpoint.scheme.casefold() in {"http", "ftp", "git"}:
                risk = "dangerous"
                reasons.append("The endpoint uses plaintext or unauthenticated transport.")
            if endpoint.username or endpoint.password:
                risk = "dangerous"
                reasons.append("The endpoint embeds credentials that can leak in logs or metadata.")
        if key == "recipe_url":
            risk = "dangerous"
            reasons.append(
                "Chef Solo downloads executable cookbook content without an integrity pin in "
                "this configuration."
            )

    if key == "ssl_verify_mode":
        if text == "verify_none":
            risk = "dangerous"
            reasons.append("TLS certificate verification is disabled for HTTPS requests.")
        else:
            reasons.append("It controls certificate verification for Chef and content requests.")
    elif key == "verify_api_cert" and text == "false":
        reasons.append("Chef Server certificate checks delegate to the configured SSL verify mode.")
    elif name == "nginx.enable_non_ssl" and text == "true":
        risk = "dangerous"
        reasons.append("The Chef Server API accepts non-TLS traffic.")
    elif name == "postgresql.sslmode" and text == "disable":
        risk = "dangerous"
        reasons.append("Chef Server disables encryption for PostgreSQL connections.")
    elif name == "nginx.ssl_protocols" and re.search(
        r"(?:^|[,\s])TLSv1(?:\.0)?(?:[,\s]|$)|(?:^|[,\s])TLSv1\.1(?:[,\s]|$)",
        text,
        re.IGNORECASE,
    ):
        risk = "dangerous"
        reasons.append("Chef Server enables a legacy TLS protocol below TLS 1.2.")
    elif name == "nginx.ssl_ciphers":
        tokens = {item for item in re.split(r"[:\s]+", text.upper()) if item}
        enabled = {item for item in tokens if not item.startswith("!")}
        weak = {
            item
            for item in enabled
            if item in {"ANULL", "ENULL", "EXP", "LOW", "NULL", "SSLV2", "SSLV3"}
            or item.startswith(("3DES", "DES", "MD5", "RC4"))
        }
        if weak:
            risk = "dangerous"
            reasons.append("Chef Server explicitly permits a weak TLS cipher class.")
        else:
            reasons.append("It changes the accepted Chef Server TLS cipher policy.")

    if name == "insecure_addon_compat" and text == "true":
        risk = "dangerous"
        reasons.append("Compatibility mode writes secrets into additional configuration files.")
    if name == "required_recipe.enable" and text == "true":
        risk = "dangerous"
        reasons.append("Chef Server forces a recipe onto every connecting client run.")
    if key == "file_atomic_update" and text == "false":
        risk = "dangerous"
        reasons.append("Global atomic file updates are disabled, risking partial writes or loss.")
    if key == "data_bag_decrypt_minimum_version" and text in {"1", "2"}:
        risk = "dangerous"
        reasons.append("Encrypted data bags may use a legacy format below version 3.")
    if key == "strict_search_result_acls" and text == "false":
        risk = "dangerous"
        reasons.append("Strict ACL filtering for Chef Server search results is disabled.")
    if name == "knife.forward_agent" and text == "true":
        risk = "dangerous"
        reasons.append("Knife forwards the local SSH agent to remote bootstrap targets.")
    if name == "knife.yes" and text == "true":
        risk = "dangerous"
        reasons.append("Knife automatically confirms prompts, including destructive operations.")
    if name == "knife.bootstrap_version" and not text:
        risk = "dangerous"
        reasons.append("Bootstrap does not pin the Chef Infra Client version to install.")
    if key == "listen" and text == "true":
        risk = "dangerous"
        reasons.append("Chef Zero binds a local HTTP listener.")
    if key == "add_formatter":
        risk = "dangerous"
        reasons.append("Chef loads third-party Ruby formatter code during execution.")
    if key == "log_level" and text in {"debug", "trace"}:
        risk = "dangerous"
        reasons.append("Verbose debug logging can expose sensitive runtime data.")
    if key == "umask" and text in {"0", "0000"}:
        risk = "dangerous"
        reasons.append("The process umask permits world-writable files by default.")
    if key in {"chef_server_url", "data_collector.server_url", "server_url"}:
        reasons.append("It changes the remote Chef control-plane or reporting endpoint.")
    if key in {"node_name", "policy_group", "policy_name", "environment"}:
        reasons.append("It changes node identity or the policy scope selected for convergence.")
    if key in {"client_key", "validation_client_name", "validation_key"}:
        reasons.append("It changes Chef Server authentication or legacy bootstrap identity.")
    if key in {"local_mode", "solo", "use_policyfile"}:
        reasons.append("It changes how Chef resolves policy and whether it uses Chef Server.")
    if key in {"interval", "splay", "run_lock_timeout"}:
        reasons.append("It changes recurring convergence or run-lock behavior.")
    if key == "fips" and text == "false":
        reasons.append("FIPS cryptographic mode is explicitly disabled.")
    if not reasons:
        reasons.append("It changes effective Chef runtime behavior or service configuration.")

    label = artifact_type.replace("_", " ")
    return _change(
        f"chef_config.{artifact_type}.line.{setting['line']}.{name}",
        "runtime_setting",
        risk,
        f"Chef {label} setting {name!r} is explicitly configured. " + " ".join(reasons),
    )


def _runtime_config_changes(
    document: dict[str, Any], artifact_type: str
) -> list[dict[str, str]]:
    settings = document["settings"]
    changes = [_runtime_setting_change(setting, artifact_type) for setting in settings]
    effective = {str(setting["name"]): _setting_text(setting) for setting in settings}
    if artifact_type == "server_config" and any(
        key.startswith("ldap.") for key in effective
    ):
        encrypted = (
            effective.get("ldap.tls_enabled") == "true"
            or effective.get("ldap.ssl_enabled") == "true"
            or effective.get("ldap.encryption") in {"simple_tls", "start_tls"}
        )
        if effective.get("ldap.host") and not encrypted:
            changes.append(
                _change(
                    "chef_config.server_config.ldap_transport",
                    "ldap_transport",
                    "dangerous",
                    "Chef Server configures an LDAP identity endpoint without an explicit "
                    "TLS/SSL mode.",
                )
            )
    artifact_name = {
        "client_config": "client.rb",
        "workstation_config": "Workstation config.rb/knife.rb",
        "solo_config": "solo.rb",
        "server_config": "chef-server.rb",
    }[artifact_type]
    changes.extend(_dynamic_changes(document.get("dynamic", []), artifact_name))
    boundary = {
        "client_config": (
            "Effective Chef client behavior also depends on command-line flags, environment "
            "variables, merged client.d fragments, node/server policy, credentials, cookbook "
            "content, and runtime Ruby evaluation."
        ),
        "workstation_config": (
            "Effective Chef Workstation behavior also depends on command-line flags, credentials, "
            "knife plugins, merged config.d fragments, bootstrap templates, and runtime Ruby "
            "evaluation."
        ),
        "solo_config": (
            "Effective Chef Solo behavior also depends on command-line flags, local roles, data "
            "bags, environments, cookbook contents, downloaded archives, and runtime Ruby "
            "evaluation."
        ),
        "server_config": (
            "Effective Chef Server behavior also depends on built-in defaults, topology, external "
            "secrets, generated service configuration, installed add-ons, reconfigure state, and "
            "runtime Ruby conditions."
        ),
    }[artifact_type]
    changes.append(
        _change(
            f"chef_config.{artifact_type}.effective_configuration",
            "runtime_boundary",
            "review",
            boundary,
        )
    )
    return changes


class ChefProjectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "chef-project"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        project = input_data.get("chef_project")
        return (
            isinstance(project, dict)
            and project.get("artifact_type")
            in {
                "policyfile",
                "lock",
                "metadata",
                "berksfile",
                "berks_lock",
                "client_config",
                "workstation_config",
                "solo_config",
                "server_config",
            }
            and isinstance(project.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        project = input_data["chef_project"]
        artifact_type = project["artifact_type"]
        document = project["document"]
        if artifact_type.endswith("_config"):
            return _runtime_config_changes(document, artifact_type)
        if artifact_type == "berksfile":
            return _berksfile_changes(document)
        if artifact_type == "berks_lock":
            return _berks_lock_changes(document)
        changes = {
            "policyfile": _policy_changes,
            "lock": _lock_changes,
            "metadata": _metadata_changes,
        }[artifact_type](document)
        changes.append(
            _change(
                "chef.effective_project",
                "project_boundary",
                "review",
                "Effective Chef behavior also depends on the lock solution, cookbook contents, "
                "Chef Infra Server policy groups, node assignment, credentials, config.rb, "
                "environments, data bags, and runtime Ruby evaluation.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"chef_project_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_chef_project(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = ChefProjectAdapter().analyze(data, tool_name="Chef project")
    summary = PlanSummary(
        path=Path("chef-project://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Chef project")
    gate["adapter"] = "chef-project"
    project = data["chef_project"]
    gate["artifact_type"] = project["artifact_type"]
    if project["artifact_type"].endswith("_config"):
        gate["setting_count"] = len(project["document"]["settings"])
    if project["artifact_type"] == "berks_lock":
        gate["dependency_count"] = len(project["document"]["graph"])
    gate["total_changes"] = len(changes)
    return gate
