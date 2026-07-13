from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class CueInputError(ValueError):
    """Raised when text is not recognizable CUE source."""


_SOURCE_MARKER = re.compile(
    r"(?m)^\s*(?:package\s+[A-Za-z_]\w*|import\s|(?:[A-Za-z_#][\w#-]*|\"[^\"]+\")[!?]?\s*:)"
)
_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)", re.I
)
_IMPORT_SINGLE = re.compile(r'(?m)^\s*import\s+(?:[A-Za-z_]\w*\s+)?"(?P<path>[^"\r\n]+)"')
_IMPORT_BLOCK = re.compile(r"(?ms)^\s*import\s*\((?P<body>.*?)^\s*\)")
_QUOTED_IMPORT = re.compile(r'(?:[A-Za-z_]\w*\s+)?"(?P<path>[^"\r\n]+)"')
_TOOL_TASK = re.compile(
    r"\b(?P<alias>exec|file|http|cli|os)\.(?P<task>[A-Z][A-Za-z0-9_]*)\b"
    r'|\$id\s*:\s*"tool/(?P<idpkg>exec|file|http|cli|os)\.(?P<idtask>[A-Za-z0-9_]+)"'
)
_FIELD = re.compile(r"(?m)^\s*(?P<name>[A-Za-z_#][\w#-]*|\"[^\"]+\")[!?]?\s*:")
_URL = re.compile(r'https?://[^\s"\']+', re.I)
_PATH_FIELD = re.compile(
    r'(?m)^\s*(?:filename|path|dir|glob|contentsFile)\s*:\s*"(?P<path>[^"\r\n]+)"'
)
_VERSION = re.compile(r"^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


def _change(line: int, kind: str, risk: str, explanation: str) -> dict[str, Any]:
    return {
        "Address": f"line[{line}].{kind}",
        "Kind": kind,
        "Risk": risk,
        "Explanation": explanation,
    }


def _line(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _external_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return path.is_absolute() or ".." in path.parts or bool(re.match(r"^[A-Za-z]:/", normalized))


def _imports(source: str) -> list[tuple[str, int]]:
    imports = [
        (match.group("path"), _line(source, match.start()))
        for match in _IMPORT_SINGLE.finditer(source)
    ]
    for block in _IMPORT_BLOCK.finditer(source):
        body = block.group("body")
        body_offset = block.start("body")
        imports.extend(
            (match.group("path"), _line(source, body_offset + match.start()))
            for match in _QUOTED_IMPORT.finditer(body)
        )
    return imports


def _tool_aliases(source: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    pattern = re.compile(
        r'(?m)^\s*(?:(?P<alias>[A-Za-z_]\w*)\s+)?"tool/(?P<package>exec|file|http|cli|os)"'
    )
    for match in pattern.finditer(source):
        package = match.group("package")
        aliases[match.group("alias") or package] = package
    return aliases


def _artifact_type(filename: str) -> str:
    name = Path(filename).name.lower()
    if name == "module.cue":
        return "module"
    if name == "local-module.cue":
        return "local-module"
    if name.endswith("_tool.cue"):
        return "tool"
    return "source"


def parse_cue(source: str, filename: str = "config.cue") -> dict[str, Any]:
    """Conservatively scan CUE source without evaluation or module loading."""
    if not source.strip():
        raise CueInputError("input is empty")
    if not filename.lower().endswith(".cue"):
        raise CueInputError("CUE input filename must end in .cue")
    if not _SOURCE_MARKER.search(source):
        raise CueInputError("no recognizable CUE package, import, or fields were found")
    return {
        "cue": {
            "artifact_type": _artifact_type(filename),
            "filename": Path(filename).name,
            "source": source,
        }
    }


def _import_changes(source: str, artifact_type: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for path, line in _imports(source):
        if path.startswith("tool/"):
            package = path.split("/", 1)[1].split(":", 1)[0]
            risk = "dangerous" if package in {"exec", "file", "http", "os"} else "review"
            changes.append(
                _change(
                    line,
                    "workflow_capability_import",
                    risk,
                    f"CUE imports the tool/{package} workflow capability; tasks can perform "
                    "stateful operations when invoked with cue cmd.",
                )
            )
            continue
        if "." not in path.split("/", 1)[0]:
            continue
        module_path = path.split(":", 1)[0]
        versioned = bool(re.search(r"@v\d+(?:/|$)", module_path))
        changes.append(
            _change(
                line,
                "module_import",
                "review" if versioned else "dangerous",
                "CUE imports an external module package; review OCI registry mapping, exact module "
                "version/build list, credentials, cached content, source provenance, and "
                "transitive dependencies.",
            )
        )
    if artifact_type == "tool" and not any(
        path.startswith("tool/") for path, _ in _imports(source)
    ):
        changes.append(
            _change(
                1,
                "dynamic_workflow_capability",
                "review",
                "CUE tool file has no directly recognized tool imports; task capabilities may be "
                "provided through package unification or external modules.",
            )
        )
    return changes


def _task_changes(source: str, artifact_type: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    if artifact_type != "tool" and "command:" not in source:
        return changes
    if re.search(r"(?m)^\s*command\s*:", source):
        changes.append(
            _change(
                1,
                "workflow_command",
                "dangerous",
                "CUE tool file defines commands whose tasks execute only when invoked by cue cmd; "
                "review task graph, injected tags, ordering, inputs, outputs, and failure "
                "behavior.",
            )
        )
    seen: set[tuple[int, str, str]] = set()
    matches: list[tuple[re.Match[str], str, str]] = []
    for match in _TOOL_TASK.finditer(source):
        package = match.group("alias") or match.group("idpkg") or "unknown"
        task = match.group("task") or match.group("idtask") or "unknown"
        matches.append((match, package, task))
    for alias, package in _tool_aliases(source).items():
        if alias == package:
            continue
        alias_pattern = re.compile(rf"\b{re.escape(alias)}\.(?P<task>[A-Z][A-Za-z0-9_]*)\b")
        matches.extend(
            (match, package, match.group("task")) for match in alias_pattern.finditer(source)
        )
    for match, package, task in matches:
        line = _line(source, match.start())
        key = (line, package, task)
        if key in seen:
            continue
        seen.add(key)
        if package == "exec":
            kind = "process_task"
            risk = "dangerous"
            explanation = (
                "CUE workflow executes a host process; review command, directory, environment, "
                "stdio, credentials, network/filesystem access, and mustSucceed behavior."
            )
        elif package == "file":
            mutating = task.lower() not in {"read", "glob", "stat"}
            kind = "file_mutation_task" if mutating else "file_read_task"
            risk = "dangerous" if mutating else "review"
            explanation = (
                "CUE workflow mutates host filesystem content; review paths, permissions, "
                "overwrite/removal scope, generated data, and symlink boundaries."
                if mutating
                else "CUE workflow reads host filesystem content; review path confinement, "
                "sensitive data, glob scope, and downstream use."
            )
        elif package == "http":
            kind = "http_task"
            risk = "dangerous"
            explanation = (
                "CUE workflow performs an HTTP request; review endpoint/TLS, method, headers, "
                "authentication, request body, response trust, redirects, and side effects."
            )
        elif package == "os":
            kind = "os_state_task"
            risk = "review"
            explanation = (
                "CUE workflow reads operating-system state; review environment and host dependency."
            )
        else:
            kind = "interactive_task"
            risk = "review"
            explanation = (
                "CUE workflow interacts with the terminal; review injected or disclosed values "
                "and unattended execution behavior."
            )
        changes.append(_change(line, kind, risk, explanation))
    if re.search(r"(?m)^\s*mustSucceed\s*:\s*false\b", source):
        changes.append(
            _change(
                _line(source, re.search(r"(?m)^\s*mustSucceed\s*:\s*false\b", source).start()),  # type: ignore[union-attr]
                "fail_open_process",
                "dangerous",
                "CUE process task permits command failure and can allow later workflow tasks "
                "to run.",
            )
        )
    return changes


def _module_changes(source: str, artifact_type: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    if artifact_type not in {"module", "local-module"}:
        return changes
    module = re.search(r'(?m)^\s*module\s*:\s*"(?P<value>[^"\r\n]+)"', source)
    if artifact_type == "module":
        changes.append(
            _change(
                _line(source, module.start()) if module else 1,
                "module_identity",
                "review" if module and re.search(r"@v\d+$", module.group("value")) else "dangerous",
                "CUE module identity controls package namespace and OCI resolution; verify the "
                "domain-qualified path and explicit major version.",
            )
        )
        language = re.search(
            r'(?m)^\s*(?:language\s*:\s*)?version\s*:\s*"(?P<value>v[^"\r\n]+)"', source
        )
        if not language:
            changes.append(
                _change(
                    1,
                    "language_version",
                    "dangerous",
                    "CUE module does not visibly pin its minimum language version.",
                )
            )
    for match in re.finditer(r'(?m)^\s*v\s*:\s*"(?P<value>[^"\r\n]+)"', source):
        version = match.group("value")
        changes.append(
            _change(
                _line(source, match.start()),
                "module_dependency",
                "review" if _VERSION.fullmatch(version) else "dangerous",
                "CUE module declares an OCI dependency; verify canonical version, registry "
                "mapping, source provenance, credentials, and transitive build-list selection.",
            )
        )
    for match in re.finditer(r'(?m)^\s*replaceWith\s*:\s*"(?P<value>[^"\r\n]+)"', source):
        replacement = match.group("value")
        local = _external_path(replacement) or replacement.startswith(".")
        pinned = bool(re.search(r"@v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$", replacement))
        changes.append(
            _change(
                _line(source, match.start()),
                "module_replacement",
                "dangerous" if local or not pinned else "review",
                "CUE local-module metadata replaces a dependency with a local directory or "
                "alternate module; review confinement, unpublished code, exact version, and "
                "source ownership.",
            )
        )
    if re.search(r'(?m)^\s*kind\s*:\s*"git"', source):
        changes.append(
            _change(
                1,
                "module_source",
                "review",
                "CUE module declares Git as its source of truth; verify repository identity, "
                "subdirectory, commit/tag mapping, and published archive contents.",
            )
        )
    changes.append(
        _change(
            1,
            "registry_resolution_boundary",
            "review",
            "Static analysis does not resolve CUE_REGISTRY routing, authenticate, download OCI "
            "modules, inspect caches, compute the minimal-version build list, or follow replaces.",
        )
    )
    return changes


def _source_changes(source: str, artifact_type: str) -> list[dict[str, Any]]:
    changes = _import_changes(source, artifact_type)
    changes.extend(_task_changes(source, artifact_type))
    changes.extend(_module_changes(source, artifact_type))
    for match in _FIELD.finditer(source):
        name = match.group("name").strip('"')
        if _SECRET.search(name):
            line_end = source.find("\n", match.end())
            field_text = source[match.end() : line_end if line_end >= 0 else len(source)]
            if field_text.strip() and not re.match(
                r"\s*(?:string|bytes|null|_)\s*(?://.*)?$", field_text
            ):
                reference = bool(re.search(r"@tag\(|\b(?:string|bytes)\b|\$", field_text))
                changes.append(
                    _change(
                        _line(source, match.start()),
                        "secret_reference" if reference else "literal_secret",
                        "review" if reference else "dangerous",
                        "CUE field references injected or constrained credential-like data."
                        if reference
                        else "CUE source embeds credential-like material; the value is omitted "
                        "from analysis output.",
                    )
                )
    for match in _PATH_FIELD.finditer(source):
        if _external_path(match.group("path")):
            changes.append(
                _change(
                    _line(source, match.start()),
                    "external_file_path",
                    "dangerous",
                    "CUE workflow file path is absolute or escapes the module/project boundary.",
                )
            )
    for match in _URL.finditer(source):
        changes.append(
            _change(
                _line(source, match.start()),
                "network_endpoint",
                "dangerous" if match.group(0).lower().startswith("http://") else "review",
                "CUE source references a network endpoint; verify TLS, identity, authentication, "
                "request side effects, and response provenance.",
            )
        )
    if "@embed(" in source:
        changes.append(
            _change(
                _line(source, source.index("@embed(")),
                "embedded_file",
                "review",
                "CUE embeds module filesystem content; review file matching, sensitive data, size, "
                "and published module archive boundaries.",
            )
        )
    if re.search(r"@(tag|if|extern)\(", source):
        changes.append(
            _change(
                1,
                "runtime_injection_or_constraint",
                "review",
                "CUE build selection or values depend on runtime tags, build constraints, or "
                "external interpretation.",
            )
        )
    if re.search(r"\bfor\s+\w+(?:\s*,\s*\w+)?\s+in\b|\bif\s+[^\n{]+\{", source):
        changes.append(
            _change(
                1,
                "generated_configuration",
                "review",
                "CUE comprehensions or conditional fields generate effective configuration only "
                "during evaluation and unification.",
            )
        )
    changes.append(
        _change(
            1,
            "evaluation_boundary",
            "review",
            "Static analysis does not parse/evaluate/unify CUE packages, resolve defaults or "
            "constraints, inject tags/data, execute workflow tasks, read/write files, call HTTP "
            "services, run processes, or export generated infrastructure data.",
        )
    )
    return changes


class CueAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "cue"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("cue")
        return (
            isinstance(payload, dict)
            and payload.get("artifact_type") in {"source", "tool", "module", "local-module"}
            and isinstance(payload.get("source"), str)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["cue"]
        return _source_changes(payload["source"], payload["artifact_type"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"cue_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_cue(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = CueAdapter().analyze(data, tool_name="CUE")
    summary = PlanSummary(
        path=Path("cue://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="CUE")
    gate["adapter"] = "cue"
    gate["artifact_type"] = data["cue"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
