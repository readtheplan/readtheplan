from __future__ import annotations

import csv
import io
import json
import re
from datetime import date, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class InSpecInputError(ValueError):
    """Raised when input is not recognizable static Chef InSpec configuration."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=False)
        try:
            duplicate = key in seen
        except TypeError as exc:
            raise InSpecInputError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise InSpecInputError("duplicate YAML key")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)

_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_NODES = 50_000
_MAX_DEPTH = 64
_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|client.?secret|api.?key|credential)",
    re.IGNORECASE,
)
_COMMIT = re.compile(r"[0-9a-f]{40,64}$", re.IGNORECASE)
_SHA256 = re.compile(r"[0-9a-f]{64}$", re.IGNORECASE)
_EXACT_VERSION = re.compile(r"(?:=\s*)?v?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?$")
_RUBY_EXECUTION = re.compile(
    r"(?:^|\W)(?:eval|exec|spawn|system|load|require|instance_eval|class_eval|"
    r"module_eval)\s*(?:\(|['\"])|IO\.popen|Open3\.|`[^`]+`|%x\s*\W",
    re.IGNORECASE,
)
_RUBY_DYNAMIC = re.compile(
    r"(?:ENV\s*\[|File\.(?:read|open|foreach)|Dir\.|\#\{|\.send\s*\(|"
    r"const_get\s*\(|define_method\s*\()",
)
_CONTROL = re.compile(r"(?m)^\s*control\s+(?:\(|\s)*(['\"])(?:\\.|(?!\1).)*\1")
_PROFILE_INCLUDE = re.compile(r"(?m)^\s*(include_controls|require_controls|skip_control)\b")
_EXEC_RESOURCES = re.compile(
    r"(?m)^\s*describe(?:\.one)?\s+(?:\(|\s)*(command|powershell|bash|script)\s*\(?"
)
_REMOTE_RESOURCES = re.compile(
    r"(?m)^\s*describe(?:\.one)?\s+(?:\(|\s)*(http|ssl|aws_[a-z0-9_]+|"
    r"azure_[a-z0-9_]+|google_[a-z0-9_]+|gcp_[a-z0-9_]+)\s*\(?",
    re.IGNORECASE,
)


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InSpecInputError("duplicate JSON key")
        result[key] = value
    return result


def _validate_shape(value: Any, *, depth: int = 0, counter: list[int] | None = None) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > _MAX_NODES:
        raise InSpecInputError("document contains too many values")
    if depth > _MAX_DEPTH:
        raise InSpecInputError("document nesting is too deep")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, (str, int, float, bool)):
                raise InSpecInputError("mapping keys must be scalar values")
            _validate_shape(child, depth=depth + 1, counter=counter)
    elif isinstance(value, list):
        for child in value:
            _validate_shape(child, depth=depth + 1, counter=counter)


def _parse_yaml(source: str) -> Any:
    try:
        events = list(yaml.parse(source, Loader=yaml.SafeLoader))
    except yaml.YAMLError as exc:
        raise InSpecInputError(f"invalid YAML: {exc.problem or 'parse failure'}") from exc
    if any(isinstance(event, yaml.AliasEvent) for event in events):
        raise InSpecInputError("YAML aliases are not expanded by static analysis")
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except InSpecInputError:
        raise
    except yaml.YAMLError as exc:
        raise InSpecInputError(f"invalid YAML: {exc.problem or 'parse failure'}") from exc
    if len(documents) != 1:
        raise InSpecInputError("input must contain exactly one YAML document")
    document = documents[0]
    _validate_shape(document)
    return document


def _parse_json(source: str) -> Any:
    try:
        document = json.loads(source, object_pairs_hook=_unique_object)
    except InSpecInputError:
        raise
    except json.JSONDecodeError as exc:
        raise InSpecInputError(f"invalid JSON at line {exc.lineno}") from exc
    _validate_shape(document)
    return document


def _parse_csv_waivers(source: str) -> dict[str, dict[str, Any]]:
    try:
        reader = csv.DictReader(io.StringIO(source), strict=True)
        fields = reader.fieldnames
        if not fields or len(fields) != len(set(fields)):
            raise InSpecInputError("waiver CSV has missing or duplicate headers")
        required = {"control_id", "justification"}
        if not required.issubset(fields):
            raise InSpecInputError("waiver CSV must include control_id and justification")
        result: dict[str, dict[str, Any]] = {}
        for row_number, row in enumerate(reader, start=2):
            if None in row:
                raise InSpecInputError(f"waiver CSV row {row_number} has too many columns")
            control_id = str(row.get("control_id") or "").strip()
            if not control_id:
                raise InSpecInputError(f"waiver CSV row {row_number} has no control_id")
            if control_id in result:
                raise InSpecInputError("waiver CSV contains a duplicate control_id")
            result[control_id] = {
                key: value.strip() if isinstance(value, str) else value
                for key, value in row.items()
                if key != "control_id" and value not in (None, "")
            }
    except csv.Error as exc:
        raise InSpecInputError("invalid waiver CSV") from exc
    return result


def _mask_ruby_comments(source: str) -> str:
    """Blank Ruby comments while preserving strings and line positions."""
    output = list(source)
    state = "code"
    quote = ""
    index = 0
    while index < len(source):
        char = source[index]
        if state == "code":
            if char == "#":
                state = "comment"
                output[index] = " "
            elif char in {"'", '"'}:
                quote = char
                state = "string"
        elif state == "comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        else:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                state = "code"
        index += 1
    if state == "string":
        raise InSpecInputError("unterminated Ruby string")
    return "".join(output)


def _ruby_artifact(name: str, parts: tuple[str, ...], source: str) -> str:
    if "libraries" in parts[:-1]:
        return "library"
    if "controls" in parts[:-1] or _CONTROL.search(_mask_ruby_comments(source)):
        return "control"
    raise InSpecInputError("Ruby input is not recognized as an InSpec control or library")


def parse_inspec(source: str, *, filename: str = "inspec.yml") -> dict[str, Any]:
    """Parse one InSpec artifact without rendering ERB or executing Ruby."""
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise InSpecInputError("input exceeds the static-analysis size limit")
    if not source.strip():
        raise InSpecInputError("input is empty")
    normalized = filename.replace("\\", "/")
    path = PurePosixPath(normalized)
    name = path.name.casefold()
    parts = tuple(part.casefold() for part in path.parts)

    if name in {"inspec.yml", "inspec.yaml"}:
        dynamic_erb = "<%" in source or "%>" in source
        if dynamic_erb:
            sanitized = re.sub(r"<%.*?%>", "DYNAMIC_ERB", source, flags=re.DOTALL)
            try:
                document = _parse_yaml(sanitized)
            except InSpecInputError:
                document = {}
        else:
            document = _parse_yaml(source)
        if not isinstance(document, dict):
            raise InSpecInputError("inspec.yml must be a mapping")
        return {
            "inspec": {
                "artifact_type": "metadata",
                "document": document,
                "dynamic_erb": dynamic_erb,
            }
        }

    if name == "inspec.lock":
        document = _parse_yaml(source)
        if not isinstance(document, dict) or not ({"lockfile_version", "depends"} & set(document)):
            raise InSpecInputError("input is not recognized as an InSpec lockfile")
        return {"inspec": {"artifact_type": "lock", "document": document}}

    waiver_path = "waivers" in parts[:-1] or "waiver" in name
    if waiver_path and path.suffix.casefold() in {".yml", ".yaml", ".json", ".csv"}:
        if path.suffix.casefold() == ".json":
            document = _parse_json(source)
        elif path.suffix.casefold() == ".csv":
            document = _parse_csv_waivers(source)
        else:
            document = _parse_yaml(source)
        if not isinstance(document, dict):
            raise InSpecInputError("waiver input must contain a mapping of control IDs")
        return {"inspec": {"artifact_type": "waiver", "document": document}}

    if path.suffix.casefold() == ".rb":
        clean = _mask_ruby_comments(source)
        artifact_type = _ruby_artifact(name, parts, source)
        return {
            "inspec": {
                "artifact_type": artifact_type,
                "document": {"source": source, "clean": clean},
            }
        }
    raise InSpecInputError("input filename is not recognized as an InSpec artifact")


def _embedded_credential(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _metadata_changes(document: dict[str, Any], dynamic_erb: bool) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if dynamic_erb:
        changes.append(
            _change(
                "inspec.metadata.erb",
                "dynamic_metadata",
                "dangerous",
                "InSpec metadata embeds ERB; rendering can execute Ruby and replace fields that "
                "static analysis could not resolve.",
            )
        )
    if not isinstance(document.get("name"), str) or not str(document.get("name")).strip():
        changes.append(
            _change(
                "inspec.metadata.name",
                "missing_profile_name",
                "dangerous",
                "InSpec metadata has no static profile name, preventing reliable identity, "
                "dependency, and waiver matching.",
            )
        )
    constraint = document.get("inspec_version")
    if not isinstance(constraint, str) or not constraint.strip():
        changes.append(
            _change(
                "inspec.metadata.inspec_version",
                "unbounded_runtime",
                "review",
                "The profile does not constrain the Chef InSpec runtime; parser, resource, and "
                "execution behavior may change across installed versions.",
            )
        )

    supports = document.get("supports")
    if not isinstance(supports, list) or not supports:
        changes.append(
            _change(
                "inspec.metadata.supports",
                "unbounded_platform_scope",
                "dangerous",
                "The profile declares no supported platforms and can be selected for unintended "
                "targets or transports.",
            )
        )
    else:
        for index, support in enumerate(supports):
            if not isinstance(support, dict):
                changes.append(
                    _change(
                        f"inspec.metadata.supports[{index}]",
                        "invalid_platform_scope",
                        "dangerous",
                        "A platform scope is not a mapping and cannot be evaluated statically.",
                    )
                )
                continue
            values = " ".join(str(value) for value in support.values())
            legacy = bool({"os-name", "os-family"} & set(support))
            wildcard = "*" in values or not (
                {"platform", "platform-name", "platform-family", "os-name", "os-family"}
                & set(support)
            )
            changes.append(
                _change(
                    f"inspec.metadata.supports[{index}]",
                    "platform_scope",
                    "dangerous" if wildcard else "review",
                    "InSpec platform scope uses a wildcard or incomplete selector."
                    if wildcard
                    else (
                        "InSpec platform scope uses legacy OS selector keys; confirm current "
                        "platform matching."
                        if legacy
                        else "InSpec restricts this profile to a declared platform scope."
                    ),
                )
            )

    depends = document.get("depends", [])
    if depends not in (None, []) and not isinstance(depends, list):
        changes.append(
            _change(
                "inspec.metadata.depends",
                "invalid_dependencies",
                "dangerous",
                "InSpec dependencies are not a list and cannot be verified statically.",
            )
        )
    elif isinstance(depends, list):
        for index, dependency in enumerate(depends):
            address = f"inspec.metadata.depends[{index}]"
            if not isinstance(dependency, dict):
                changes.append(
                    _change(
                        address,
                        "invalid_dependency",
                        "dangerous",
                        "An InSpec dependency is not a mapping and cannot be resolved safely.",
                    )
                )
                continue
            sources = [
                key
                for key in ("path", "url", "git", "compliance", "supermarket", "gem")
                if dependency.get(key) not in (None, "")
            ]
            if len(sources) != 1:
                changes.append(
                    _change(
                        address,
                        "ambiguous_dependency_source",
                        "dangerous",
                        "An InSpec dependency must declare exactly one static source.",
                    )
                )
                continue
            source_key = sources[0]
            value = str(dependency[source_key])
            risk = "review"
            reasons = ["The profile imports controls or custom resources from another package."]
            if source_key == "path":
                candidate = PurePosixPath(value.replace("\\", "/"))
                if Path(value).is_absolute() or ".." in candidate.parts:
                    risk = "dangerous"
                    reasons.append("The local source escapes the profile boundary.")
                else:
                    reasons.append("Review repository ownership and vendored content.")
            elif source_key in {"url", "git"}:
                if value.casefold().startswith(("http://", "git://")):
                    risk = "dangerous"
                    reasons.append("The source uses plaintext or unauthenticated transport.")
                if _embedded_credential(value):
                    risk = "dangerous"
                    reasons.append("The source embeds credentials that can leak through metadata.")
                selectors = [
                    key
                    for key in ("branch", "tag", "ref", "commit")
                    if dependency.get(key) not in (None, "")
                ]
                revision = dependency.get("ref", dependency.get("commit"))
                if len(selectors) > 1:
                    risk = "dangerous"
                    reasons.append("The Git source declares conflicting revision selectors.")
                if source_key == "git" and not (
                    isinstance(revision, str) and _COMMIT.fullmatch(revision.strip())
                ):
                    risk = "dangerous"
                    reasons.append("The Git source is not pinned to an immutable commit.")
                elif source_key == "url":
                    reasons.append("Verify the generated lockfile digest before execution.")
            else:
                reasons.append("Resolution depends on an external registry or Chef control plane.")
            changes.append(
                _change(address, "profile_dependency", risk, " ".join(reasons))
            )

    gems = document.get("gem_dependencies", [])
    if gems not in (None, []) and not isinstance(gems, list):
        changes.append(
            _change(
                "inspec.metadata.gem_dependencies",
                "invalid_gem_dependencies",
                "dangerous",
                "Ruby gem dependencies are not a list and cannot be verified statically.",
            )
        )
    elif isinstance(gems, list):
        for index, gem in enumerate(gems):
            exact = isinstance(gem, dict) and isinstance(gem.get("version"), str) and bool(
                _EXACT_VERSION.fullmatch(str(gem["version"]).strip())
            )
            changes.append(
                _change(
                    f"inspec.metadata.gem_dependencies[{index}]",
                    "gem_dependency",
                    "dangerous",
                    "InSpec may install and load arbitrary Ruby gem code; "
                    + (
                        "the declared version is exact, but provenance and integrity still need "
                        "review."
                        if exact
                        else "the dependency is not pinned to an exact version."
                    ),
                )
            )

    inputs = document.get("inputs", [])
    if inputs not in (None, []) and not isinstance(inputs, list):
        changes.append(
            _change(
                "inspec.metadata.inputs",
                "invalid_inputs",
                "dangerous",
                "InSpec inputs are not a list and their precedence cannot be evaluated.",
            )
        )
    elif isinstance(inputs, list):
        for index, item in enumerate(inputs):
            if not isinstance(item, dict):
                changes.append(
                    _change(
                        f"inspec.metadata.inputs[{index}]",
                        "invalid_input",
                        "dangerous",
                        "An InSpec input declaration is not a mapping.",
                    )
                )
                continue
            name = str(item.get("name", ""))
            has_value = "value" in item
            sensitive_value = has_value and _SECRET.search(name)
            cross_profile = bool(item.get("profile"))
            risk = "dangerous" if sensitive_value or cross_profile else "review"
            explanation = "InSpec declares a typed or runtime-supplied profile input."
            if sensitive_value:
                explanation = (
                    "InSpec metadata contains a credential-like input value; the name and value "
                    "are omitted from findings, and reporter redaction does not protect test "
                    "output."
                )
            elif cross_profile:
                explanation = (
                    "InSpec metadata overrides an input in a dependency profile; review namespace "
                    "and priority interactions."
                )
            changes.append(
                _change(f"inspec.metadata.inputs[{index}]", "profile_input", risk, explanation)
            )

    changes.append(
        _change(
            "inspec.metadata.effective_profile",
            "profile_boundary",
            "review",
            "Static analysis does not render ERB, resolve or vendor dependencies, install gems, "
            "load inputs/plugins, select a transport, verify signatures, or execute the profile.",
        )
    )
    return changes


def _lock_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if document.get("lockfile_version") != 1:
        changes.append(
            _change(
                "inspec.lock.version",
                "unsupported_lock_version",
                "dangerous",
                "The InSpec lockfile version is missing or unsupported, so resolution semantics "
                "cannot be verified.",
            )
        )
    dependencies = document.get("depends", [])
    if not isinstance(dependencies, list):
        changes.append(
            _change(
                "inspec.lock.depends",
                "invalid_lock_dependencies",
                "dangerous",
                "The InSpec lock dependency graph is not a list.",
            )
        )
        dependencies = []
    for index, dependency in enumerate(dependencies):
        address = f"inspec.lock.depends[{index}]"
        if not isinstance(dependency, dict) or not isinstance(
            dependency.get("resolved_source"), dict
        ):
            changes.append(
                _change(
                    address,
                    "unresolved_dependency",
                    "dangerous",
                    "A locked InSpec dependency has no structured resolved source.",
                )
            )
            continue
        resolved = dependency["resolved_source"]
        digest = resolved.get("sha256")
        revision = resolved.get("ref", resolved.get("commit"))
        risk = "review"
        reasons = ["The lockfile records a resolved profile dependency."]
        has_digest = isinstance(digest, str) and bool(_SHA256.fullmatch(digest.strip()))
        has_git_ref = (
            resolved.get("git") not in (None, "")
            and isinstance(revision, str)
            and bool(_COMMIT.fullmatch(revision.strip()))
        )
        if not has_digest and not has_git_ref:
            risk = "dangerous"
            reasons.append("It has no valid SHA-256 digest or immutable Git commit.")
        source_values = [
            str(value)
            for key, value in resolved.items()
            if key in {"url", "git", "path", "compliance", "supermarket", "gem"}
        ]
        if not source_values:
            risk = "dangerous"
            reasons.append("It has no recognized resolved location.")
        for value in source_values:
            if value.casefold().startswith(("http://", "git://")):
                risk = "dangerous"
                reasons.append("A resolved location uses plaintext or unauthenticated transport.")
            if _embedded_credential(value):
                risk = "dangerous"
                reasons.append("A resolved location embeds credentials.")
        changes.append(_change(address, "locked_dependency", risk, " ".join(reasons)))
    changes.append(
        _change(
            "inspec.lock.effective_dependencies",
            "lock_boundary",
            "review",
            "Static analysis does not download dependency archives, recompute content digests, "
            "verify signatures, or compare the lockfile with inspec.yml.",
        )
    )
    return changes


def _line(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1


def _control_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    source = str(document["source"])
    clean = str(document["clean"])
    changes: list[dict[str, str]] = []
    controls = list(_CONTROL.finditer(clean))
    for index, match in enumerate(controls):
        end = controls[index + 1].start() if index + 1 < len(controls) else len(clean)
        block = clean[match.end() : end]
        impact_match = re.search(r"(?m)^\s*impact\s+(?:\(|\s)*([0-9]+(?:\.[0-9]+)?)", block)
        risk = "review"
        explanation = "InSpec defines a compliance control that reads target state."
        if not impact_match:
            explanation += " Its impact is not statically declared in this control block."
        else:
            impact = float(impact_match.group(1))
            if impact <= 0:
                risk = "dangerous"
                explanation += " Impact zero prevents failures from enforcing compliance."
            elif impact > 1:
                risk = "dangerous"
                explanation += " Its impact is outside the documented 0.0 to 1.0 range."
        changes.append(
            _change(f"inspec.control[{index}]", "control", risk, explanation)
        )
    if not controls and not _PROFILE_INCLUDE.search(clean):
        changes.append(
            _change(
                "inspec.controls",
                "missing_controls",
                "dangerous",
                "The Ruby artifact contains no statically recognized controls or profile imports.",
            )
        )
    include_index = 0
    for match in _PROFILE_INCLUDE.finditer(clean):
        operation = match.group(1)
        risk = "dangerous" if operation == "skip_control" else "review"
        explanation = (
            "InSpec excludes a dependency control from execution."
            if operation == "skip_control"
            else "InSpec imports controls from a dependency profile; their implementation is "
            "outside this file."
        )
        changes.append(
            _change(
                f"inspec.profile_control[{include_index}]",
                "profile_control_selection",
                risk,
                explanation,
            )
        )
        include_index += 1
    for index, match in enumerate(re.finditer(r"\b(?:only_if|describe\.one)\b", clean)):
        conditional = clean[match.start() :].startswith("only_if")
        changes.append(
            _change(
                f"inspec.control_flow[{index}]",
                "conditional_skip" if conditional else "alternative_assertion",
                "dangerous" if conditional else "review",
                "InSpec conditionally skips one or more controls at runtime."
                if conditional
                else (
                    "InSpec accepts any passing assertion group; review OR semantics and "
                    "coverage."
                ),
            )
        )
    for index, match in enumerate(_EXEC_RESOURCES.finditer(clean)):
        changes.append(
            _change(
                f"inspec.execution_resource[{index}]",
                "command_execution",
                "dangerous",
                "An InSpec resource executes a command or script on the target; arguments and "
                "side effects are intentionally omitted from findings.",
            )
        )
    for index, _ in enumerate(_REMOTE_RESOURCES.finditer(clean)):
        changes.append(
            _change(
                f"inspec.remote_resource[{index}]",
                "remote_assessment",
                "review",
                "An InSpec resource queries a remote service or cloud API; review credentials, "
                "selected account/region, TLS, pagination, and request side effects.",
            )
        )
    for index, match in enumerate(_RUBY_EXECUTION.finditer(clean)):
        changes.append(
            _change(
                f"inspec.ruby_execution[{index}]",
                "ruby_execution",
                "dangerous",
                f"InSpec control source can load or execute arbitrary Ruby or operating-system "
                f"code near line {_line(clean, match.start())}.",
            )
        )
    if _RUBY_DYNAMIC.search(source):
        changes.append(
            _change(
                "inspec.controls.dynamic",
                "dynamic_ruby",
                "review",
                "InSpec control behavior depends on environment, filesystem, interpolation, or "
                "dynamic Ruby dispatch that static analysis did not evaluate.",
            )
        )
    for index, match in enumerate(re.finditer(r"(['\"])([^\n]*?)\1", source)):
        literal = match.group(2)
        if _SECRET.search(literal) and re.search(r"[:=]", literal):
            changes.append(
                _change(
                    f"inspec.literal[{index}]",
                    "literal_secret",
                    "dangerous",
                    "InSpec control source contains a credential-like literal; its contents are "
                    "omitted from findings.",
                )
            )
    changes.append(
        _change(
            "inspec.controls.effective_execution",
            "control_boundary",
            "review",
            "Static analysis does not execute Ruby, evaluate resources/matchers/inputs, load "
            "libraries or dependencies, connect to a target, apply waivers, or prove results.",
        )
    )
    return changes


def _library_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    clean = str(document["clean"])
    changes = [
        _change(
            "inspec.library",
            "custom_resource_code",
            "dangerous",
            "An InSpec profile library is executable Ruby loaded into the resource runtime; review "
            "all dependencies, commands, network access, and sensitive output.",
        )
    ]
    for index, match in enumerate(_RUBY_EXECUTION.finditer(clean)):
        changes.append(
            _change(
                f"inspec.library.execution[{index}]",
                "ruby_execution",
                "dangerous",
                f"The custom resource can load or execute arbitrary code near line "
                f"{_line(clean, match.start())}.",
            )
        )
    changes.append(
        _change(
            "inspec.library.effective_runtime",
            "library_boundary",
            "review",
            "Static analysis does not instantiate the custom resource, load Ruby gems or profile "
            "files, connect to the target, or evaluate resource methods.",
        )
    )
    return changes


def _expiration(value: Any) -> tuple[str, bool | None]:
    if value in (None, ""):
        return "missing", None
    if isinstance(value, datetime):
        parsed = value.date()
    elif isinstance(value, date):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).date()
        except ValueError:
            try:
                parsed = date.fromisoformat(value)
            except ValueError:
                return "invalid", None
    else:
        return "invalid", None
    return "present", parsed <= date.today()


def _boolish(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().casefold()
        if lowered in {"true", "yes"}:
            return True
        if lowered in {"false", "no"}:
            return False
    return None


def _waiver_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, waiver in enumerate(document.values()):
        address = f"inspec.waiver[{index}]"
        if not isinstance(waiver, dict):
            changes.append(
                _change(
                    address,
                    "invalid_waiver",
                    "dangerous",
                    "An InSpec waiver is not a mapping and cannot be audited.",
                )
            )
            continue
        reasons = ["The waiver prevents a control failure from failing the overall run."]
        risk = "review"
        justification = waiver.get("justification")
        if not isinstance(justification, str) or not justification.strip():
            risk = "dangerous"
            reasons.append("It has no non-empty justification.")
        run = _boolish(waiver.get("run", True))
        if run is False:
            risk = "dangerous"
            reasons.append("It skips control execution entirely.")
        elif run is None:
            risk = "dangerous"
            reasons.append("Its run value is invalid or dynamic.")
        state, expired = _expiration(waiver.get("expiration_date"))
        if state == "missing":
            risk = "dangerous"
            reasons.append("It has no expiration and is permanent.")
        elif state == "invalid":
            risk = "dangerous"
            reasons.append("Its expiration date is invalid.")
        elif expired:
            risk = "dangerous"
            reasons.append("Its expiration date has passed or is today.")
        else:
            reasons.append("It has a future expiration date.")
        changes.append(_change(address, "control_waiver", risk, " ".join(reasons)))
    if not document:
        changes.append(
            _change(
                "inspec.waivers",
                "empty_waiver_file",
                "review",
                "The InSpec waiver file is empty and has no effect.",
            )
        )
    changes.append(
        _change(
            "inspec.waivers.effective_scope",
            "waiver_boundary",
            "review",
            "Static analysis does not confirm that control IDs exist, combine multiple waiver "
            "files, evaluate local-time expiry at execution, or inspect CLI/config selection.",
        )
    )
    return changes


class InSpecAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "inspec"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("inspec")
        return (
            isinstance(payload, dict)
            and payload.get("artifact_type") in {"metadata", "lock", "control", "library", "waiver"}
            and isinstance(payload.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["inspec"]
        artifact_type = str(payload["artifact_type"])
        document = payload["document"]
        if artifact_type == "metadata":
            return _metadata_changes(document, bool(payload.get("dynamic_erb")))
        return {
            "lock": _lock_changes,
            "control": _control_changes,
            "library": _library_changes,
            "waiver": _waiver_changes,
        }[artifact_type](document)

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"inspec_{raw['Kind']}",
            actions=("assess",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_inspec(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = InSpecAdapter().analyze(data, tool_name="Chef InSpec")
    summary = PlanSummary(
        path=Path("inspec://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Chef InSpec")
    gate["adapter"] = "inspec"
    artifact = data["inspec"]
    gate["artifact_type"] = artifact["artifact_type"]
    gate["total_changes"] = len(changes)
    if artifact["artifact_type"] == "metadata":
        gate["dependency_count"] = len(artifact["document"].get("depends", [])) if isinstance(
            artifact["document"].get("depends", []), list
        ) else 0
    elif artifact["artifact_type"] == "lock":
        gate["dependency_count"] = len(artifact["document"].get("depends", [])) if isinstance(
            artifact["document"].get("depends", []), list
        ) else 0
    elif artifact["artifact_type"] == "waiver":
        gate["waiver_count"] = len(artifact["document"])
    return gate
