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
    r"(?:^|\W)(?:eval|exec|spawn|system|require|load|IO\.popen|Open3\.)\s*(?:\(|['\"])"
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


def parse_chef_project(source: str) -> dict[str, Any]:
    """Parse static Chef policy/cookbook project files without executing Ruby."""
    if not source.strip():
        raise ChefProjectInputError("input is empty")
    parsed = _parse_lock(source) or _parse_ruby(source)
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


class ChefProjectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "chef-project"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        project = input_data.get("chef_project")
        return (
            isinstance(project, dict)
            and project.get("artifact_type") in {"policyfile", "lock", "metadata"}
            and isinstance(project.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        project = input_data["chef_project"]
        artifact_type = project["artifact_type"]
        document = project["document"]
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
    gate["artifact_type"] = data["chef_project"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
