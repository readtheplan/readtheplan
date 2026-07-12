from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class CFEngineInputError(ValueError):
    """Raised when input is not recognizable CFEngine policy or Augments data."""


_PROMISE_TYPES = {
    "access",
    "classes",
    "commands",
    "databases",
    "defaults",
    "files",
    "guest_environments",
    "interfaces",
    "measurements",
    "meta",
    "methods",
    "packages",
    "processes",
    "reports",
    "roles",
    "services",
    "storage",
    "users",
    "vars",
}
_MUTATING_TYPES = {
    "commands",
    "databases",
    "guest_environments",
    "interfaces",
    "packages",
    "storage",
    "users",
}
_SECRET_NAME = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|registration.?key)",
    re.IGNORECASE,
)
_DYNAMIC_FUNCTION = re.compile(
    r"\b(?:execresult|returnszero|usemodule|remotescalar|remoteclassesmatching|"
    r"readfile|readjson|readyaml|parsejson|parseyaml|data_readstringarray|"
    r"ldaparray|ldapvalue|http_get|url_get)\s*\(",
    re.IGNORECASE,
)
def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CFEngineInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _strip_comments(source: str) -> str:
    output = list(source)
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        if state == "code":
            if source[index] == "#" or source.startswith("//", index):
                width = 2 if source.startswith("//", index) else 1
                output[index : index + width] = " " * width
                index += width
                state = "line"
                continue
            if source[index] in {'"', "'"}:
                quote = source[index]
                state = "string"
        elif state == "line":
            if source[index] == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "string":
            if source[index] == "\\":
                index += 2
                continue
            if source[index] == quote:
                state = "code"
        index += 1
    if state == "string":
        raise CFEngineInputError("unterminated quoted string")
    return "".join(output)


def _looks_like_augments(document: Any) -> bool:
    return isinstance(document, dict) and bool(
        {"inputs", "classes", "vars", "variables", "augments"} & set(document)
    )


def _validate_augments(document: dict[str, Any]) -> dict[str, Any]:
    for name in ("classes", "vars", "variables"):
        if name in document and not isinstance(document[name], dict):
            raise CFEngineInputError(f"CFEngine Augments {name} must be an object")
    for name in ("inputs", "augments"):
        if name not in document:
            continue
        value = document[name]
        if isinstance(value, str):
            continue
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise CFEngineInputError(
                f"CFEngine Augments {name} must be a string or array of strings"
            )
    return document


def parse_cfengine(source: str) -> dict[str, Any]:
    """Parse Augments JSON or recognize CFEngine policy source without executing it."""
    if not source.strip():
        raise CFEngineInputError("input is empty")
    if source.lstrip().startswith("{"):
        try:
            document = json.loads(source, object_pairs_hook=_unique_object)
        except CFEngineInputError:
            raise
        except json.JSONDecodeError as exc:
            raise CFEngineInputError(f"invalid CFEngine Augments JSON: {exc}") from exc
        if not _looks_like_augments(document):
            raise CFEngineInputError("JSON is not recognized as CFEngine Augments data")
        return {
            "cfengine": {
                "artifact_type": "augments",
                "document": _validate_augments(document),
            }
        }
    clean = _strip_comments(source)
    marker = re.compile(
        r"(?im)^\s*(?:bundle\s+(?:agent|common|server|monitor)|"
        r"body\s+(?:common|agent|server|executor|runagent|file)\s+control)\b"
    )
    if not marker.search(clean):
        raise CFEngineInputError("input is not recognized as CFEngine policy")
    blocks = _blocks(clean)
    if not blocks:
        raise CFEngineInputError("CFEngine policy contains no complete bundle or control body")
    for block in blocks:
        if block["kind"] == "bundle":
            for _, _, section in _sections(str(block["body"])):
                _split_statements(section)
        elif block["kind"] == "body" and block["name"] == "control":
            _split_statements(str(block["body"]))
    return {
        "cfengine": {
            "artifact_type": "policy",
            "document": {"source": clean, "blocks": blocks},
        }
    }


def _line(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1


def _matching_brace(source: str, opening: int) -> int | None:
    depth = 0
    quote = ""
    index = opening
    while index < len(source):
        char = source[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _blocks(source: str) -> list[dict[str, Any]]:
    pattern = re.compile(
        r"(?im)^\s*(bundle|body)\s+([A-Za-z_][\w]*)\s+([A-Za-z_][\w:]*)"
        r"(?:\s*\([^)]*\))?\s*\{"
    )
    blocks: list[dict[str, Any]] = []
    for match in pattern.finditer(source):
        opening = source.find("{", match.start())
        closing = _matching_brace(source, opening)
        if closing is None:
            raise CFEngineInputError(
                f"unterminated {match.group(1)} at line {_line(source, match.start())}"
            )
        blocks.append(
            {
                "kind": match.group(1).lower(),
                "component": match.group(2).lower(),
                "name": match.group(3),
                "position": match.start(),
                "body": source[opening + 1 : closing],
                "body_position": opening + 1,
            }
        )
    return blocks


def _split_statements(source: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    start = 0
    quote = ""
    depth = 0
    index = 0
    while index < len(source):
        char = source[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in {'"', "'"}:
            quote = char
        elif char in "{[(":
            depth += 1
        elif char in "}])":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 0:
            statement = source[start:index].strip()
            if statement:
                relative = source.find(statement, start, index)
                result.append((relative, statement))
            start = index + 1
        index += 1
    trailing = source[start:].strip()
    class_guards = re.sub(r"(?m)^\s*[A-Za-z0-9_!&|().]+::\s*$", "", trailing).strip()
    if class_guards:
        raise CFEngineInputError("unterminated CFEngine promise or control statement")
    return result


def _sections(body: str) -> list[tuple[str, int, str]]:
    headers: list[tuple[str, int, int]] = []
    quote = ""
    depth = 0
    index = 0
    while index < len(body):
        char = body[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {'"', "'"}:
            quote = char
            index += 1
            continue
        if char in "{[(":
            depth += 1
            index += 1
            continue
        if char in "}])":
            depth = max(0, depth - 1)
            index += 1
            continue
        if depth == 0 and (char.isalpha() or char == "_"):
            end = index + 1
            while end < len(body) and (body[end].isalnum() or body[end] == "_"):
                end += 1
            colon = end
            while colon < len(body) and body[colon].isspace():
                colon += 1
            if colon < len(body) and body[colon] == ":":
                if colon + 1 >= len(body) or body[colon + 1] != ":":
                    headers.append((body[index:end], index, colon + 1))
                    index = colon + 1
                    continue
            index = end
            continue
        index += 1
    result: list[tuple[str, int, str]] = []
    for index, (name, _start, content_start) in enumerate(headers):
        end = headers[index + 1][1] if index + 1 < len(headers) else len(body)
        result.append((name, content_start, body[content_start:end]))
    return result


def _attributes(statement: str) -> dict[str, str]:
    pattern = re.compile(
        r"(?ms)\b([A-Za-z_][\w]*)\s*=>\s*(.*?)"
        r"(?=,\s*[A-Za-z_][\w]*\s*=>|\Z)"
    )
    return {
        match.group(1): match.group(2).strip().rstrip(",")
        for match in pattern.finditer(statement)
    }


def _promiser(statement: str) -> str:
    clean = re.sub(r"(?m)^\s*[A-Za-z0-9_!&|().]+::\s*$", "", statement).strip()
    if not clean:
        return "dynamic"
    if clean[0] not in {'"', "'"}:
        end = 0
        while end < len(clean) and not clean[end].isspace() and clean[end] != ",":
            end += 1
        return clean[:end] or "dynamic"
    quote = clean[0]
    value: list[str] = []
    index = 1
    while index < len(clean):
        char = clean[index]
        if char == "\\" and index + 1 < len(clean):
            value.extend((char, clean[index + 1]))
            index += 2
            continue
        if char == quote:
            return "".join(value)
        value.append(char)
        index += 1
    # parse_cfengine rejects unterminated source strings. Keep this helper total for
    # direct callers and adversarial input without re-scanning or backtracking.
    return clean


def _truthy(value: Any) -> bool:
    return value is True or str(value).strip(" '\"").lower() in {"true", "yes", "1", "any"}


def _world_writable(value: str) -> bool:
    return bool(re.search(r"(?:^|[^0-9])0?777(?:[^0-9]|$)", value))


def _promise_change(
    source: str,
    position: int,
    bundle: str,
    promise_type: str,
    statement: str,
) -> list[dict[str, str]]:
    promiser = _promiser(statement)
    attrs = _attributes(statement)
    address = f"source.line.{_line(source, position)}.{bundle}.{promise_type}"
    changes: list[dict[str, str]] = []
    risk = "review"
    reason = f"CFEngine {promise_type} promise manages {promiser!r}"
    if promise_type not in _PROMISE_TYPES:
        risk = "dangerous"
        reason = (
            f"CFEngine custom promise type {promise_type!r} is implemented by an external "
            f"promise module and manages {promiser!r}"
        )
    elif promise_type == "reports":
        risk = "safe"
        reason = f"CFEngine reports message {promiser!r} without directly changing host state"
    elif promise_type == "commands":
        risk = "dangerous"
        reason = f"CFEngine executes command {promiser!r} during convergence"
    elif promise_type in _MUTATING_TYPES:
        risk = "dangerous"
        reason += "; this promise changes software, identity, storage, network, or runtime state"
    elif promise_type == "files":
        destructive = any(
            key in attrs
            for key in ("delete", "rename", "transformer", "edit_line", "edit_template")
        ) or _truthy(attrs.get("purge", "false"))
        risk = "dangerous" if destructive else "review"
        reason += "; review content, ownership, permissions, deletion, and copy provenance"
    elif promise_type == "services":
        policy = attrs.get("service_policy", "").strip(" '\"").lower()
        risk = "dangerous" if policy in {"disable", "restart", "stop"} else "review"
        reason += f"; desired service policy is {policy or 'resolved at runtime'!r}"
    elif promise_type == "processes":
        risk = "dangerous" if any(
            key in attrs for key in ("signals", "process_stop", "restart_class")
        ) else "review"
        reason += "; matching and signals can stop or restart host processes"
    elif promise_type in {"access", "roles"}:
        risk = "dangerous"
        reason += "; this changes CFEngine server authorization or remote class activation"
    elif promise_type == "methods":
        reason += "; another policy bundle is invoked and not expanded at this call site"
    elif promise_type == "classes":
        reason += "; this class can conditionally activate downstream promises"
    elif promise_type == "measurements":
        reason += "; the monitor executes or samples an external measurement source"
    changes.append(_change(address, f"{promise_type}_promise", risk, reason + "."))

    values = " ".join([promiser, *attrs.values()])
    if "http://" in values.lower():
        changes.append(
            _change(
                f"{address}.source",
                "plaintext_source",
                "dangerous",
                "CFEngine policy obtains content or contacts an endpoint over plaintext HTTP.",
            )
        )
    urls = re.findall(r"(?:https?|git)://[^\s'\",}\]]+", values, re.IGNORECASE)
    if any(_embedded_credential(url) for url in urls):
        changes.append(
            _change(
                f"{address}.credential",
                "embedded_source_credential",
                "dangerous",
                "CFEngine policy embeds credentials in a remote URL.",
            )
        )
    if _world_writable(values):
        changes.append(
            _change(
                f"{address}.permissions",
                "world_writable_permissions",
                "dangerous",
                "CFEngine policy requests world-writable permissions.",
            )
        )
    if "depends_on" in attrs:
        changes.append(
            _change(
                f"{address}.depends_on",
                "promise_dependency",
                "review",
                "CFEngine gates this promise on handles from earlier promises; review ordering "
                "and failure propagation.",
            )
        )
    if _DYNAMIC_FUNCTION.search(values):
        changes.append(
            _change(
                f"{address}.dynamic",
                "dynamic_evaluation",
                "dangerous",
                "CFEngine evaluates external commands, modules, remote data, or file content "
                "while resolving this promise.",
            )
        )
    if promise_type == "vars" and _SECRET_NAME.search(promiser):
        reference = bool(
            re.search(r"\b(?:getenv|readfile|data_readstringarray|vault)\s*\(", values, re.I)
        )
        changes.append(
            _change(
                f"{address}.secret",
                "secret_reference" if reference else "literal_secret",
                "review" if reference else "dangerous",
                "CFEngine resolves credential-like data from an external source; verify access "
                "and logging boundaries."
                if reference
                else "CFEngine policy assigns credential-like data directly in source.",
            )
        )
    return changes


def _control_changes(source: str, block: dict[str, Any]) -> list[dict[str, str]]:
    component = block["component"]
    body = str(block["body"])
    attrs: dict[str, str] = {}
    for _, statement in _split_statements(body):
        attrs.update(_attributes(statement))
    changes: list[dict[str, str]] = []
    prefix = f"source.line.{_line(source, int(block['position']))}.control.{component}"
    if component == "common":
        if "inputs" in attrs:
            dynamic = bool(_DYNAMIC_FUNCTION.search(attrs["inputs"]))
            changes.append(
                _change(
                    f"{prefix}.inputs",
                    "policy_inputs",
                    "dangerous" if dynamic or "http://" in attrs["inputs"].lower() else "review",
                    "CFEngine loads additional policy inputs before evaluation; review path, "
                    "transport, ownership, and version provenance.",
                )
            )
        if "bundlesequence" in attrs:
            changes.append(
                _change(
                    f"{prefix}.bundlesequence",
                    "bundle_sequence",
                    "dangerous" if _DYNAMIC_FUNCTION.search(attrs["bundlesequence"]) else "review",
                    "CFEngine bundlesequence selects and orders agent bundles that will execute.",
                )
            )
        if _truthy(attrs.get("ignore_missing_inputs", "false")):
            changes.append(
                _change(
                    f"{prefix}.ignore_missing_inputs",
                    "missing_input_bypass",
                    "dangerous",
                    "CFEngine continues when policy inputs are missing, allowing partial policy "
                    "evaluation.",
                )
            )
    elif component == "server":
        for name in ("allowconnects", "allowusers", "trustkeysfrom"):
            if name not in attrs:
                continue
            broad = bool(re.search(r"(?:\"\*\"|0\.0\.0\.0/0|::/0|\bany\b)", attrs[name], re.I))
            changes.append(
                _change(
                    f"{prefix}.{name}",
                    "broad_server_trust" if broad or name == "trustkeysfrom" else "server_access",
                    "dangerous" if broad or name == "trustkeysfrom" else "review",
                    f"CFEngine server control {name} defines remote trust or authorization scope.",
                )
            )
        if _truthy(attrs.get("allowbadclocks", "false")):
            changes.append(
                _change(
                    f"{prefix}.allowbadclocks",
                    "clock_validation_bypass",
                    "dangerous",
                    "CFEngine server accepts peers with invalid clock synchronization.",
                )
            )
    elif component == "executor":
        if "exec_command" in attrs:
            changes.append(
                _change(
                    f"{prefix}.exec_command",
                    "scheduled_agent_command",
                    "dangerous",
                    "CFEngine executor runs a configured agent command on its schedule.",
                )
            )
        if "schedule" in attrs:
            changes.append(
                _change(
                    f"{prefix}.schedule",
                    "execution_schedule",
                    "review",
                    "CFEngine executor schedule controls unattended policy execution cadence.",
                )
            )
    if _DYNAMIC_FUNCTION.search(body):
        changes.append(
            _change(
                f"{prefix}.dynamic",
                "dynamic_control_evaluation",
                "dangerous",
                "CFEngine control body evaluates external commands, modules, files, or remote "
                "data.",
            )
        )
    return changes


def _policy_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    source = str(document["source"])
    changes: list[dict[str, str]] = []
    for block in document["blocks"]:
        if block["kind"] == "body" and block["name"] == "control":
            changes.extend(_control_changes(source, block))
            continue
        if block["kind"] != "bundle":
            continue
        for promise_type, offset, section in _sections(str(block["body"])):
            for statement_offset, statement in _split_statements(section):
                absolute = int(block["body_position"]) + offset + statement_offset
                changes.extend(
                    _promise_change(
                        source,
                        absolute,
                        str(block["name"]),
                        promise_type,
                        statement,
                    )
                )
    changes.append(
        _change(
            "cfengine.effective_policy",
            "evaluation_boundary",
            "review",
            "Static analysis does not invoke cf-promises/cf-agent, expand classes or variables, "
            "load policy inputs/Augments, inspect custom bodies/modules, resolve bundle order "
            "overrides, or query host state.",
        )
    )
    return changes


def _embedded_credential(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _walk(value: Any, prefix: str = "augments") -> list[tuple[str, Any]]:
    result: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            address = f"{prefix}.{key}"
            result.append((address, child))
            result.extend(_walk(child, address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            address = f"{prefix}[{index}]"
            result.append((address, child))
            result.extend(_walk(child, address))
    return result


def _augments_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    inputs = document.get("inputs", [])
    if not isinstance(inputs, list):
        inputs = [inputs]
    for index, source in enumerate(inputs):
        text = str(source)
        dangerous = text.lower().startswith(("http://", "git://")) or _embedded_credential(text)
        changes.append(
            _change(
                f"augments.inputs[{index}]",
                "policy_input",
                "dangerous" if dangerous else "review",
                f"CFEngine Augments adds policy input {text!r}; review path, transport, ownership, "
                "and immutable provenance.",
            )
        )
    classes = document.get("classes", {})
    if isinstance(classes, dict):
        for name, expression in classes.items():
            autorun = "autorun" in str(name).lower()
            changes.append(
                _change(
                    f"augments.classes.{name}",
                    "autorun_class" if autorun else "augmented_class",
                    "dangerous" if autorun else "review",
                    f"CFEngine Augments defines class {name!r} from {expression!r}; "
                    + (
                        "this can automatically load policy inputs or execute tagged bundles."
                        if autorun
                        else "review the downstream promises activated by this class."
                    ),
                )
            )
    for address, value in _walk(document):
        leaf = address.rsplit(".", 1)[-1]
        if _SECRET_NAME.search(leaf) and value not in (None, "", False, {}, []):
            changes.append(
                _change(
                    address,
                    "literal_secret",
                    "dangerous",
                    "CFEngine Augments contains credential-like material directly in JSON.",
                )
            )
        if any(token in leaf.lower() for token in ("bundlesequence", "autorun_inputs")):
            changes.append(
                _change(
                    address,
                    "execution_extension",
                    "dangerous",
                    "CFEngine Augments extends policy inputs or the effective bundle execution "
                    "sequence.",
                )
            )
        if leaf == "augments":
            changes.append(
                _change(
                    address,
                    "nested_augments",
                    "review",
                    "CFEngine loads additional Augments data before policy parsing and evaluation.",
                )
            )
    changes.append(
        _change(
            "cfengine.effective_augments",
            "augments_boundary",
            "review",
            "Effective values also depend on host-specific Augments precedence, variables/classes "
            "from policy, Masterfiles Policy Framework defaults, and runtime expansion.",
        )
    )
    return changes


class CFEngineAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "cfengine"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("cfengine")
        return (
            isinstance(payload, dict)
            and payload.get("artifact_type") in {"policy", "augments"}
            and isinstance(payload.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["cfengine"]
        if payload["artifact_type"] == "augments":
            return _augments_changes(payload["document"])
        return _policy_changes(payload["document"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"cfengine_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_cfengine(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = CFEngineAdapter().analyze(data, tool_name="CFEngine")
    summary = PlanSummary(
        path=Path("cfengine://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="CFEngine")
    gate["adapter"] = "cfengine"
    gate["artifact_type"] = data["cfengine"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
