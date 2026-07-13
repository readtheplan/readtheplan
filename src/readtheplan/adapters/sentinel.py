from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import hcl2
from hcl2.utils import SerializationOptions

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class SentinelInputError(ValueError):
    """Raised when input is not recognizable Sentinel policy or configuration."""


_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|auth)", re.I
)
_IMPORT = re.compile(r'(?m)^\s*import\s+(["`])([^"`]+)\1(?:\s+as\s+\w+)?\s*$')
_PARAM = re.compile(r"(?m)^\s*param\s+([A-Za-z_][\w]*)\b")
_REMOTE = re.compile(r"^(?:git::)?(?:https?|git|ssh|oci)://", re.I)


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SentinelInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _clean_source(source: str, *, blank_strings: bool = True) -> str:
    output = list(source)
    state = "code"
    quote = ""
    depth = 0
    index = 0
    while index < len(source):
        char = source[index]
        if state == "code":
            if source.startswith("/*", index):
                output[index : index + 2] = "  "
                state = "block_comment"
                index += 2
                continue
            if source.startswith("//", index) or char == "#":
                width = 2 if source.startswith("//", index) else 1
                output[index : index + width] = " " * width
                state = "line_comment"
                index += width
                continue
            if char in {'"', "`"}:
                quote = char
                state = "string"
                if blank_strings:
                    output[index] = " "
            elif char in "{([":
                depth += 1
            elif char in "})]":
                depth -= 1
                if depth < 0:
                    raise SentinelInputError("unbalanced Sentinel delimiters")
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block_comment":
            if source.startswith("*/", index):
                output[index : index + 2] = "  "
                state = "code"
                index += 2
                continue
            if char != "\n":
                output[index] = " "
        else:
            if blank_strings:
                output[index] = " "
            if quote != "`" and char == "\\":
                if blank_strings and index + 1 < len(source):
                    output[index + 1] = " "
                index += 2
                continue
            if char == quote:
                state = "code"
        index += 1
    if state == "string":
        raise SentinelInputError("unterminated Sentinel string")
    if state == "block_comment":
        raise SentinelInputError("unterminated Sentinel block comment")
    if depth:
        raise SentinelInputError("unbalanced Sentinel delimiters")
    return "".join(output)


def _json_document(source: str) -> dict[str, Any]:
    try:
        document = json.loads(source, object_pairs_hook=_unique_object)
    except SentinelInputError:
        raise
    except json.JSONDecodeError as exc:
        raise SentinelInputError(f"invalid Sentinel configuration JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SentinelInputError("Sentinel configuration JSON must be an object")
    return document


def _strip_internal(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_internal(child) for key, child in value.items() if key != "__is_block__"
        }
    if isinstance(value, list):
        return [_strip_internal(child) for child in value]
    return value


def parse_sentinel(source: str, filename: str = "policy.sentinel") -> dict[str, Any]:
    """Recognize Sentinel policy or CLI configuration without evaluating it."""
    if not source.strip():
        raise SentinelInputError("input is empty")
    name = Path(filename).name.lower()
    if name.endswith(".sentinel"):
        clean = _clean_source(source)
        comments_only = _clean_source(source, blank_strings=False)
        if not re.search(r"(?m)^\s*(?:import|param|[A-Za-z_]\w*\s*=)", clean):
            raise SentinelInputError("input is not recognized as Sentinel policy source")
        return {
            "sentinel": {
                "artifact_type": "policy",
                "document": {
                    "source": source,
                    "clean": clean,
                    "comments_only": comments_only,
                    "filename": name,
                },
            }
        }
    if name.endswith(".json"):
        document = _json_document(source)
    else:
        try:
            document = _strip_internal(
                hcl2.loads(
                    source,
                    serialization_options=SerializationOptions(
                        explicit_blocks=False,
                        strip_string_quotes=True,
                    ),
                )
            )
        except Exception as exc:
            raise SentinelInputError(f"invalid Sentinel HCL configuration: {exc}") from exc
    if not isinstance(document, dict) or not (
        {"policy", "import", "mock", "param", "global", "test", "sentinel"} & set(document)
    ):
        raise SentinelInputError("input is not recognized as Sentinel CLI configuration")
    return {"sentinel": {"artifact_type": "configuration", "document": document}}


def _line(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1


def _policy_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    source = str(document["source"])
    clean = str(document["clean"])
    comments_only = str(document["comments_only"])
    changes: list[dict[str, str]] = []
    imports = [match.group(2) for match in _IMPORT.finditer(comments_only)]
    for index, name in enumerate(imports):
        if name == "http":
            changes.append(
                _change(
                    f"sentinel.import[{index}].http",
                    "network_import",
                    "dangerous",
                    "Sentinel policy imports http, enabling outbound requests and potential "
                    "disclosure of policy inputs, parameters, or imported data.",
                )
            )
        elif name == "runtime":
            changes.append(
                _change(
                    f"sentinel.import[{index}].runtime",
                    "runtime_dependency",
                    "review",
                    "Sentinel policy depends on runtime version information and may behave "
                    "differently across hosts.",
                )
            )
        elif name.startswith(("tfplan", "tfconfig", "tfstate", "tfrun")):
            legacy = not name.endswith("/v2") and name != "tfrun"
            changes.append(
                _change(
                    f"sentinel.import[{index}].terraform",
                    "terraform_import",
                    "dangerous" if legacy else "review",
                    f"Sentinel consumes host-provided {name!r} data; review schema version, "
                    "unknown values, sensitivity, and integration-specific behavior.",
                )
            )
        elif name not in {
            "base64",
            "collection",
            "decimal",
            "json",
            "sockaddr",
            "strings",
            "time",
            "types",
            "units",
            "version",
        }:
            changes.append(
                _change(
                    f"sentinel.import[{index}].custom",
                    "host_import",
                    "review",
                    f"Sentinel policy imports host-defined capability {name!r}; its data, "
                    "side effects, and trust boundary are not defined in this module.",
                )
            )
    for match in re.finditer(r"\bhttp\.(?:get|post|send|request)\s*\(", clean):
        changes.append(
            _change(
                f"source.line.{_line(clean, match.start())}.http",
                "network_request",
                "dangerous",
                "Sentinel performs an HTTP request during policy evaluation; review endpoint, "
                "TLS, redirects, headers, request body, retries, and response trust.",
            )
        )
    for name in ("print", "trace"):
        for match in re.finditer(rf"\b{name}\s*\(", clean):
            changes.append(
                _change(
                    f"source.line.{_line(clean, match.start())}.{name}",
                    "debug_output",
                    "dangerous",
                    f"Sentinel calls {name}(); evaluation output can expose sensitive policy "
                    "inputs, parameters, imports, or decisions.",
                )
            )
    main = re.search(r"(?m)^\s*main\s*=\s*rule\b", clean)
    if not main:
        changes.append(
            _change(
                "sentinel.main",
                "missing_main_rule",
                "dangerous",
                "Sentinel policy has no recognized main rule, so the final enforcement result "
                "cannot be established.",
            )
        )
    elif re.search(r"(?ms)^\s*main\s*=\s*rule\s*\{\s*true\s*\}", clean):
        changes.append(
            _change(
                "sentinel.main",
                "unconditional_pass",
                "dangerous",
                "Sentinel main is unconditionally true, so the policy cannot block any input.",
            )
        )
    params = _PARAM.findall(clean)
    for name in params:
        changes.append(
            _change(
                f"sentinel.param.{name}",
                "sensitive_parameter" if _SECRET.search(name) else "policy_parameter",
                "review",
                f"Sentinel declares parameter {name!r}; its effective value is supplied by the "
                "host or configuration and was not loaded.",
            )
        )
    if re.search(r"\belse\b", clean):
        changes.append(
            _change(
                "sentinel.fallbacks",
                "undefined_fallback",
                "review",
                "Sentinel uses else fallback expressions; review whether missing or undefined "
                "data can produce a permissive result.",
            )
        )
    for match in re.finditer(r'(["`])([^\n]*?)\1', source):
        literal = match.group(2)
        if _SECRET.search(literal) and re.search(r"[:=]", literal):
            changes.append(
                _change(
                    f"source.line.{_line(source, match.start())}.secret",
                    "literal_secret",
                    "dangerous",
                    "Sentinel source contains a credential-like literal; the value is omitted "
                    "from analysis output.",
                )
            )
    changes.append(
        _change(
            "sentinel.effective_policy",
            "evaluation_boundary",
            "review",
            "Static analysis does not run Sentinel, load parameters/imports/Terraform data, "
            "resolve undefined values, execute plugins or HTTP requests, or prove policy results.",
        )
    )
    return changes


def _scalar(value: Any) -> str:
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return text


def _blocks(document: dict[str, Any], name: str) -> list[tuple[list[str], dict[str, Any]]]:
    result: list[tuple[list[str], dict[str, Any]]] = []
    raw = document.get(name, [])
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise SentinelInputError(f"Sentinel {name} configuration must contain blocks")

    def visit(value: Any, labels: list[str]) -> None:
        if not isinstance(value, dict):
            raise SentinelInputError(f"Sentinel {name} block must be an object")
        nested = [(key, child) for key, child in value.items() if isinstance(child, dict)]
        attributes = {key: child for key, child in value.items() if not isinstance(child, dict)}
        if attributes or not nested:
            result.append((labels, value))
            return
        for label, child in nested:
            visit(child, [*labels, _scalar(label)])

    for item in raw:
        visit(item, [])
    return result


def _embedded_credential(value: str) -> bool:
    candidate = value[5:] if value.startswith("git::") else value
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _source_findings(address: str, source: str, kind: str) -> list[dict[str, str]]:
    remote = bool(_REMOTE.match(source))
    plaintext = source.lower().startswith(("http://", "git://"))
    mutable = remote and not re.search(r"(?:\?ref=|@sha256:)[0-9A-Za-z._/-]+", source)
    escaped = not remote and (Path(source).is_absolute() or ".." in PurePosixPath(source).parts)
    risk = (
        "dangerous" if plaintext or mutable or escaped or _embedded_credential(source) else "review"
    )
    reason = f"Sentinel {kind} source changes executable policy code or imported behavior"
    if remote:
        reason += "; review transport, immutable revision, ownership, and cached content"
    elif escaped:
        reason += "; the path escapes the local project boundary"
    else:
        reason += "; review local path ownership and repository inclusion"
    return [_change(address, f"{kind}_source", risk, reason + ".")]


def _walk_secrets(value: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            address = f"{prefix}.{_scalar(key)}"
            if _SECRET.search(_scalar(key)) and child not in (None, "", False, [], {}):
                changes.append(
                    _change(
                        address,
                        "literal_secret",
                        "dangerous",
                        "Sentinel configuration contains credential-like material; the value "
                        "is omitted from analysis output.",
                    )
                )
            changes.extend(_walk_secrets(child, address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            changes.extend(_walk_secrets(child, f"{prefix}[{index}]"))
    return changes


def _configuration_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    policies = _blocks(document, "policy")
    for index, (labels, block) in enumerate(policies):
        address = f"sentinel.policy.{labels[-1] if labels else index}"
        source = _scalar(block.get("source", ""))
        if not source:
            changes.append(
                _change(
                    f"{address}.source",
                    "missing_policy_source",
                    "dangerous",
                    "Sentinel policy block has no source and cannot be tied to reviewed "
                    "policy code.",
                )
            )
        else:
            changes.extend(_source_findings(f"{address}.source", source, "policy"))
        enforcement = _scalar(block.get("enforcement_level", "advisory")).lower()
        if enforcement not in {"advisory", "soft-mandatory", "hard-mandatory"}:
            changes.append(
                _change(
                    f"{address}.enforcement",
                    "unknown_enforcement",
                    "dangerous",
                    f"Sentinel policy uses unknown enforcement level {enforcement!r}.",
                )
            )
        else:
            risk = "dangerous" if enforcement == "advisory" else "review"
            changes.append(
                _change(
                    f"{address}.enforcement",
                    "policy_enforcement",
                    risk,
                    f"Sentinel enforcement is {enforcement!r}; review override permissions "
                    "and whether failure blocks the protected operation.",
                )
            )
        changes.extend(_walk_secrets(block.get("params", {}), f"{address}.params"))

    for index, (labels, block) in enumerate(_blocks(document, "import")):
        kind = labels[0] if labels else "unknown"
        name = labels[1] if len(labels) > 1 else str(index)
        address = f"sentinel.import.{kind}.{name}"
        source = _scalar(block.get("source", ""))
        if kind == "plugin":
            changes.append(
                _change(
                    address,
                    "executable_import_plugin",
                    "dangerous",
                    "Sentinel launches an import plugin executable during evaluation; review "
                    "binary provenance, arguments, environment, configuration, privileges, "
                    "and network access.",
                )
            )
            if source:
                changes.extend(_source_findings(f"{address}.source", source, "plugin"))
            changes.extend(_walk_secrets(block.get("env", {}), f"{address}.env"))
            changes.extend(_walk_secrets(block.get("config", {}), f"{address}.config"))
        elif kind in {"module", "static"}:
            if not source:
                changes.append(
                    _change(
                        f"{address}.source",
                        "missing_import_source",
                        "dangerous",
                        f"Sentinel {kind} import has no source.",
                    )
                )
            else:
                changes.extend(_source_findings(f"{address}.source", source, kind))
        else:
            changes.append(
                _change(
                    address,
                    "unknown_import_kind",
                    "dangerous",
                    f"Sentinel configuration declares unsupported import kind {kind!r}.",
                )
            )

    for index, (labels, block) in enumerate(_blocks(document, "mock")):
        address = f"sentinel.mock.{labels[-1] if labels else index}"
        changes.append(
            _change(
                address,
                "mock_import",
                "review",
                "Sentinel test configuration replaces an import with mock data or code; review "
                "fidelity and ensure mocks cannot affect production invocation.",
            )
        )
        modules = block.get("module", [])
        if isinstance(modules, dict):
            modules = [modules]
        for module_index, module in enumerate(modules if isinstance(modules, list) else []):
            if isinstance(module, dict) and module.get("source"):
                changes.extend(
                    _source_findings(
                        f"{address}.module[{module_index}]",
                        _scalar(module["source"]),
                        "mock_module",
                    )
                )
        changes.extend(_walk_secrets(block.get("data", {}), f"{address}.data"))

    for name in ("param", "global"):
        for index, (labels, block) in enumerate(_blocks(document, name)):
            address = f"sentinel.{name}.{labels[-1] if labels else index}"
            changes.append(
                _change(
                    address,
                    f"{name}_input",
                    "review",
                    f"Sentinel configuration supplies {name} data that can change policy results.",
                )
            )
            changes.extend(_walk_secrets(block, address))

    for index, (_labels, block) in enumerate(_blocks(document, "test")):
        rules = block.get("rules", {})
        if not isinstance(rules, dict) or "main" not in rules:
            changes.append(
                _change(
                    f"sentinel.test[{index}].main",
                    "missing_main_assertion",
                    "dangerous",
                    "Sentinel test case does not explicitly assert main, so final policy "
                    "behavior may regress without failing this test.",
                )
            )
        else:
            changes.append(
                _change(
                    f"sentinel.test[{index}]",
                    "test_assertions",
                    "review",
                    "Sentinel test case asserts policy rules; static analysis does not execute "
                    "or measure coverage of those assertions.",
                )
            )

    if document.get("sentinel"):
        changes.append(
            _change(
                "sentinel.runtime",
                "runtime_configuration",
                "review",
                "Sentinel runtime configuration enables features or changes evaluation "
                "behavior; review host compatibility and capability scope.",
            )
        )
    changes.extend(_walk_secrets(document, "sentinel.configuration"))
    changes.append(
        _change(
            "sentinel.effective_configuration",
            "configuration_boundary",
            "review",
            "Static analysis does not fetch remote sources, launch plugins, load mocks, "
            "imports, or parameters, run tests, or apply host-specific configuration precedence.",
        )
    )
    return changes


class SentinelAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "sentinel"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("sentinel")
        return (
            isinstance(payload, dict)
            and payload.get("artifact_type") in {"policy", "configuration"}
            and isinstance(payload.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["sentinel"]
        if payload["artifact_type"] == "policy":
            return _policy_changes(payload["document"])
        return _configuration_changes(payload["document"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"sentinel_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_sentinel(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = SentinelAdapter().analyze(data, tool_name="Sentinel")
    summary = PlanSummary(
        path=Path("sentinel://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Sentinel")
    gate["adapter"] = "sentinel"
    gate["artifact_type"] = data["sentinel"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
