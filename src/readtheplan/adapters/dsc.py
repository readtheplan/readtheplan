from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class DscInputError(ValueError):
    """Raised when input is not a recognizable DSC configuration."""


_SECRET_NAME = re.compile(
    r"(?:password|passwd|token|secret|private.?key|registration.?key|credential)",
    re.IGNORECASE,
)
_EXPRESSION = re.compile(r"^\s*\[(?:parameters|variables|env|secret)\(", re.IGNORECASE)


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise DscInputError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DscInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _strip_powershell_comments(source: str) -> str:
    """Remove PowerShell comments while preserving offsets and quoted strings."""
    output = list(source)
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        if state == "code":
            if source.startswith("<#", index):
                output[index : index + 2] = "  "
                state = "block"
                index += 2
                continue
            if source.startswith(('@"', "@'"), index):
                quote = source[index + 1]
                state = "here_string"
                index += 2
                continue
            if source[index] == "#":
                output[index] = " "
                state = "line"
            elif source[index] in {'"', "'"}:
                quote = source[index]
                state = "string"
        elif state == "line":
            if source[index] == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block":
            if source.startswith("#>", index):
                output[index : index + 2] = "  "
                state = "code"
                index += 2
                continue
            if source[index] != "\n":
                output[index] = " "
        elif state == "string":
            if source[index] == "`":
                index += 2
                continue
            if source[index] == quote:
                if quote == "'" and index + 1 < len(source) and source[index + 1] == "'":
                    index += 2
                    continue
                state = "code"
        elif state == "here_string" and source.startswith(f"{quote}@", index):
            line_start = source.rfind("\n", 0, index) + 1
            if not source[line_start:index].strip():
                state = "code"
                index += 2
                continue
        index += 1
    if state == "block":
        raise DscInputError("unterminated PowerShell block comment")
    if state in {"string", "here_string"}:
        raise DscInputError("unterminated PowerShell string")
    return "".join(output)


def _validate_document(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise DscInputError("DSC configuration document must be an object")
    schema = document.get("$schema")
    resources = document.get("resources")
    if not isinstance(schema, str) or "dsc" not in schema.lower():
        raise DscInputError("DSC configuration document requires a DSC $schema URI")
    if not isinstance(resources, list) or not resources:
        raise DscInputError("DSC configuration document requires a non-empty resources array")
    names: set[str] = set()
    for index, resource in enumerate(resources):
        if not isinstance(resource, dict):
            raise DscInputError(f"DSC resource {index} must be an object")
        for key in ("name", "type", "properties"):
            if key not in resource:
                raise DscInputError(f"DSC resource {index} is missing {key!r}")
        if not isinstance(resource["name"], str) or not resource["name"].strip():
            raise DscInputError(f"DSC resource {index} name must be a non-empty string")
        if resource["name"] in names:
            raise DscInputError(f"duplicate DSC resource name: {resource['name']}")
        names.add(resource["name"])
        if not isinstance(resource["type"], str) or "/" not in resource["type"]:
            raise DscInputError(f"DSC resource {index} type must be fully qualified")
        if not isinstance(resource["properties"], dict):
            raise DscInputError(f"DSC resource {index} properties must be an object")
    return document


def parse_dsc(source: str) -> dict[str, Any]:
    """Parse a DSC v3 document or recognize legacy PowerShell DSC source."""
    if not source.strip():
        raise DscInputError("input is empty")
    stripped = source.lstrip()
    if stripped.startswith("{"):
        try:
            document = json.loads(source, object_pairs_hook=_unique_object)
        except DscInputError:
            raise
        except json.JSONDecodeError as exc:
            raise DscInputError(f"invalid DSC JSON: {exc}") from exc
        return {"dsc": {"artifact_type": "document", "document": _validate_document(document)}}
    if re.search(r"(?m)^\s*\$schema\s*:", source) and re.search(
        r"(?m)^\s*resources\s*:", source
    ):
        try:
            document = yaml.load(source, Loader=_UniqueKeyLoader)  # noqa: S506
        except DscInputError:
            raise
        except yaml.YAMLError as exc:
            raise DscInputError(f"invalid DSC YAML: {exc}") from exc
        return {"dsc": {"artifact_type": "document", "document": _validate_document(document)}}
    clean = _strip_powershell_comments(source)
    if not re.search(
        r"(?im)^\s*(?:\[DSCLocalConfigurationManager\(\)\]\s*)?Configuration\s+"
        r"[A-Za-z_][\w-]*\s*\{",
        clean,
    ):
        raise DscInputError("input is not recognized as DSC source or a DSC document")
    return {"dsc": {"artifact_type": "powershell", "document": {"source": clean}}}


def _line(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1


def _matching_brace(source: str, opening: int) -> int | None:
    depth = 0
    quote = ""
    here_quote = ""
    index = opening
    while index < len(source):
        char = source[index]
        if here_quote:
            if source.startswith(f"{here_quote}@", index):
                line_start = source.rfind("\n", 0, index) + 1
                if not source[line_start:index].strip():
                    here_quote = ""
                    index += 2
                    continue
            index += 1
            continue
        if quote:
            if char == "`":
                index += 2
                continue
            if char == quote:
                if quote == "'" and index + 1 < len(source) and source[index + 1] == "'":
                    index += 2
                    continue
                quote = ""
        elif source.startswith(('@"', "@'"), index):
            here_quote = source[index + 1]
            index += 2
            continue
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


def _is_true(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"true", "$true", "yes", "1"}


def _embedded_credential(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _secret_changes(value: Any, address: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_address = f"{address}.{key}"
            secret_value = child
            secret_address = child_address
            if isinstance(child, dict):
                secret_value = _property(child, "defaultValue", "default")
                secret_address = f"{child_address}.defaultValue"
            if _SECRET_NAME.search(str(key)) and secret_value not in (None, "", False):
                reference = isinstance(secret_value, str) and bool(
                    _EXPRESSION.match(secret_value)
                )
                changes.append(
                    _change(
                        secret_address,
                        "credential_reference" if reference else "literal_secret",
                        "review" if reference else "dangerous",
                        "DSC resolves credential-like material from a runtime expression; verify "
                        "the secret provider and execution identity."
                        if reference
                        else "DSC configuration contains credential-like material directly; it "
                        "can leak through source control, logs, or compiled configuration data.",
                    )
                )
            changes.extend(_secret_changes(child, child_address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            changes.extend(_secret_changes(child, f"{address}[{index}]"))
    return changes


def _property(properties: dict[str, Any], *names: str) -> Any:
    lowered = {str(key).lower(): value for key, value in properties.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _document_resource_changes(
    resource: dict[str, Any],
    address: str,
) -> list[dict[str, str]]:
    name = str(resource["name"])
    resource_type = str(resource["type"])
    lowered = resource_type.lower()
    properties = resource["properties"]
    changes: list[dict[str, str]] = []
    risk = "review"
    reasons = ["review the resource provider, desired state, and target scope"]
    if "script" in lowered or "powershell" in lowered or "command" in lowered:
        risk = "dangerous"
        reasons = ["the resource or adapter can execute imperative code"]
    elif "file" in lowered and str(_property(properties, "ensure")).lower() == "absent":
        risk = "dangerous"
        reasons = ["the desired state removes a filesystem object"]
    elif "package" in lowered:
        risk = "dangerous"
        reasons = ["the resource installs, upgrades, or removes software"]
    elif "service" in lowered and str(_property(properties, "state", "startupType")).lower() in {
        "stopped",
        "disabled",
    }:
        risk = "dangerous"
        reasons = ["the desired state stops or disables a service"]
    elif any(token in lowered for token in ("user", "group", "account")):
        risk = "dangerous"
        reasons = ["the resource changes local identity or authorization state"]
    elif "firewall" in lowered:
        broad = (
            _is_true(_property(properties, "disabled"))
            or str(_property(properties, "action")).lower() == "allow"
            and str(_property(properties, "remoteAddress", "remoteAddresses")).lower()
            in {"*", "any", "0.0.0.0/0", "::/0"}
        )
        risk = "dangerous" if broad else "review"
        reasons = ["the resource changes host firewall policy"]
    elif any(token in lowered for token in ("registry", "feature", "environment", "archive")):
        reasons = ["the resource changes operating-system or machine-wide state"]
    changes.append(
        _change(
            address,
            "resource_instance",
            risk,
            f"DSC resource {name!r} uses type {resource_type!r}; {reasons[0]}.",
        )
    )
    source = _property(properties, "uri", "url", "source", "path")
    if isinstance(source, str) and source.lower().startswith("http://"):
        changes.append(
            _change(
                f"{address}.source",
                "plaintext_source",
                "dangerous",
                "DSC obtains content over plaintext HTTP, allowing modification in transit.",
            )
        )
    if isinstance(source, str) and _embedded_credential(source):
        changes.append(
            _change(
                f"{address}.source",
                "embedded_source_credential",
                "dangerous",
                "DSC source URL embeds credentials that can leak through logs and configuration.",
            )
        )
    depends_on = resource.get("dependsOn") or _property(properties, "dependsOn")
    if depends_on:
        changes.append(
            _change(
                f"{address}.dependsOn",
                "dependency_order",
                "review",
                "DSC orders this resource after another instance; review failure and rollback "
                "behavior across the dependency edge.",
            )
        )
    changes.extend(_secret_changes(properties, f"{address}.properties"))
    nested = _property(properties, "resources")
    if isinstance(nested, list):
        for index, child in enumerate(nested):
            if isinstance(child, dict) and {"name", "type", "properties"} <= set(child):
                changes.extend(_document_resource_changes(child, f"{address}.resources[{index}]"))
    return changes


def _document_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, resource in enumerate(document["resources"]):
        changes.extend(_document_resource_changes(resource, f"resources[{index}]"))
    changes.extend(_secret_changes(document.get("parameters", {}), "parameters"))
    changes.extend(_secret_changes(document.get("variables", {}), "variables"))
    changes.append(
        _change(
            "dsc.effective_document",
            "evaluation_boundary",
            "review",
            "Static analysis does not invoke DSC resources or resolve parameters, expressions, "
            "adapter behavior, resource schemas, includes, or machine-specific current state.",
        )
    )
    return changes


def _assignment(block: str, name: str) -> str | None:
    match = re.search(rf"(?im)^\s*{re.escape(name)}\s*=\s*([^\r\n;]+)", block)
    return match.group(1).strip() if match else None


def _resource_blocks(source: str) -> list[tuple[int, str, str, str]]:
    pattern = re.compile(
        r"(?im)^\s*([A-Za-z_][\w.-]*)\s+([A-Za-z_$][\w$.-]*)\s*\{"
    )
    ignored = {"configuration", "node", "if", "elseif", "foreach", "while", "switch"}
    blocks: list[tuple[int, str, str, str]] = []
    for match in pattern.finditer(source):
        resource_type = match.group(1)
        if resource_type.lower() in ignored:
            continue
        opening = source.find("{", match.start())
        closing = _matching_brace(source, opening)
        if closing is not None:
            blocks.append(
                (
                    match.start(),
                    resource_type,
                    match.group(2),
                    source[opening + 1 : closing],
                )
            )
    return blocks


def _powershell_resource_changes(
    source: str,
    position: int,
    resource_type: str,
    name: str,
    body: str,
) -> list[dict[str, str]]:
    address = f"source.line.{_line(source, position)}.{resource_type}.{name}"
    lowered = resource_type.lower()
    changes: list[dict[str, str]] = []
    risk = "review"
    explanation = "changes host configuration through a PowerShell DSC resource"
    imperative = re.search(
        r"(?i)\b(?:SetScript|Invoke-Expression|Start-Process)\b",
        body,
    )
    if lowered == "script" or imperative:
        risk = "dangerous"
        explanation = "executes imperative PowerShell during DSC convergence"
    elif lowered in {"package", "xremotefile", "archive"}:
        risk = "dangerous"
        explanation = "downloads, installs, removes, or expands executable content"
    elif lowered == "file" and str(_assignment(body, "Ensure")).strip("'\"").lower() == "absent":
        risk = "dangerous"
        explanation = "removes a filesystem object during convergence"
    elif lowered in {"user", "group"} or "account" in lowered:
        risk = "dangerous"
        explanation = "changes local identity or authorization state"
    elif lowered in {"service", "windowsfeature", "windowsoptionalfeature"}:
        explanation = "changes a service or Windows feature and may disrupt workloads"
    elif "firewall" in lowered or "registry" in lowered or "scheduledtask" in lowered:
        explanation = "changes security-sensitive operating-system policy"
    changes.append(
        _change(
            address,
            "resource_block",
            risk,
            f"PowerShell DSC resource {resource_type} {name} {explanation}.",
        )
    )
    for key in ("Credential", "PsDscRunAsCredential", "Password", "RegistrationKey"):
        value = _assignment(body, key)
        if value:
            changes.append(
                _change(
                    f"{address}.{key}",
                    "privileged_credential" if "credential" in key.lower() else "literal_secret",
                    "dangerous",
                    f"PowerShell DSC resource supplies {key}; review privilege scope and keep "
                    "credential material out of source and compiled MOF files.",
                )
            )
    source_value = next(
        (value for key in ("Uri", "SourcePath", "Path") if (value := _assignment(body, key))),
        None,
    )
    if source_value and "http://" in source_value.lower():
        changes.append(
            _change(
                f"{address}.source",
                "plaintext_source",
                "dangerous",
                "PowerShell DSC downloads or reads content over plaintext HTTP.",
            )
        )
    return changes


def _powershell_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    source = str(document["source"])
    changes: list[dict[str, str]] = []
    imports = list(re.finditer(r"(?im)^\s*Import-DscResource\b([^\r\n]+)", source))
    for match in imports:
        pinned = bool(
            re.search(
                r"(?i)(?:-(?:ModuleVersion|RequiredVersion)\s+|ModuleVersion\s*=\s*)"
                r"['\"][^'\"]+['\"]",
                match.group(1),
            )
        )
        changes.append(
            _change(
                f"source.line.{_line(source, match.start())}.module",
                "module_dependency",
                "review" if pinned else "dangerous",
                "PowerShell DSC imports executable resource code "
                + (
                    "with an explicit version; verify publisher and integrity."
                    if pinned
                    else "without an explicit version pin."
                ),
            )
        )
    nodes = list(re.finditer(r"(?im)^\s*Node\s+([^\{\r\n]+)\s*\{", source))
    for match in nodes:
        target = match.group(1).strip()
        broad = target.strip("'\" ").lower() in {"*", "$allnodes.nodename"}
        changes.append(
            _change(
                f"source.line.{_line(source, match.start())}.node",
                "broad_node_target" if broad else "node_target",
                "dangerous" if broad else "review",
                f"PowerShell DSC configuration targets {target!r}."
                + (
                    " This expression can select every node in configuration data."
                    if broad
                    else " Review resolved node membership."
                ),
            )
        )
    for position, resource_type, name, body in _resource_blocks(source):
        changes.extend(_powershell_resource_changes(source, position, resource_type, name, body))
    rules = (
        (
            r"(?i)PSDscAllowPlainTextPassword\s*=\s*\$?true",
            "plaintext_passwords",
            "DSC configuration data explicitly permits plaintext passwords in compiled "
            "configuration.",
        ),
        (
            r"(?i)ConvertTo-SecureString\b[^\r\n]*-AsPlainText",
            "constructed_plaintext_credential",
            "PowerShell constructs a SecureString from plaintext embedded in source.",
        ),
        (
            r"(?i)ConfigurationMode\s*=\s*['\"]ApplyAndAutoCorrect['\"]",
            "automatic_remediation",
            "The LCM continuously auto-corrects drift without an interactive approval "
            "boundary.",
        ),
        (
            r"(?i)RebootNodeIfNeeded\s*=\s*\$?true",
            "automatic_reboot",
            "The LCM may reboot a node automatically while applying configuration.",
        ),
        (
            r"(?i)(?:ServerURL|ConfigurationNames?)\s*=\s*['\"]http://",
            "plaintext_pull_endpoint",
            "The LCM uses a plaintext HTTP pull or reporting endpoint.",
        ),
        (
            r"(?i)AllowModuleOverwrite\s*=\s*\$?true",
            "module_overwrite",
            "The LCM permits pull service modules to overwrite installed resource code.",
        ),
    )
    for pattern, kind, explanation in rules:
        match = re.search(pattern, source)
        if match:
            changes.append(
                _change(
                    f"source.line.{_line(source, match.start())}.{kind}",
                    kind,
                    "dangerous",
                    explanation,
                )
            )
    changes.append(
        _change(
            "dsc.effective_configuration",
            "compilation_boundary",
            "review",
            "Static analysis does not execute PowerShell, compile MOF, resolve configuration "
            "data, inspect installed DSC resource implementations, or query LCM/current state.",
        )
    )
    return changes


class DscAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "dsc"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("dsc")
        return (
            isinstance(payload, dict)
            and payload.get("artifact_type") in {"document", "powershell"}
            and isinstance(payload.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["dsc"]
        if payload["artifact_type"] == "document":
            return _document_changes(payload["document"])
        return _powershell_changes(payload["document"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"dsc_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_dsc(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = DscAdapter().analyze(data, tool_name="DSC")
    summary = PlanSummary(
        path=Path("dsc://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="DSC")
    gate["adapter"] = "dsc"
    gate["artifact_type"] = data["dsc"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
