from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_LINES = 100_000
_MAX_FINDINGS = 5_000

_RESOURCE = re.compile(
    r"^\s*(?P<type>apt_package|apt_repository|ark|bash|batch|chef_gem|cookbook_file|"
    r"cron|cron_d|deploy|directory|execute|file|firewall_rule|git|group|http_request|"
    r"link|log|mount|package|powershell_script|reboot|remote_directory|remote_file|"
    r"route|ruby_block|script|service|sudo|systemd_unit|template|user|windows_service|"
    r"windows_task|yum_package|yum_repository)\s+"
    r"(?:['\"](?P<name>[^'\"]+)['\"]|(?P<dynamic>(?!do\b)[^\s#]+))",
    re.MULTILINE,
)
_INCLUDE = re.compile(
    r"^\s*(?P<type>include_recipe|include_attribute|require_relative)\s*[(']?['\"]"
    r"(?P<name>[^'\"]+)['\"]",
    re.MULTILINE,
)
_ACTION_BLOCK = re.compile(r"\baction\s+(?P<actions>\[[^\]]+\]|:[a-z_]+)")
_ACTION_NAME = re.compile(r":(?P<action>[a-z_]+)")
_CUSTOM_ACTION = re.compile(
    r"^\s*action\s+:(?P<name>[a-zA-Z_][\w]*)\s+do\b",
    re.MULTILINE,
)
_CUSTOM_PROPERTY = re.compile(
    r"^\s*(?:property|attribute)\s+:(?P<name>[a-zA-Z_][\w]*)\b",
    re.MULTILINE,
)
_PROPERTY = re.compile(
    r"^\s*(?P<name>checksum|command|group|mode|not_if|notifies|only_if|owner|sensitive|"
    r"source|subscribes|user)\s+(?P<value>.+?)\s*$",
    re.MULTILINE,
)
_ATTRIBUTE_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:node\.)?(?P<precedence>force_default|force_override|default|normal|override)!?"
    r"|(?P<node>node))(?P<keys>(?:\s*\[[^\]\r\n]+\])+?)\s*=",
)
_ERB_TAG = re.compile(r"<%(?P<kind>[=#-]?)(?P<code>.*?)(?:-?%>)", re.DOTALL)
_SENSITIVE_TOKENS = (
    "api_key",
    "credential",
    "password",
    "passwd",
    "private_key",
    "secret",
    "token",
)

_EXECUTION_TYPES = {
    "bash",
    "batch",
    "cron",
    "cron_d",
    "execute",
    "powershell_script",
    "ruby_block",
    "script",
    "windows_task",
}
_BOUNDARY_TYPES = {"firewall_rule", "mount", "route"}
_DANGEROUS_TYPES = _EXECUTION_TYPES | _BOUNDARY_TYPES | {"reboot", "sudo"}
_SAFE_TYPES = {"log"}
_DESTRUCTIVE_ACTIONS = {"delete", "disable", "purge", "remove", "restart", "stop"}
_REMOTE_TYPES = {
    "apt_repository",
    "ark",
    "chef_gem",
    "deploy",
    "git",
    "http_request",
    "remote_directory",
    "remote_file",
    "yum_repository",
}
_IDENTITY_TYPES = {"group", "user"}
_ARTIFACT_DIRECTORIES = {
    "attributes": "attribute_file",
    "definitions": "definition",
    "libraries": "library",
    "providers": "provider",
    "recipes": "recipe",
    "resources": "custom_resource",
    "templates": "template",
}
_BOUNDARY_EXPLANATIONS = {
    "attribute_file": (
        "Chef cookbook attributes participate in node configuration and precedence; review their "
        "effective values across roles, environments, recipes, and Ohai data."
    ),
    "custom_resource": (
        "Chef custom resources define reusable convergence actions; review action code, "
        "current-value loading, desired-state properties, and every call site."
    ),
    "definition": (
        "Legacy Chef definitions expand reusable recipe code at compile time; review expanded "
        "resources and migrate obsolete definition behavior where practical."
    ),
    "library": (
        "Chef cookbook libraries load arbitrary Ruby into Chef Infra Client and may extend "
        "built-in classes; review trust, side effects, and every caller."
    ),
    "provider": (
        "Legacy Chef providers implement convergence with Ruby and node-side operations; review "
        "execution, idempotence, and privilege boundaries."
    ),
    "template": (
        "Chef ERB template output is applied by a referencing template resource; review the target "
        "path, permissions, variables, helpers, and partials in that external context."
    ),
}

_RUBY_RISKS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    (
        "command_execution",
        re.compile(
            r"(?:\b(?:exec|spawn|system)\s*(?:\(|\s)|\b(?:shell_out|shell_out!)\s*(?:\(|\s)|"
            r"\bMixlib::ShellOut\b|\bIO\.popen\b|\bOpen3\.(?:capture|pipeline|popen)|`|%x\s*[({[])",
            re.IGNORECASE,
        ),
        "dangerous",
        "Cookbook Ruby can execute an arbitrary operating-system command during compile "
        "or converge.",
    ),
    (
        "direct_file_mutation",
        re.compile(
            r"\b(?:File|IO)\.(?:chmod|chown|delete|rename|truncate|unlink|write|binwrite)\b",
            re.IGNORECASE,
        ),
        "dangerous",
        "Cookbook Ruby directly mutates the filesystem outside Chef resource convergence tracking.",
    ),
    (
        "dynamic_evaluation",
        re.compile(r"\b(?:class_eval|eval|instance_eval|module_eval)\s*(?:\(|\s)", re.IGNORECASE),
        "dangerous",
        "Cookbook Ruby dynamically evaluates code, obscuring the effective convergence behavior.",
    ),
    (
        "external_runtime_access",
        re.compile(
            r"\b(?:Net::HTTP|TCPSocket|UDPSocket|URI\.(?:open|parse)|OpenURI|Sequel\.|PG\.|Mysql2::)",
            re.IGNORECASE,
        ),
        "dangerous",
        "Cookbook Ruby accesses an external network or data service during Chef execution.",
    ),
    (
        "secret_lookup",
        re.compile(
            r"\b(?:chef_vault_item|data_bag_item|encrypted_data_bag_item|Chef::EncryptedDataBagItem)\b",
            re.IGNORECASE,
        ),
        "review",
        "Cookbook Ruby loads external or encrypted data; review authorization and downstream "
        "secret handling.",
    ),
    (
        "runtime_data_access",
        re.compile(
            r"(?:\bENV\s*\[|\b(?:File|IO)\.(?:binread|foreach|read)\b|"
            r"\bDir\.(?:entries|glob)\b|\bnode\.run_state\b)",
            re.IGNORECASE,
        ),
        "review",
        "Cookbook Ruby reads process, filesystem, or transient node data outside declared "
        "resource properties; review provenance and secret handling.",
    ),
    (
        "chef_server_query",
        re.compile(
            r"(?:\b(?:partial_search|search)\s*\(|\bChef::Search::Query\b)",
            re.IGNORECASE,
        ),
        "review",
        "Cookbook Ruby queries Chef Server state whose authorization, result set, and live values "
        "are external to this artifact.",
    ),
    (
        "event_handler",
        re.compile(
            r"(?:\bChef\.event_handler\b|\bChef::Config\.event_handlers\b|\bat_exit\b)",
            re.IGNORECASE,
        ),
        "dangerous",
        "Cookbook Ruby registers lifecycle code that can run after convergence or failure and "
        "change node-side behavior.",
    ),
    (
        "dynamic_dependency",
        re.compile(r"\b(?:autoload|load|require|require_relative)\s*(?:\(|\s)", re.IGNORECASE),
        "review",
        "Cookbook Ruby loads code not expanded in this artifact; review dependency provenance "
        "and load paths.",
    ),
    (
        "chef_extension",
        re.compile(r"^\s*(?:class|module)\s+Chef(?:::|\b)", re.IGNORECASE),
        "dangerous",
        "Cookbook Ruby extends or reopens Chef classes, changing runtime behavior beyond "
        "this artifact.",
    ),
)


class ChefInputError(ValueError):
    """Raised when Chef source is unsafe, oversized, or not recognizable."""


def _validate_source(source: str) -> None:
    if not isinstance(source, str):
        raise ChefInputError("source must be text")
    if "\x00" in source:
        raise ChefInputError("input contains a NUL byte")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise ChefInputError("source size limit exceeded")
    if source.count("\n") + 1 > _MAX_SOURCE_LINES:
        raise ChefInputError("source line limit exceeded")
    if not source.strip():
        raise ChefInputError("input is empty")


def _artifact_type(filename: str | None) -> str | None:
    if not filename:
        return None
    normalized = filename.replace("\\", "/").casefold().strip("/")
    parts = tuple(part for part in normalized.split("/") if part)
    for part in reversed(parts[:-1]):
        if part in _ARTIFACT_DIRECTORIES:
            artifact = _ARTIFACT_DIRECTORIES[part]
            if artifact == "template" or parts[-1].endswith((".rb", ".erb")):
                return artifact
            return None
    return None


def _strip_ruby_comments(source: str) -> str:
    """Remove line comments while preserving strings, offsets, and newlines."""
    result = list(source)
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(source):
        character = source[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
        elif character == "#":
            while index < len(source) and source[index] not in "\r\n":
                result[index] = " "
                index += 1
            continue
        index += 1
    return "".join(result)


def _mask_ruby_strings(source: str) -> str:
    """Mask string bodies after comments are removed, retaining executable delimiters."""
    result = list(source)
    quote: str | None = None
    escaped = False
    for index, character in enumerate(source):
        if quote is None:
            if character in {"'", '"', "`"}:
                quote = character
            continue
        if character in "\r\n":
            continue
        if escaped:
            result[index] = " "
            escaped = False
        elif character == "\\":
            result[index] = " "
            escaped = True
        elif character == quote:
            quote = None
        else:
            result[index] = " "
    return "".join(result)


def _metadata(source: str, artifact_type: str) -> dict[str, int | str]:
    without_comments = _strip_ruby_comments(source)
    code = _mask_ruby_strings(without_comments)
    action_count = len(_CUSTOM_ACTION.findall(code))
    property_count = len(_CUSTOM_PROPERTY.findall(code))
    resource_count = len(_RESOURCE.findall(without_comments))
    dynamic_count = 0
    if artifact_type == "template":
        tags = [match for match in _ERB_TAG.finditer(source) if match.group("kind") != "#"]
        action_count = len(tags)
        dynamic_count = len(tags)
    else:
        for line in code.splitlines():
            dynamic_count += sum(bool(pattern.search(line)) for _, pattern, _, _ in _RUBY_RISKS)
    return {
        "artifact_type": artifact_type,
        "line_count": source.count("\n") + 1,
        "resource_count": resource_count,
        "action_count": action_count,
        "property_count": property_count,
        "dynamic_count": dynamic_count,
    }


def parse_chef(source: str, filename: str | None = None) -> dict[str, Any]:
    """Parse Chef recipe and cookbook content using bounded static inspection only."""
    _validate_source(source)
    artifact_type = _artifact_type(filename)
    without_comments = _strip_ruby_comments(source)
    if artifact_type is None and (
        _RESOURCE.search(without_comments) or _INCLUDE.search(without_comments)
    ):
        artifact_type = "recipe"
    if artifact_type is None:
        raise ChefInputError("input is not recognized as Chef cookbook content")
    return {
        "chef_recipe": source,
        "chef_artifact_type": artifact_type,
        "chef_metadata": _metadata(source, artifact_type),
    }


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _generic_change(
    artifact_type: str,
    line: int,
    finding_type: str,
    risk: str,
    explanation: str,
) -> dict[str, Any]:
    return {
        "Type": finding_type,
        "Name": finding_type,
        "Actions": ["inspect"],
        "Address": f"{artifact_type}:{line}",
        "Properties": {},
        "Risk": risk,
        "Explanation": explanation,
        "Generic": True,
    }


class ChefAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "chef"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        source = input_data.get("chef_recipe")
        if not isinstance(source, str):
            return False
        if input_data.get("chef_artifact_type") in set(_ARTIFACT_DIRECTORIES.values()):
            return bool(source.strip())
        without_comments = _strip_ruby_comments(source)
        return bool(_RESOURCE.search(without_comments) or _INCLUDE.search(without_comments))

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        source = str(input_data.get("chef_recipe", ""))
        artifact_type = str(input_data.get("chef_artifact_type") or "recipe")
        without_comments = _strip_ruby_comments(source)
        lines = without_comments.splitlines()
        changes: list[dict[str, Any]] = []

        if artifact_type in _BOUNDARY_EXPLANATIONS:
            changes.append(
                _generic_change(
                    artifact_type,
                    1,
                    f"{artifact_type}_boundary",
                    "review",
                    _BOUNDARY_EXPLANATIONS[artifact_type],
                )
            )

        for index, line in enumerate(lines):
            match = _RESOURCE.match(line)
            if not match:
                continue
            block_lines = [line]
            if re.search(r"\bdo\s*(?:\|[^|]*\|)?\s*$", line):
                for candidate in lines[index + 1 :]:
                    block_lines.append(candidate)
                    if candidate.strip() == "end":
                        break
            block = "\n".join(block_lines)
            action_block = _ACTION_BLOCK.search(block)
            actions = (
                _ACTION_NAME.findall(action_block.group("actions"))
                if action_block
                else ["converge"]
            )
            properties: dict[str, list[str]] = {}
            for property_match in _PROPERTY.finditer(block):
                properties.setdefault(property_match.group("name"), []).append(
                    property_match.group("value")
                )
            changes.append(
                {
                    "Type": match.group("type"),
                    "Name": match.group("name") or "<dynamic>",
                    "Actions": actions,
                    "Address": f"{artifact_type}:{index + 1}",
                    "Properties": properties,
                }
            )

        for match in _INCLUDE.finditer(without_comments):
            changes.append(
                {
                    "Type": match.group("type"),
                    "Name": match.group("name"),
                    "Actions": ["include"],
                    "Address": f"{artifact_type}:{_line_number(without_comments, match.start())}",
                    "Properties": {},
                }
            )

        if artifact_type == "attribute_file":
            changes.extend(self._attribute_changes(without_comments))
        elif artifact_type == "custom_resource":
            changes.extend(self._custom_resource_changes(without_comments))

        if artifact_type == "template":
            changes.extend(self._template_changes(source))
        else:
            changes.extend(self._ruby_changes(without_comments, artifact_type))

        if len(changes) > _MAX_FINDINGS:
            raise ChefInputError("finding count limit exceeded")
        return changes

    @staticmethod
    def _ruby_changes(source: str, artifact_type: str) -> list[dict[str, Any]]:
        code = _mask_ruby_strings(source)
        changes: list[dict[str, Any]] = []
        for line_number, line in enumerate(code.splitlines(), start=1):
            for finding_type, pattern, risk, explanation in _RUBY_RISKS:
                if pattern.search(line):
                    changes.append(
                        _generic_change(
                            artifact_type,
                            line_number,
                            finding_type,
                            risk,
                            explanation,
                        )
                    )
        return changes

    @staticmethod
    def _attribute_changes(source: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for line_number, line in enumerate(source.splitlines(), start=1):
            match = _ATTRIBUTE_ASSIGNMENT.match(line)
            if not match:
                continue
            precedence = match.group("precedence") or "implicit_normal"
            lowered_keys = match.group("keys").casefold()
            sensitive = any(token in lowered_keys for token in _SENSITIVE_TOKENS)
            high_precedence = precedence in {
                "force_default",
                "force_override",
                "normal",
                "override",
                "implicit_normal",
            }
            risk = "dangerous" if high_precedence or sensitive else "review"
            explanation = (
                "Chef assigns a high-precedence or persistent node attribute that can override "
                "environment, role, or lower-precedence cookbook intent."
                if high_precedence
                else (
                    "Chef assigns a default node attribute; review its effective value and "
                    "source order."
                )
            )
            if sensitive:
                explanation += (
                    " The attribute key appears credential-related; keep secret values out of "
                    "cookbook source and logs."
                )
            changes.append(
                _generic_change(
                    "attribute_file",
                    line_number,
                    "attribute_assignment",
                    risk,
                    explanation,
                )
            )
        return changes

    @staticmethod
    def _custom_resource_changes(source: str) -> list[dict[str, Any]]:
        code = _mask_ruby_strings(source)
        changes: list[dict[str, Any]] = []
        source_lines = source.splitlines()
        for line_number, line in enumerate(code.splitlines(), start=1):
            if _CUSTOM_ACTION.match(line):
                changes.append(
                    _generic_change(
                        "custom_resource",
                        line_number,
                        "custom_resource_action",
                        "review",
                        "Chef custom-resource action code converges managed nodes; review "
                        "idempotence, privilege, notifications, and nested resources.",
                    )
                )
            property_match = _CUSTOM_PROPERTY.match(line)
            if property_match:
                raw_line = source_lines[line_number - 1] if line_number <= len(source_lines) else ""
                sensitive_name = any(
                    token in property_match.group("name").casefold() for token in _SENSITIVE_TOKENS
                )
                declares_sensitive = bool(re.search(r"\bsensitive\s*:\s*true\b", raw_line))
                if sensitive_name:
                    changes.append(
                        _generic_change(
                            "custom_resource",
                            line_number,
                            "sensitive_property",
                            "review" if declares_sensitive else "dangerous",
                            (
                                "Chef custom-resource property appears credential-related and is "
                                "marked sensitive; review all downstream handling."
                                if declares_sensitive
                                else (
                                    "Chef custom-resource property appears credential-related "
                                    "without sensitive metadata, risking disclosure in logs and "
                                    "diffs."
                                )
                            ),
                        )
                    )
            if re.search(r"\bload_current_value\??\s+do\b", line):
                changes.append(
                    _generic_change(
                        "custom_resource",
                        line_number,
                        "current_value_loader",
                        "review",
                        "Chef loads current node state with Ruby before convergence; review "
                        "external reads, authorization, and idempotence.",
                    )
                )
            if re.search(r"\bconverge_by\s*(?:\(|\s|do\b)", line):
                changes.append(
                    _generic_change(
                        "custom_resource",
                        line_number,
                        "custom_convergence",
                        "review",
                        "Chef wraps custom Ruby convergence outside a built-in resource; review "
                        "side effects and why-run behavior.",
                    )
                )
        return changes

    @staticmethod
    def _template_changes(source: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for match in _ERB_TAG.finditer(source):
            if match.group("kind") == "#":
                continue
            line = _line_number(source, match.start())
            code = _mask_ruby_strings(_strip_ruby_comments(match.group("code")))
            kind = "template_expression" if match.group("kind") == "=" else "template_statement"
            changes.append(
                _generic_change(
                    "template",
                    line,
                    kind,
                    "review",
                    "Chef evaluates embedded Ruby while rendering this template; review variables, "
                    "helpers, partials, and rendered-file exposure.",
                )
            )
            if any(token in match.group("code").casefold() for token in _SENSITIVE_TOKENS):
                changes.append(
                    _generic_change(
                        "template",
                        line,
                        "sensitive_template_value",
                        "dangerous",
                        "Chef template references a credential-like value that may be written to "
                        "the rendered file or exposed in diagnostics.",
                    )
                )
            for finding_type, pattern, risk, explanation in _RUBY_RISKS:
                if pattern.search(code):
                    changes.append(
                        _generic_change("template", line, finding_type, risk, explanation)
                    )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        resource = str(raw.get("Type", "unknown"))
        actions = tuple(str(action) for action in raw.get("Actions", ["converge"]))
        if raw.get("Generic") is True:
            return ResourceChange(
                address=str(raw.get("Address", "chef")),
                resource_type=f"chef_{resource}",
                actions=actions,
                risk=str(raw.get("Risk", "review")),
                explanation=str(raw.get("Explanation", "Chef cookbook content requires review.")),
            )
        properties = raw.get("Properties")
        properties = properties if isinstance(properties, dict) else {}
        risk = "review"
        explanation = (
            f"Chef resource '{resource}' converges system configuration; review desired state."
        )
        if resource in _SAFE_TYPES:
            risk = "safe"
            explanation = "Chef log resources report information without changing infrastructure."
        elif resource in _DANGEROUS_TYPES:
            risk = "dangerous"
            if resource in _EXECUTION_TYPES:
                explanation = (
                    f"Chef resource '{resource}' can execute arbitrary or scheduled code "
                    "during convergence."
                )
            elif resource in _BOUNDARY_TYPES:
                explanation = (
                    f"Chef resource '{resource}' changes network, routing, or mounted-storage "
                    "boundaries."
                )
            elif resource == "reboot":
                explanation = "Chef can reboot the managed node and interrupt availability."
            else:
                explanation = "Chef changes sudo policy and local privilege boundaries."
        elif resource in _IDENTITY_TYPES:
            risk = "dangerous"
            explanation = f"Chef resource '{resource}' changes local identity or group membership."
        elif resource in _REMOTE_TYPES:
            explanation = (
                f"Chef resource '{resource}' retrieves or deploys external content; review "
                "source trust, version pinning, checksum verification, and credentials."
            )
            source_values = " ".join(properties.get("source", []))
            if ("http://" in source_values or "latest" in source_values) and not properties.get(
                "checksum"
            ):
                risk = "dangerous"
                explanation += " The source is mutable or unencrypted and has no checksum."
        elif resource in {"include_recipe", "include_attribute", "require_relative"}:
            explanation = (
                f"Chef '{resource}' loads code or attributes not expanded in this recipe; "
                "review the referenced cookbook and dependency lock."
            )
        elif destructive := next(
            (action for action in actions if action in _DESTRUCTIVE_ACTIONS), None
        ):
            risk = "dangerous"
            explanation = (
                f"Chef resource '{resource}' requests availability-changing action '{destructive}'."
            )
        if any("immediately" in value for value in properties.get("notifies", [])):
            risk = "dangerous"
            explanation += " It immediately notifies another resource during convergence."
        if properties.get("only_if") or properties.get("not_if"):
            risk = "dangerous"
            explanation += " Shell or Ruby guard code can execute while deciding convergence."
        if any("0777" in value or "'777'" in value for value in properties.get("mode", [])):
            risk = "dangerous"
            explanation += " It requests world-writable file permissions."
        return ResourceChange(
            address=str(raw.get("Address", raw.get("Name", "recipe"))),
            resource_type=f"chef_{resource}",
            actions=actions,
            risk=risk,
            explanation=explanation,
        )


def analyze_chef(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = ChefAdapter().analyze(data, tool_name="Chef")
    summary = PlanSummary(
        path=Path("chef://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Chef")
    gate["adapter"] = "chef"
    gate["total_changes"] = len(changes)
    metadata = data.get("chef_metadata")
    if not isinstance(metadata, dict):
        source = str(data.get("chef_recipe", ""))
        artifact_type = str(data.get("chef_artifact_type") or "recipe")
        metadata = _metadata(source, artifact_type)
    for key in (
        "artifact_type",
        "line_count",
        "resource_count",
        "action_count",
        "property_count",
        "dynamic_count",
    ):
        if isinstance(metadata.get(key), (str, int)):
            gate[key] = metadata[key]
    return gate
