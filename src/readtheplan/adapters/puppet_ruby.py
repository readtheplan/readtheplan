from __future__ import annotations

import re
from bisect import bisect_right
from pathlib import PurePosixPath
from typing import Any


class PuppetRubyInputError(ValueError):
    """Raised when Puppet Ruby extension source cannot be inspected safely."""


_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_LINES = 100_000
_MAX_FINDINGS = 2_000
_SECRET_NAME = re.compile(
    r"(?:password|passwd|token|secret|private_?key|client_?secret|api_?key|credential)",
    re.IGNORECASE,
)
_INTERPOLATION = re.compile(r"#\{")


def puppet_ruby_metadata(filename: str | None) -> dict[str, str] | None:
    """Classify a documented Puppet Ruby module plug-in path."""
    if not filename:
        return None
    path = PurePosixPath(filename.replace("\\", "/"))
    if path.suffix.casefold() != ".rb":
        return None
    parts = tuple(part.casefold() for part in path.parts)
    lib_indexes = [index for index, part in enumerate(parts[:-1]) if part == "lib"]
    if not lib_indexes:
        return None
    index = lib_indexes[-1]
    component_name = path.stem

    if len(parts) > index + 2 and parts[index + 1] == "facter":
        relative = parts[index + 2 : -1] + (path.stem,)
        return {
            "artifact_type": "ruby_extension",
            "component_name": "::".join(relative),
            "extension_type": "custom_fact",
            "language": "ruby",
            "source_kind": "agent_fact",
        }
    if len(parts) <= index + 3 or parts[index + 1] != "puppet":
        return None

    extension_parts = parts[index + 2 : -1]
    if extension_parts[:2] == ("parser", "functions"):
        namespace = extension_parts[2:] + (component_name,)
        return {
            "artifact_type": "ruby_extension",
            "component_name": "::".join(namespace),
            "extension_type": "legacy_function",
            "language": "ruby",
            "source_kind": "server_compile_function",
        }
    definitions = {
        "functions": ("ruby_function", "server_compile_function"),
        "provider": ("resource_provider", "server_agent_provider"),
        "reports": ("report_processor", "server_report_processor"),
        "type": ("resource_type", "server_agent_type"),
    }
    category = extension_parts[0]
    definition = definitions.get(category)
    if definition is None:
        return None
    namespace = extension_parts[1:] + (component_name,)
    return {
        "artifact_type": "ruby_extension",
        "component_name": "::".join(namespace),
        "extension_type": definition[0],
        "language": "ruby",
        "source_kind": definition[1],
    }


def is_puppet_ruby_extension(filename: str | None) -> bool:
    return puppet_ruby_metadata(filename) is not None


def _mask_ruby(source: str) -> str:
    """Mask Ruby comments and quoted bodies while preserving offsets and newlines."""
    result = list(source)
    quote: str | None = None
    escaped = False
    block_comment = False
    line_start = True
    index = 0
    while index < len(source):
        character = source[index]
        if character in "\r\n":
            line_start = True
            index += 1
            continue
        if block_comment:
            if line_start and source.startswith("=end", index) and (
                index + 4 == len(source) or source[index + 4].isspace()
            ):
                while index < len(source) and source[index] not in "\r\n":
                    result[index] = " "
                    index += 1
                block_comment = False
            else:
                result[index] = " "
                line_start = False
                index += 1
            continue
        if quote is not None:
            if escaped:
                if character not in "\r\n":
                    result[index] = " "
                escaped = False
            elif character == "\\":
                result[index] = " "
                escaped = True
            elif character == quote:
                quote = None
            else:
                result[index] = " "
            line_start = False
            index += 1
            continue
        if line_start and source.startswith("=begin", index) and (
            index + 6 == len(source) or source[index + 6].isspace()
        ):
            block_comment = True
            while index < len(source) and source[index] not in "\r\n":
                result[index] = " "
                index += 1
            continue
        line_start = False
        if character in {"'", '"', "`"}:
            quote = character
            index += 1
            continue
        if character == "#":
            while index < len(source) and source[index] not in "\r\n":
                result[index] = " "
                index += 1
            continue
        index += 1
    if quote is not None or block_comment:
        raise PuppetRubyInputError("unterminated Ruby string or block comment")
    return "".join(result)


_RUBY_FINDINGS: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    (
        "dynamic_execution",
        "dangerous",
        re.compile(
            r"(?<![.\w])(?:eval|instance_eval|class_eval|module_eval)\s*(?:\(|\b)",
            re.IGNORECASE,
        ),
        "The extension dynamically evaluates Ruby code; runtime values can change executed "
        "behavior.",
    ),
    (
        "process_execution",
        "dangerous",
        re.compile(
            r"(?<![.\w])(?:system|exec|spawn)\s*(?:\(|\s)|"
            r"\b(?:IO\.popen|Open3\.[A-Za-z_]+)\s*\(|`|%x\s*[^A-Za-z0-9\s]|"
            r"\b(?:Facter::Core::Execution|Puppet::Util(?::Execution)?)\.execute\s*\(",
            re.IGNORECASE,
        ),
        "The extension starts a process or shell command; review argument separation, input "
        "validation, identity, and exit handling.",
    ),
    (
        "provider_command",
        "dangerous",
        re.compile(r"^\s*commands?\s+:[A-Za-z_][A-Za-z0-9_]*\s*=>", re.MULTILINE),
        "The provider declares an external command that can execute while reading or changing "
        "target state.",
    ),
    (
        "destructive_filesystem",
        "dangerous",
        re.compile(
            r"\b(?:FileUtils\.(?:rm|rm_f|rm_rf|rmtree|remove_dir)|"
            r"File\.(?:delete|unlink|truncate))\s*\(",
            re.IGNORECASE,
        ),
        "The extension deletes or truncates filesystem content.",
    ),
    (
        "filesystem_mutation",
        "dangerous",
        re.compile(
            r"\b(?:File\.(?:write|binwrite|rename|chmod|chown)|"
            r"FileUtils\.(?:cp|cp_r|mv|mkdir|mkdir_p|chmod|chown)|IO\.write)\s*\(",
            re.IGNORECASE,
        ),
        "The extension writes, moves, or changes permissions on filesystem content.",
    ),
    (
        "network_access",
        "dangerous",
        re.compile(
            r"\b(?:Net::HTTP|OpenURI|TCPSocket|UDPSocket|RestClient|Faraday|"
            r"Puppet::HTTP::Client)\b|\bURI\.(?:open|parse)\s*\(",
            re.IGNORECASE,
        ),
        "The extension opens a network or external-service boundary; review endpoint trust, "
        "TLS, credentials, timeouts, and response handling.",
    ),
    (
        "tls_verification_disabled",
        "dangerous",
        re.compile(
            r"\b(?:verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE|"
            r"verify_(?:ssl|peer|cert(?:ificate)?)\s*(?:=>|=)\s*false)\b",
            re.IGNORECASE,
        ),
        "TLS certificate or peer verification is explicitly disabled.",
    ),
    (
        "unsafe_deserialization",
        "dangerous",
        re.compile(r"\b(?:YAML|Marshal)\.(?:load|unsafe_load|restore)\s*\(", re.IGNORECASE),
        "The extension uses a deserializer that can construct executable or attacker-controlled "
        "objects.",
    ),
    (
        "privilege_change",
        "dangerous",
        re.compile(r"\bProcess::Sys\.set(?:e|re|res)?(?:uid|gid)\s*\(", re.IGNORECASE),
        "The extension changes its process identity or group privileges.",
    ),
    (
        "catalog_mutation",
        "dangerous",
        re.compile(
            r"\b(?:catalog|closure_scope\.compiler\.catalog)\."
            r"(?:add_resource|add_class|add_edge|remove_resource)\s*\(",
            re.IGNORECASE,
        ),
        "The function directly mutates the compiled catalog rather than only returning a value.",
    ),
    (
        "runtime_data_access",
        "review",
        re.compile(
            r"\bENV\s*\[|\b(?:File|IO)\.(?:binread|foreach|read|readlines)\s*\(|"
            r"\bDir\.(?:entries|glob)\s*\(|\bFacter\.value\s*\(",
            re.IGNORECASE,
        ),
        "The extension reads environment, filesystem, directory, or fact data resolved at runtime.",
    ),
    (
        "dynamic_dependency",
        "review",
        re.compile(r"^\s*(?:autoload|load|require|require_relative)\s*(?:\(|\s)", re.MULTILINE),
        "The extension loads code not expanded in this artifact; review dependency provenance "
        "and load paths.",
    ),
    (
        "dynamic_dispatch",
        "review",
        re.compile(r"\b(?:send|public_send|const_get)\s*\(", re.IGNORECASE),
        "The extension dynamically selects a method or constant; runtime values influence the "
        "call graph.",
    ),
)


def _line_starts(source: str) -> list[int]:
    starts = [0]
    starts.extend(match.end() for match in re.finditer(r"\n", source))
    return starts


def _finding(
    *, kind: str, risk: str, explanation: str, line: int, occurrence: int
) -> dict[str, str]:
    return {
        "Action": "execute",
        "Address": f"puppet_ruby.line.{line}.{kind}.{occurrence}",
        "Kind": kind,
        "Risk": risk,
        "Explanation": f"Line {line}: {explanation}",
    }


def _append_finding(
    findings: list[dict[str, str]],
    *,
    kind: str,
    risk: str,
    explanation: str,
    line: int = 1,
) -> None:
    if len(findings) >= _MAX_FINDINGS:
        raise PuppetRubyInputError("Puppet Ruby source exceeds the finding count limit")
    findings.append(
        _finding(
            kind=kind,
            risk=risk,
            explanation=explanation,
            line=line,
            occurrence=len(findings) + 1,
        )
    )


def _pattern_findings(source: str, masked: str) -> list[dict[str, str]]:
    starts = _line_starts(masked)
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, int]] = set()
    for kind, risk, pattern, explanation in _RUBY_FINDINGS:
        for match in pattern.finditer(masked):
            line = bisect_right(starts, match.start())
            key = (kind, line)
            if key in seen:
                continue
            seen.add(key)
            _append_finding(
                findings,
                kind=kind,
                risk=risk,
                explanation=explanation,
                line=line,
            )
    comment_free = _strip_comments_only(source)
    comment_free_starts = _line_starts(comment_free)
    for match in _INTERPOLATION.finditer(comment_free):
        line = bisect_right(comment_free_starts, match.start())
        key = ("dynamic_interpolation", line)
        if key in seen:
            continue
        seen.add(key)
        _append_finding(
            findings,
            kind="dynamic_interpolation",
            risk="review",
            explanation=(
                "Ruby string interpolation evaluates an expression at runtime; review values "
                "that flow into commands, paths, logs, or network requests."
            ),
            line=line,
        )
    return findings


def _strip_comments_only(source: str) -> str:
    """Mask comments while retaining strings for interpolation detection."""
    result = list(source)
    quote: str | None = None
    escaped = False
    block_comment = False
    line_start = True
    index = 0
    while index < len(source):
        character = source[index]
        if character in "\r\n":
            line_start = True
            index += 1
            continue
        if block_comment:
            if line_start and source.startswith("=end", index) and (
                index + 4 == len(source) or source[index + 4].isspace()
            ):
                while index < len(source) and source[index] not in "\r\n":
                    result[index] = " "
                    index += 1
                block_comment = False
            else:
                result[index] = " "
                line_start = False
                index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            line_start = False
            index += 1
            continue
        if line_start and source.startswith("=begin", index) and (
            index + 6 == len(source) or source[index + 6].isspace()
        ):
            block_comment = True
            while index < len(source) and source[index] not in "\r\n":
                result[index] = " "
                index += 1
            continue
        line_start = False
        if character in {"'", '"', "`"}:
            quote = character
            index += 1
            continue
        if character == "#":
            while index < len(source) and source[index] not in "\r\n":
                result[index] = " "
                index += 1
            continue
        index += 1
    return "".join(result)


def _interface_findings(
    document: dict[str, Any], masked: str, findings: list[dict[str, str]]
) -> None:
    extension_type = document["extension_type"]
    interfaces = {
        "custom_fact": (r"\bFacter\.add\s*\(", "Facter.add"),
        "legacy_function": (r"\bnewfunction\s*\(", "newfunction"),
        "report_processor": (r"\bPuppet::Reports\.register_report\s*\(", "register_report"),
        "resource_provider": (r"\.provide\s*\(", "Puppet provider registration"),
        "resource_type": (r"\bPuppet::Type\.newtype\s*\(", "Puppet type registration"),
        "ruby_function": (r"\bPuppet::Functions\.create_function\s*\(", "create_function"),
    }
    pattern, interface = interfaces[extension_type]
    if re.search(pattern, masked) is None:
        _append_finding(
            findings,
            kind="extension_interface",
            risk="review",
            explanation=(
                f"The conventional {extension_type.replace('_', ' ')} path does not visibly "
                f"use {interface}; verify autoloading, registration, and compatibility."
            ),
        )

    if extension_type == "custom_fact":
        if re.search(r"\bconfine\b", masked) is None:
            _append_finding(
                findings,
                kind="fact_platform_scope",
                risk="review",
                explanation=(
                    "The custom fact has no visible confinement; it can be considered across "
                    "all synced agent platforms."
                ),
            )
        high_latency = any(
            finding["Kind"] in {"network_access", "process_execution"} for finding in findings
        )
        if high_latency and re.search(r"\b(?:timeout|limit)\b", masked, re.IGNORECASE) is None:
            _append_finding(
                findings,
                kind="fact_resolution_timeout",
                risk="dangerous",
                explanation=(
                    "The fact performs process or network work without a visible timeout/limit; "
                    "fact collection can delay or block agent runs."
                ),
            )
    elif extension_type == "report_processor":
        if re.search(r"\bdef\s+process\b", masked) is None:
            _append_finding(
                findings,
                kind="report_process_interface",
                risk="review",
                explanation="The report processor does not visibly define its process method.",
            )
        for match in re.finditer(r"\b(?:self\.)?to_(?:yaml|json)\b", masked, re.IGNORECASE):
            _append_finding(
                findings,
                kind="report_serialization",
                risk="review",
                explanation=(
                    "The processor serializes report data; verify secret redaction, destination "
                    "authorization, schema stability, and retained copies."
                ),
                line=bisect_right(_line_starts(masked), match.start()),
            )
    elif extension_type in {"ruby_function", "legacy_function"} and re.search(
        r"\b(?:closure_scope|scope)\b", masked
    ):
        _append_finding(
            findings,
            kind="compiler_scope_access",
            risk="review",
            explanation=(
                "The function accesses compiler scope/catalog context; runtime variables and "
                "catalog state influence behavior beyond explicit parameters."
            ),
        )

    for line_number, line in enumerate(masked.splitlines(), start=1):
        assignment = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if assignment and _SECRET_NAME.search(assignment.group(1)):
            _append_finding(
                findings,
                kind="secret_handling",
                risk="review",
                explanation=(
                    "A secret-like value is assigned; verify redaction, logging, storage lifetime, "
                    "and exception handling."
                ),
                line=line_number,
            )


def parse_puppet_ruby_extension(source: str, filename: str | None) -> dict[str, Any]:
    """Inspect Puppet Ruby plug-in source without loading or executing it."""
    metadata = puppet_ruby_metadata(filename)
    if metadata is None:
        raise PuppetRubyInputError("path is not a supported Puppet Ruby extension")
    if not source.strip():
        raise PuppetRubyInputError("input is empty")
    if "\x00" in source:
        raise PuppetRubyInputError("input contains a NUL byte")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise PuppetRubyInputError("Puppet Ruby source exceeds the source size limit")
    line_count = source.count("\n") + 1
    if line_count > _MAX_SOURCE_LINES:
        raise PuppetRubyInputError("Puppet Ruby source exceeds the line count limit")

    masked = _mask_ruby(source)
    document: dict[str, Any] = {
        **metadata,
        "source_line_count": line_count,
    }
    findings = _pattern_findings(source, masked)
    _interface_findings(document, masked, findings)
    document["findings"] = findings
    return document


def puppet_ruby_extension_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    findings = list(document["findings"])
    source_kind = document["source_kind"]
    boundaries = {
        "agent_fact": (
            "This custom fact runs Ruby during fact collection on every applicable synced agent; "
            "review host data access, latency, platform confinement, privileges, and returned data."
        ),
        "server_compile_function": (
            "This Ruby function executes in Puppet Server during catalog compilation; review "
            "compiler-side credentials, network/filesystem access, side effects, and JRuby safety."
        ),
        "server_agent_provider": (
            "This provider implements target-state discovery and mutation and can load on Puppet "
            "Server and agents; review command execution, idempotence, identity, and pluginsync."
        ),
        "server_agent_type": (
            "This custom type defines resource validation and synchronization behavior loaded by "
            "Puppet Server and agents; review callbacks, side effects, and provider contracts."
        ),
        "server_report_processor": (
            "This report processor executes on the primary server for submitted reports; review "
            "report-data sensitivity, external destinations, failure handling, and throughput."
        ),
    }
    safe_component = re.sub(r"[^A-Za-z0-9_.:-]+", "_", document["component_name"])
    findings.append(
        {
            "Action": "execute",
            "Address": f"puppet_ruby.{source_kind}.{safe_component}.execution",
            "Kind": "extension_execution_boundary",
            "Risk": "review",
            "Explanation": boundaries[source_kind],
        }
    )
    return findings
