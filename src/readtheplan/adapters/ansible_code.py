from __future__ import annotations

import re
import tokenize
from bisect import bisect_right
from io import StringIO
from pathlib import PurePosixPath
from typing import Any


class AnsibleCodeInputError(ValueError):
    """Raised when Ansible executable source is unsupported or unsafe to inspect."""


_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_LINES = 100_000
_MAX_FINDINGS = 2_000
_PYTHON_PLUGIN_TYPES = {
    "action",
    "become",
    "cache",
    "callback",
    "cliconf",
    "connection",
    "filter",
    "httpapi",
    "inventory",
    "lookup",
    "netconf",
    "shell",
    "strategy",
    "terminal",
    "test",
    "vars",
}
_LEGACY_PLUGIN_DIRECTORIES = {
    f"{plugin_type}_plugins": plugin_type for plugin_type in _PYTHON_PLUGIN_TYPES
}
_SECRET_NAME = re.compile(
    r"(?:password|passwd|token|secret|private_?key|client_?secret|api_?key|credential)",
    re.IGNORECASE,
)


def ansible_code_metadata(filename: str | None) -> dict[str, str] | None:
    """Classify a conventional Ansible module, module utility, or controller plugin path."""
    if not filename:
        return None
    path = PurePosixPath(filename.replace("\\", "/"))
    parts = tuple(part.casefold() for part in path.parts)
    suffix = path.suffix.casefold()
    language = {".py": "python", ".ps1": "powershell"}.get(suffix)
    if language is None:
        return None
    component_name = path.stem

    if "plugins" in parts[:-1]:
        index = len(parts) - 2 - tuple(reversed(parts[:-1])).index("plugins")
        if index + 1 < len(parts) - 1:
            plugin_type = parts[index + 1]
            if plugin_type == "modules" and language in {"python", "powershell"}:
                return {
                    "artifact_type": "module_source",
                    "component_name": component_name,
                    "language": language,
                    "plugin_type": "module",
                    "source_kind": "target_module",
                }
            if plugin_type == "module_utils" and language == "python":
                return {
                    "artifact_type": "module_utility_source",
                    "component_name": component_name,
                    "language": language,
                    "plugin_type": "module_utils",
                    "source_kind": "shared_module_utility",
                }
            if plugin_type in _PYTHON_PLUGIN_TYPES and language == "python":
                return {
                    "artifact_type": "controller_plugin_source",
                    "component_name": component_name,
                    "language": language,
                    "plugin_type": plugin_type,
                    "source_kind": "controller_plugin",
                }

    if "library" in parts[:-1] and language in {"python", "powershell"}:
        return {
            "artifact_type": "module_source",
            "component_name": component_name,
            "language": language,
            "plugin_type": "module",
            "source_kind": "target_module",
        }

    for directory, plugin_type in _LEGACY_PLUGIN_DIRECTORIES.items():
        if directory in parts[:-1] and language == "python":
            return {
                "artifact_type": "controller_plugin_source",
                "component_name": component_name,
                "language": language,
                "plugin_type": plugin_type,
                "source_kind": "controller_plugin",
            }
    return None


def is_ansible_code(filename: str | None) -> bool:
    return ansible_code_metadata(filename) is not None


def _mask_python(source: str) -> str:
    lines = source.splitlines(keepends=True)
    masked = [list(line) for line in lines]
    try:
        tokens = tokenize.generate_tokens(StringIO(source).readline)
        for token in tokens:
            if token.type not in {tokenize.COMMENT, tokenize.STRING}:
                continue
            (start_line, start_col), (end_line, end_col) = token.start, token.end
            for line_number in range(start_line, end_line + 1):
                if line_number - 1 >= len(masked):
                    continue
                start = start_col if line_number == start_line else 0
                end = end_col if line_number == end_line else len(masked[line_number - 1])
                for column in range(start, min(end, len(masked[line_number - 1]))):
                    if masked[line_number - 1][column] not in {"\r", "\n"}:
                        masked[line_number - 1][column] = " "
    except (IndentationError, tokenize.TokenError) as exc:
        raise AnsibleCodeInputError(f"invalid Python source: {exc}") from exc
    return "".join("".join(line) for line in masked)


def _mask_powershell(source: str) -> str:
    result: list[str] = []
    index = 0
    quote: str | None = None
    block_comment = False
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if char in "\r\n":
            result.append(char)
            index += 1
            continue
        if block_comment:
            if char == "#" and next_char == ">":
                result.extend((" ", " "))
                index += 2
                block_comment = False
            else:
                result.append(" ")
                index += 1
            continue
        if quote is not None:
            if char == "`" and index + 1 < len(source):
                result.extend((" ", " "))
                index += 2
            elif char == quote:
                result.append(" ")
                index += 1
                quote = None
            else:
                result.append(" ")
                index += 1
            continue
        if char == "<" and next_char == "#":
            result.extend((" ", " "))
            index += 2
            block_comment = True
        elif char == "#":
            while index < len(source) and source[index] not in "\r\n":
                result.append(" ")
                index += 1
        elif char in {"'", '"'}:
            quote = char
            result.append(" ")
            index += 1
        else:
            result.append(char)
            index += 1
    if block_comment or quote is not None:
        raise AnsibleCodeInputError("unterminated PowerShell comment or string")
    return "".join(result)


_PYTHON_FINDINGS = (
    (
        "dynamic_execution",
        "dangerous",
        re.compile(r"\b(?:eval|exec|compile)\s*\("),
        "The source dynamically evaluates or compiles Python code; untrusted inputs can "
        "change executed behavior.",
    ),
    (
        "command_execution",
        "dangerous",
        re.compile(
            r"\b(?:os\.(?:system|popen|spawn[a-z]*)|subprocess\.(?:Popen|run|call|check_call|check_output)|run_command)\s*\("
        ),
        "The source starts a process or command; review argument construction, quoting, "
        "privileges, and target trust.",
    ),
    (
        "shell_execution",
        "dangerous",
        re.compile(r"\bshell\s*=\s*True\b"),
        "The command uses a shell interpreter, expanding the command-injection surface.",
    ),
    (
        "controller_module_execution",
        "dangerous",
        re.compile(r"\b(?:_execute_module|_low_level_execute_command)\s*\("),
        "The controller plugin dispatches a module or low-level command; review the "
        "resulting target execution boundary.",
    ),
    (
        "network_access",
        "dangerous",
        re.compile(
            r"\b(?:requests\.(?:get|post|put|patch|delete|request)|httpx\.(?:get|post|put|patch|delete|request)|urllib\.request\.|socket\.(?:socket|create_connection)|fetch_url|open_url)\s*\("
        ),
        "The source opens a network boundary; review endpoint trust, TLS, credentials, "
        "timeouts, and response handling.",
    ),
    (
        "tls_verification_disabled",
        "dangerous",
        re.compile(r"\b(?:verify|validate_certs)\s*=\s*False\b"),
        "TLS certificate verification is explicitly disabled.",
    ),
    (
        "destructive_filesystem",
        "dangerous",
        re.compile(
            r"\b(?:os\.(?:remove|unlink|rmdir|removedirs)|shutil\.rmtree|Path\([^\n]*\)\.(?:unlink|rmdir))\s*\("
        ),
        "The source deletes files or directories; review path control, check mode, and "
        "recovery behavior.",
    ),
    (
        "filesystem_mutation",
        "dangerous",
        re.compile(
            r"\b(?:os\.(?:rename|replace|mkdir|makedirs)|shutil\.(?:move|copy|copy2|copytree)|atomic_move|Path\([^\n]*\)\.(?:write_text|write_bytes|mkdir|rename|replace))\s*\("
        ),
        "The source mutates the filesystem; review path validation, idempotency, check "
        "mode, and rollback behavior.",
    ),
    (
        "permission_change",
        "dangerous",
        re.compile(r"\b(?:os\.(?:chmod|chown|lchmod|lchown)|Path\([^\n]*\)\.chmod)\s*\("),
        "The source changes ownership or permissions on the managed system.",
    ),
    (
        "privilege_change",
        "dangerous",
        re.compile(r"\bos\.(?:setuid|seteuid|setgid|setegid)\s*\("),
        "The source changes process identity or privileges.",
    ),
    (
        "unsafe_deserialization",
        "dangerous",
        re.compile(r"\b(?:pickle|marshal)\.loads?\s*\(|\byaml\.load\s*\("),
        "The source uses a deserializer that can execute or instantiate attacker-controlled "
        "objects.",
    ),
    (
        "insecure_temporary_path",
        "dangerous",
        re.compile(r"\btempfile\.mktemp\s*\("),
        "The source creates a race-prone predictable temporary path.",
    ),
    (
        "argument_logging",
        "dangerous",
        re.compile(r"\bno_log\s*=\s*False\b"),
        "Sensitive argument redaction is explicitly disabled.",
    ),
    (
        "environment_input",
        "review",
        re.compile(r"\bos\.environ(?:\b|\[|\.get\s*\()"),
        "The source reads process environment input; review secret handling and "
        "controller/target configuration precedence.",
    ),
)


_POWERSHELL_FINDINGS = (
    (
        "dynamic_execution",
        "dangerous",
        re.compile(r"\b(?:Invoke-Expression|iex|Add-Type)\b|&\s*\$", re.IGNORECASE),
        "The source dynamically evaluates code or invokes a computed command.",
    ),
    (
        "command_execution",
        "dangerous",
        re.compile(r"\b(?:Start-Process|Start-Job|Invoke-Command)\b", re.IGNORECASE),
        "The source starts a process, job, or remote command; review argument construction "
        "and identity.",
    ),
    (
        "network_access",
        "dangerous",
        re.compile(
            r"\b(?:Invoke-WebRequest|Invoke-RestMethod|New-PSSession|Enter-PSSession)\b",
            re.IGNORECASE,
        ),
        "The source opens a network or remoting boundary; review endpoint trust, TLS, and "
        "credentials.",
    ),
    (
        "destructive_filesystem",
        "dangerous",
        re.compile(r"\b(?:Remove-Item|Clear-Content)\b", re.IGNORECASE),
        "The source deletes or clears managed-system content; review paths, check mode, "
        "and recovery behavior.",
    ),
    (
        "filesystem_mutation",
        "dangerous",
        re.compile(
            r"\b(?:Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|New-Item|Rename-Item)\b",
            re.IGNORECASE,
        ),
        "The source mutates the filesystem; review path validation, idempotency, and check mode.",
    ),
    (
        "permission_change",
        "dangerous",
        re.compile(r"\b(?:Set-Acl|icacls|takeown)\b", re.IGNORECASE),
        "The source changes access control or ownership.",
    ),
    (
        "system_mutation",
        "dangerous",
        re.compile(
            r"\b(?:Restart-Computer|Stop-Computer|Set-Service|Restart-Service|New-Service|Remove-Service)\b",
            re.IGNORECASE,
        ),
        "The source changes services or the managed host lifecycle.",
    ),
    (
        "tls_verification_disabled",
        "dangerous",
        re.compile(r"\bSkipCertificateCheck\b", re.IGNORECASE),
        "TLS certificate verification is explicitly bypassed.",
    ),
    (
        "encoded_command",
        "dangerous",
        re.compile(r"-(?:e|enc|encodedcommand)\b", re.IGNORECASE),
        "The source launches encoded PowerShell content, obscuring executed behavior.",
    ),
    (
        "environment_input",
        "review",
        re.compile(r"\$env:[A-Za-z_][A-Za-z0-9_]*", re.IGNORECASE),
        "The source reads process environment input; review secret handling and execution context.",
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
        "Address": f"ansible_code.line.{line}.{kind}.{occurrence}",
        "Action": "execute",
        "Kind": kind,
        "Risk": risk,
        "Explanation": f"Line {line}: {explanation}",
    }


def _pattern_findings(source: str, language: str) -> list[dict[str, str]]:
    masked = _mask_python(source) if language == "python" else _mask_powershell(source)
    starts = _line_starts(masked)
    patterns = _PYTHON_FINDINGS if language == "python" else _POWERSHELL_FINDINGS
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, int]] = set()
    for kind, risk, pattern, explanation in patterns:
        for match in pattern.finditer(masked):
            line = bisect_right(starts, match.start())
            key = (kind, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                _finding(
                    kind=kind,
                    risk=risk,
                    explanation=explanation,
                    line=line,
                    occurrence=len(findings) + 1,
                )
            )
            if len(findings) >= _MAX_FINDINGS:
                raise AnsibleCodeInputError("Ansible source exceeds the finding count limit")
    return findings


def parse_ansible_code(source: str, filename: str | None) -> dict[str, Any]:
    """Parse executable Ansible source without importing or running it."""
    metadata = ansible_code_metadata(filename)
    if metadata is None:
        raise AnsibleCodeInputError("path is not a supported Ansible module or plugin source")
    if not source.strip():
        raise AnsibleCodeInputError("input is empty")
    if "\x00" in source:
        raise AnsibleCodeInputError("input contains a NUL byte")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise AnsibleCodeInputError("Ansible source exceeds the source size limit")
    line_count = len(source.splitlines())
    if line_count > _MAX_SOURCE_LINES:
        raise AnsibleCodeInputError("Ansible source exceeds the line count limit")

    findings = _pattern_findings(source, metadata["language"])
    masked = _mask_python(source) if metadata["language"] == "python" else _mask_powershell(source)
    if metadata["artifact_type"] == "module_source":
        if metadata["language"] == "python" and not re.search(r"\bAnsibleModule\s*\(", masked):
            findings.append(
                _finding(
                    kind="module_interface",
                    risk="review",
                    explanation=(
                        "The Python module does not visibly construct AnsibleModule; verify "
                        "argument handling, JSON output, and failure semantics."
                    ),
                    line=1,
                    occurrence=len(findings) + 1,
                )
            )
        if not re.search(r"\b(?:supports_check_mode|CheckMode)\b", masked, re.IGNORECASE):
            findings.append(
                _finding(
                    kind="check_mode",
                    risk="review",
                    explanation=(
                        "No check-mode handling was detected; verify dry-run behavior before "
                        "allowing mutations."
                    ),
                    line=1,
                    occurrence=len(findings) + 1,
                )
            )
    for line_number, line in enumerate(masked.splitlines(), start=1):
        assignment = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=", line)
        if assignment and _SECRET_NAME.search(assignment.group(1)):
            findings.append(
                _finding(
                    kind="secret_handling",
                    risk="review",
                    explanation=(
                        "A secret-like value is assigned; verify no_log/redaction, storage "
                        "lifetime, and error-path handling."
                    ),
                    line=line_number,
                    occurrence=len(findings) + 1,
                )
            )
            if len(findings) >= _MAX_FINDINGS:
                raise AnsibleCodeInputError("Ansible source exceeds the finding count limit")

    return {
        **metadata,
        "source_line_count": line_count,
        "findings": findings,
    }


def ansible_code_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    findings = list(document["findings"])
    source_kind = document["source_kind"]
    plugin_type = document["plugin_type"]
    if source_kind == "target_module":
        explanation = (
            "This custom module is executable automation transferred to or run for a "
            "managed target. Review its parameters, effective identity, check-mode/idempotency "
            "behavior, platform interpreter, and module_utils dependencies."
        )
    elif source_kind == "controller_plugin":
        explanation = (
            f"This {plugin_type} plugin executes Python in the Ansible controller process. "
            "Review controller filesystem, network, credential, variable, and plugin-loader "
            "trust boundaries."
        )
    else:
        explanation = (
            "This module_utils source is shared executable code that modules or plugins can "
            "package or import. Review every caller and whether execution occurs on the "
            "controller or a managed target."
        )
    findings.append(
        {
            "Address": f"ansible_code.{source_kind}.{document['component_name']}.execution",
            "Action": "execute",
            "Kind": "execution_boundary",
            "Risk": "review",
            "Explanation": explanation,
        }
    )
    return findings
