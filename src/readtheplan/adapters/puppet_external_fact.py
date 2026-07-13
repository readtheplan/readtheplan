from __future__ import annotations

import json
import re
import tokenize
from bisect import bisect_right
from io import StringIO
from pathlib import PurePosixPath
from typing import Any

import yaml


class PuppetExternalFactInputError(ValueError):
    """Raised when Puppet external-fact content cannot be inspected safely."""


_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_LINES = 100_000
_MAX_FACTS = 5_000
_MAX_NODES = 100_000
_MAX_DEPTH = 100
_MAX_FINDINGS = 2_000
_SECRET_NAME = re.compile(
    r"(?:password|passwd|token|secret|private_?key|client_?secret|api_?key|credential)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:\$|%|\b)([A-Za-z_][A-Za-z0-9_]*(?:password|passwd|token|secret|"
    r"private_?key|client_?secret|api_?key|credential)[A-Za-z0-9_]*)\s*(?::=|=>|=|:)"
)
_FACT_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_CORE_FACTS = {
    "architecture",
    "cloud",
    "disks",
    "dmi",
    "domain",
    "ec2_metadata",
    "ec2_userdata",
    "environment",
    "facterversion",
    "filesystems",
    "fqdn",
    "gce",
    "hostname",
    "identity",
    "interfaces",
    "ipaddress",
    "kernel",
    "memory",
    "mountpoints",
    "networking",
    "os",
    "partitions",
    "processors",
    "puppetversion",
    "system_uptime",
    "timezone",
    "virtual",
}
_SCRIPT_SUFFIXES = {
    ".bash": "shell",
    ".bat": "batch",
    ".cmd": "batch",
    ".ksh": "shell",
    ".pl": "perl",
    ".ps1": "powershell",
    ".py": "python",
    ".rb": "ruby",
    ".sh": "shell",
    ".zsh": "shell",
}
_SHEBANGS = (
    (re.compile(r"^#![^\n]*[/ ](?:bash|dash|ksh|sh|zsh)(?:\s|$)", re.I), "shell"),
    (
        re.compile(r"^#![^\n]*[/ ](?:powershell|pwsh)(?:\.exe)?(?:\s|$)", re.I),
        "powershell",
    ),
    (re.compile(r"^#![^\n]*[/ ]python(?:\d+(?:\.\d+)?)?(?:\s|$)", re.I), "python"),
    (re.compile(r"^#![^\n]*[/ ]ruby(?:\d+(?:\.\d+)?)?(?:\s|$)", re.I), "ruby"),
    (re.compile(r"^#![^\n]*[/ ]perl(?:\d+(?:\.\d+)?)?(?:\s|$)", re.I), "perl"),
)


def _parts(filename: str | None) -> tuple[str, ...]:
    if not filename:
        return ()
    return tuple(part.casefold() for part in PurePosixPath(filename.replace("\\", "/")).parts)


def is_puppet_external_fact_path(filename: str | None) -> bool:
    parts = _parts(filename)
    return bool(parts and "facts.d" in parts[:-1])


def puppet_external_fact_metadata(filename: str | None, source: str = "") -> dict[str, str] | None:
    """Classify a supported text external fact in a documented facts.d path."""
    if not is_puppet_external_fact_path(filename):
        return None
    path = PurePosixPath(str(filename).replace("\\", "/"))
    suffix = path.suffix.casefold()
    component_name = path.stem or path.name
    data_format = {".json": "json", ".txt": "text", ".yaml": "yaml"}.get(suffix)
    if data_format is not None:
        return {
            "artifact_type": "external_fact",
            "component_name": component_name,
            "external_fact_type": "structured_data",
            "format": data_format,
            "source_kind": "agent_external_fact",
        }
    language = _SCRIPT_SUFFIXES.get(suffix)
    if language is None:
        first_line = source.splitlines()[0] if source.splitlines() else ""
        for pattern, candidate in _SHEBANGS:
            if pattern.search(first_line):
                language = candidate
                break
    if language is None:
        return None
    return {
        "artifact_type": "external_fact",
        "component_name": component_name,
        "external_fact_type": "executable",
        "language": language,
        "source_kind": "agent_external_fact",
    }


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    keys: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in keys
        except TypeError as exc:
            raise PuppetExternalFactInputError("YAML mapping keys must be scalar") from exc
        if duplicate:
            raise PuppetExternalFactInputError("duplicate YAML fact key")
        keys.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PuppetExternalFactInputError("duplicate JSON fact key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise PuppetExternalFactInputError("non-finite JSON values are not supported")


def _source_checks(source: str) -> int:
    if not source.strip():
        raise PuppetExternalFactInputError("input is empty")
    if "\x00" in source:
        raise PuppetExternalFactInputError("input contains a NUL byte")
    if source.startswith("\ufeff"):
        raise PuppetExternalFactInputError("external facts must not contain a UTF-8 BOM")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise PuppetExternalFactInputError("external fact exceeds the source size limit")
    line_count = source.count("\n") + 1
    if line_count > _MAX_SOURCE_LINES:
        raise PuppetExternalFactInputError("external fact exceeds the line count limit")
    return line_count


def _validate_tree(value: Any, *, depth: int = 0, active: set[int] | None = None) -> int:
    if depth > _MAX_DEPTH:
        raise PuppetExternalFactInputError("external fact exceeds the nesting depth limit")
    if active is None:
        active = set()
    if isinstance(value, dict):
        identity = id(value)
        if identity in active:
            raise PuppetExternalFactInputError("recursive YAML aliases are not supported")
        active.add(identity)
        count = 1
        for key, child in value.items():
            if not isinstance(key, str):
                raise PuppetExternalFactInputError("external fact mapping keys must be strings")
            count += _validate_tree(child, depth=depth + 1, active=active)
            if count > _MAX_NODES:
                raise PuppetExternalFactInputError("external fact exceeds the node count limit")
        active.remove(identity)
        return count
    if isinstance(value, list):
        identity = id(value)
        if identity in active:
            raise PuppetExternalFactInputError("recursive YAML aliases are not supported")
        active.add(identity)
        count = 1
        for child in value:
            count += _validate_tree(child, depth=depth + 1, active=active)
            if count > _MAX_NODES:
                raise PuppetExternalFactInputError("external fact exceeds the node count limit")
        active.remove(identity)
        return count
    if value is None or isinstance(value, (str, int, float, bool)):
        return 1
    raise PuppetExternalFactInputError("external fact contains an unsupported value type")


def _parse_text_facts(source: str) -> dict[str, str]:
    document: dict[str, str] = {}
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, separator, value = stripped.partition("=")
        key = key.strip()
        if not separator or not _FACT_NAME.fullmatch(key) or ".." in key:
            raise PuppetExternalFactInputError("invalid text external-fact entry")
        if key in document:
            raise PuppetExternalFactInputError("duplicate text external-fact key")
        document[key] = value.strip()
        if len(document) > _MAX_FACTS:
            raise PuppetExternalFactInputError("external fact exceeds the fact count limit")
    if not document:
        raise PuppetExternalFactInputError("text external fact contains no fact entries")
    return document


def _parse_structured(source: str, data_format: str) -> dict[str, Any]:
    try:
        if data_format == "json":
            document = json.loads(
                source,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        elif data_format == "yaml":
            documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
            documents = [document for document in documents if document is not None]
            if len(documents) != 1:
                raise PuppetExternalFactInputError(
                    "YAML external fact must contain exactly one document"
                )
            document = documents[0]
        else:
            return _parse_text_facts(source)
    except PuppetExternalFactInputError:
        raise
    except yaml.constructor.ConstructorError as exc:
        if "recursive" in str(exc).casefold():
            raise PuppetExternalFactInputError(
                "recursive YAML aliases are not supported"
            ) from exc
        raise PuppetExternalFactInputError("invalid structured external-fact data") from exc
    except (json.JSONDecodeError, yaml.YAMLError, RecursionError) as exc:
        raise PuppetExternalFactInputError("invalid structured external-fact data") from exc
    if not isinstance(document, dict) or not document:
        raise PuppetExternalFactInputError("structured external fact must be a non-empty mapping")
    if len(document) > _MAX_FACTS:
        raise PuppetExternalFactInputError("external fact exceeds the fact count limit")
    _validate_tree(document)
    return document


def _mask_python(source: str, *, strings: bool) -> str:
    lines = source.splitlines(keepends=True)
    output = [list(line) for line in lines]
    try:
        for token in tokenize.generate_tokens(StringIO(source).readline):
            if token.type != tokenize.COMMENT and not (strings and token.type == tokenize.STRING):
                continue
            (start_line, start_column), (end_line, end_column) = token.start, token.end
            for line_number in range(start_line, end_line + 1):
                row = output[line_number - 1]
                start = start_column if line_number == start_line else 0
                end = end_column if line_number == end_line else len(row)
                for column in range(start, min(end, len(row))):
                    if row[column] not in "\r\n":
                        row[column] = " "
    except (IndentationError, tokenize.TokenError) as exc:
        raise PuppetExternalFactInputError("invalid Python external fact") from exc
    return "".join("".join(line) for line in output)


def _mask_quoted(source: str, *, language: str, strings: bool) -> str:
    output = list(source)
    quote: str | None = None
    escaped = False
    block_comment = False
    line_start = True
    index = 0
    while index < len(source):
        character = source[index]
        next_character = source[index + 1] if index + 1 < len(source) else ""
        if character in "\r\n":
            line_start = True
            index += 1
            continue
        if block_comment:
            if language == "powershell" and character == "#" and next_character == ">":
                output[index : index + 2] = [" ", " "]
                block_comment = False
                index += 2
            elif language in {"perl", "ruby"} and line_start and source.startswith("=cut", index):
                while index < len(source) and source[index] not in "\r\n":
                    output[index] = " "
                    index += 1
                block_comment = False
            else:
                output[index] = " "
                line_start = False
                index += 1
            continue
        if quote is not None:
            if escaped:
                if strings:
                    output[index] = " "
                escaped = False
            elif character in {"\\", "`"} and language == "powershell":
                if strings:
                    output[index] = " "
                escaped = True
            elif character == "\\" and language != "powershell":
                if strings:
                    output[index] = " "
                escaped = True
            elif character == quote:
                if strings:
                    output[index] = " "
                quote = None
            elif strings:
                output[index] = " "
            line_start = False
            index += 1
            continue
        if language == "powershell" and character == "<" and next_character == "#":
            output[index : index + 2] = [" ", " "]
            block_comment = True
            index += 2
            continue
        if (
            language in {"perl", "ruby"}
            and line_start
            and re.match(r"=(?:begin|pod)\b", source[index:])
        ):
            block_comment = True
            while index < len(source) and source[index] not in "\r\n":
                output[index] = " "
                index += 1
            continue
        line_start = False
        if character == "#":
            while index < len(source) and source[index] not in "\r\n":
                output[index] = " "
                index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            if strings:
                output[index] = " "
            index += 1
            continue
        index += 1
    if quote is not None or block_comment:
        raise PuppetExternalFactInputError("unterminated external-fact string or comment")
    return "".join(output)


def _mask_batch_comments(source: str) -> str:
    lines: list[str] = []
    for line in source.splitlines(keepends=True):
        stripped = line.lstrip().casefold()
        if stripped.startswith("rem ") or stripped.startswith("rem\t") or stripped.startswith("::"):
            ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            lines.append(" " * (len(line) - len(ending)) + ending)
        else:
            lines.append(line)
    return "".join(lines)


_SCRIPT_FINDINGS: dict[str, tuple[tuple[str, str, re.Pattern[str], str], ...]] = {
    "shell": (
        (
            "dynamic_execution",
            "dangerous",
            re.compile(r"\beval\b|\b(?:ba|da|k|z)?sh\s+-c\b|\$\(|`", re.I),
            "The executable fact uses dynamic shell evaluation or command substitution.",
        ),
        (
            "process_execution",
            "dangerous",
            re.compile(r"(?:^|[;&|\s])(?:xargs|env|command|nohup)\b", re.I | re.M),
            "The executable fact starts or composes another process.",
        ),
        (
            "destructive_filesystem",
            "dangerous",
            re.compile(r"\brm\b[^\n]*(?:-[A-Za-z]*r|--recursive)|\bmkfs(?:\.|\b)|\bdd\s+if=", re.I),
            "The executable fact contains destructive filesystem operations.",
        ),
        (
            "network_access",
            "dangerous",
            re.compile(
                r"(?:^|[;&|(\s])(?:curl|wget|nc|ncat|socat|ssh|scp|sftp|rsync)\b",
                re.I | re.M,
            ),
            "The executable fact opens a network, remote-access, or download boundary "
            "from the agent.",
        ),
        (
            "tls_verification_disabled",
            "dangerous",
            re.compile(
                r"\bcurl\b[^\n]*(?:\s-k\b|--insecure\b)|\bwget\b[^\n]*--no-check-certificate\b",
                re.I,
            ),
            "The executable fact disables TLS certificate verification.",
        ),
        (
            "privilege_escalation",
            "dangerous",
            re.compile(r"(?:^|[;&|\s])(?:sudo|su|doas)\b", re.I | re.M),
            "The executable fact invokes a privilege-escalation utility.",
        ),
        (
            "system_mutation",
            "dangerous",
            re.compile(
                r"(?:^|[;&|\s])(?:apk|apt(?:-get)?|dnf|yum|rpm|systemctl|service|useradd|usermod|userdel|groupadd|iptables|nft|mount|umount|chmod|chown|chgrp|setfacl)\b",
                re.I | re.M,
            ),
            "The executable fact mutates packages, services, identities, permissions, "
            "firewall policy, or mounts.",
        ),
        (
            "environment_input",
            "review",
            re.compile(
                r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
            ),
            "The executable fact reads process-environment input.",
        ),
    ),
    "powershell": (
        (
            "dynamic_execution",
            "dangerous",
            re.compile(r"\b(?:Invoke-Expression|iex|Add-Type)\b|&\s*\$", re.I),
            "The executable fact dynamically evaluates code or invokes a computed command.",
        ),
        (
            "process_execution",
            "dangerous",
            re.compile(r"\b(?:Start-Process|Start-Job|Invoke-Command)\b", re.I),
            "The executable fact starts a process, job, or remote command.",
        ),
        (
            "destructive_filesystem",
            "dangerous",
            re.compile(r"\b(?:Remove-Item|Clear-Content|Clear-Disk|Format-Volume)\b", re.I),
            "The executable fact deletes or clears agent content.",
        ),
        (
            "network_access",
            "dangerous",
            re.compile(
                r"\b(?:Invoke-WebRequest|Invoke-RestMethod|New-PSSession|Enter-PSSession)\b", re.I
            ),
            "The executable fact opens a network or remoting boundary from the agent.",
        ),
        (
            "tls_verification_disabled",
            "dangerous",
            re.compile(r"\bSkipCertificateCheck\b|ServerCertificateValidationCallback", re.I),
            "The executable fact bypasses TLS certificate validation.",
        ),
        (
            "system_mutation",
            "dangerous",
            re.compile(
                r"\b(?:Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|New-Item|Rename-Item|Set-Acl|icacls|takeown|Restart-Computer|Stop-Computer|Set-Service|New-Service)\b",
                re.I,
            ),
            "The executable fact mutates files, permissions, services, or agent lifecycle state.",
        ),
        (
            "environment_input",
            "review",
            re.compile(r"\$env:[A-Za-z_][A-Za-z0-9_]*", re.I),
            "The executable fact reads process-environment input.",
        ),
    ),
    "python": (
        (
            "dynamic_execution",
            "dangerous",
            re.compile(r"\b(?:eval|exec|compile)\s*\(|\bshell\s*=\s*True\b"),
            "The executable fact dynamically evaluates Python or enables shell parsing.",
        ),
        (
            "process_execution",
            "dangerous",
            re.compile(
                r"\b(?:os\.(?:system|popen)|subprocess\.(?:Popen|run|call|check_call|check_output))\s*\("
            ),
            "The executable fact starts a process on the agent.",
        ),
        (
            "destructive_filesystem",
            "dangerous",
            re.compile(
                r"\b(?:shutil\.rmtree|os\.(?:remove|unlink|rmdir)|Path\([^\n]*\)\.(?:unlink|rmdir))\s*\("
            ),
            "The executable fact deletes agent filesystem content.",
        ),
        (
            "network_access",
            "dangerous",
            re.compile(
                r"\b(?:requests|httpx)\.(?:get|post|put|patch|delete|request)\s*\(|\burllib\.request\.|\bsocket\.(?:socket|create_connection)\s*\("
            ),
            "The executable fact opens a network boundary from the agent.",
        ),
        (
            "tls_verification_disabled",
            "dangerous",
            re.compile(r"\bverify\s*=\s*False\b"),
            "The executable fact disables TLS certificate verification.",
        ),
        (
            "filesystem_mutation",
            "dangerous",
            re.compile(
                r"\b(?:Path\([^\n]*\)\.(?:write_text|write_bytes|rename|replace|chmod)|shutil\.(?:copy|copy2|copytree|move)|os\.(?:rename|replace|chmod|chown))\s*\("
            ),
            "The executable fact writes, moves, or changes permissions on agent files.",
        ),
        (
            "unsafe_deserialization",
            "dangerous",
            re.compile(r"\b(?:pickle|marshal)\.loads?\s*\(|\byaml\.(?:load|unsafe_load)\s*\("),
            "The executable fact uses unsafe object deserialization.",
        ),
        (
            "privilege_change",
            "dangerous",
            re.compile(r"\bos\.set(?:e|re|res)?(?:uid|gid)\s*\("),
            "The executable fact changes process identity or privileges.",
        ),
        (
            "environment_input",
            "review",
            re.compile(r"\bos\.environ(?:\b|\[|\.get\s*\()"),
            "The executable fact reads process-environment input.",
        ),
    ),
    "ruby": (
        (
            "dynamic_execution",
            "dangerous",
            re.compile(r"(?<![.\w])(?:eval|instance_eval|class_eval|module_eval)\s*(?:\(|\b)"),
            "The executable fact dynamically evaluates Ruby code.",
        ),
        (
            "process_execution",
            "dangerous",
            re.compile(
                r"(?<![.\w])(?:system|exec|spawn)\s*(?:\(|\s)|\b(?:IO\.popen|Open3\.[A-Za-z_]+)\s*\(|`|%x\s*[^A-Za-z0-9\s]",
                re.I,
            ),
            "The executable fact starts a process or shell command on the agent.",
        ),
        (
            "destructive_filesystem",
            "dangerous",
            re.compile(r"\b(?:FileUtils\.(?:rm|rm_f|rm_rf|rmtree)|File\.(?:delete|unlink))\s*\("),
            "The executable fact deletes agent filesystem content.",
        ),
        (
            "network_access",
            "dangerous",
            re.compile(
                r"\b(?:Net::HTTP|OpenURI|TCPSocket|UDPSocket|RestClient|Faraday)\b|\bURI\.open\s*\("
            ),
            "The executable fact opens a network boundary from the agent.",
        ),
        (
            "tls_verification_disabled",
            "dangerous",
            re.compile(r"\bverify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE\b", re.I),
            "The executable fact disables TLS certificate verification.",
        ),
        (
            "filesystem_mutation",
            "dangerous",
            re.compile(
                r"\b(?:File\.(?:write|rename|chmod|chown)|FileUtils\.(?:cp|cp_r|mv|mkdir|mkdir_p))\s*\("
            ),
            "The executable fact writes, moves, or changes permissions on agent files.",
        ),
        (
            "unsafe_deserialization",
            "dangerous",
            re.compile(r"\b(?:YAML|Marshal)\.(?:load|unsafe_load|restore)\s*\("),
            "The executable fact uses unsafe object deserialization.",
        ),
        (
            "privilege_change",
            "dangerous",
            re.compile(r"\bProcess::Sys\.set(?:e|re|res)?(?:uid|gid)\s*\("),
            "The executable fact changes process identity or privileges.",
        ),
        (
            "environment_input",
            "review",
            re.compile(r"\bENV\s*\["),
            "The executable fact reads process-environment input.",
        ),
    ),
    "perl": (
        (
            "dynamic_execution",
            "dangerous",
            re.compile(r"\beval\s*(?:\{|\()"),
            "The executable fact dynamically evaluates Perl code.",
        ),
        (
            "process_execution",
            "dangerous",
            re.compile(r"\b(?:system|exec|qx)\s*(?:\(|\{|\b)|`"),
            "The executable fact starts a process or shell command on the agent.",
        ),
        (
            "destructive_filesystem",
            "dangerous",
            re.compile(r"\b(?:unlink|rmdir|remove_tree)\s*(?:\(|\b)"),
            "The executable fact deletes agent filesystem content.",
        ),
        (
            "network_access",
            "dangerous",
            re.compile(r"\b(?:HTTP::Tiny|LWP::UserAgent|IO::Socket|Net::HTTP|Net::FTP|Net::SSH)\b"),
            "The executable fact opens a network boundary from the agent.",
        ),
        (
            "tls_verification_disabled",
            "dangerous",
            re.compile(r"\b(?:verify_hostname|SSL_verify_mode)\s*(?:=>|=)\s*0\b"),
            "The executable fact disables TLS peer verification.",
        ),
        (
            "filesystem_mutation",
            "dangerous",
            re.compile(r"\b(?:rename|chmod|chown|make_path|move|copy)\s*(?:\(|\b)"),
            "The executable fact mutates agent filesystem content or permissions.",
        ),
        (
            "unsafe_deserialization",
            "dangerous",
            re.compile(r"\b(?:Storable::)?(?:thaw|retrieve)\s*\("),
            "The executable fact uses object deserialization.",
        ),
        (
            "environment_input",
            "review",
            re.compile(r"\$ENV\s*\{"),
            "The executable fact reads process-environment input.",
        ),
    ),
    "batch": (
        (
            "dynamic_execution",
            "dangerous",
            re.compile(
                r"\bcall\s+(?:set|%|!)|\b(?:powershell|pwsh)(?:\.exe)?\s+-(?:e|enc|encodedcommand)\b",
                re.I,
            ),
            "The executable fact uses delayed or encoded command evaluation.",
        ),
        (
            "process_execution",
            "dangerous",
            re.compile(r"(?:^|[&|]\s*)start\s+", re.I | re.M),
            "The executable fact starts another process.",
        ),
        (
            "destructive_filesystem",
            "dangerous",
            re.compile(r"(?:^|[&|]\s*)(?:del|erase|rmdir|rd)\b", re.I | re.M),
            "The executable fact deletes agent filesystem content.",
        ),
        (
            "network_access",
            "dangerous",
            re.compile(r"(?:^|[&|\s])(?:curl|certutil|bitsadmin|ftp|ssh|scp)\b", re.I | re.M),
            "The executable fact opens a network or download boundary from the agent.",
        ),
        (
            "tls_verification_disabled",
            "dangerous",
            re.compile(r"\bcurl\b[^\n]*(?:\s-k\b|--insecure\b)", re.I),
            "The executable fact disables TLS certificate verification.",
        ),
        (
            "system_mutation",
            "dangerous",
            re.compile(
                r"(?:^|[&|]\s*)(?:reg\s+(?:add|delete)|sc\s+(?:create|config|delete|start|stop)|net\s+(?:user|localgroup)|icacls|takeown|shutdown)\b",
                re.I | re.M,
            ),
            "The executable fact mutates registry, services, identities, permissions, or "
            "agent lifecycle state.",
        ),
        (
            "environment_input",
            "review",
            re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%|![A-Za-z_][A-Za-z0-9_]*!"),
            "The executable fact reads process-environment input.",
        ),
    ),
}

_OUTPUT_PATTERNS = {
    "batch": re.compile(r"^\s*@?echo\s+(?!off\b)", re.I | re.M),
    "perl": re.compile(r"\bprint\b"),
    "powershell": re.compile(r"\b(?:Write-(?:Output|Host)|echo)\b", re.I),
    "python": re.compile(r"\bprint\s*\("),
    "ruby": re.compile(r"(?:^|\s)(?:puts|print)\b"),
    "shell": re.compile(r"(?:^|[;&|]\s*)(?:echo|printf)\b", re.M),
}
_TIMEOUT = re.compile(
    r"\b(?:timeout|request_timeout|open_timeout|read_timeout|connect_timeout|max[_-]?time)\b",
    re.IGNORECASE,
)


def _line_starts(source: str) -> list[int]:
    starts = [0]
    starts.extend(match.end() for match in re.finditer(r"\n", source))
    return starts


def _finding(
    findings: list[dict[str, str]],
    *,
    kind: str,
    risk: str,
    explanation: str,
    line: int | None = 1,
    action: str = "execute",
) -> None:
    if len(findings) >= _MAX_FINDINGS:
        raise PuppetExternalFactInputError("external fact exceeds the finding count limit")
    findings.append(
        {
            "Action": action,
            "Address": (
                f"puppet_external_fact.{'data' if line is None else f'line.{line}'}."
                f"{kind}.{len(findings) + 1}"
            ),
            "Kind": kind,
            "Risk": risk,
            "Explanation": explanation if line is None else f"Line {line}: {explanation}",
        }
    )


def _executable_findings(source: str, language: str) -> list[dict[str, str]]:
    if language == "python":
        masked = _mask_python(source, strings=True)
        comments_removed = _mask_python(source, strings=False)
    elif language == "batch":
        masked = comments_removed = _mask_batch_comments(source)
    elif language == "shell":
        masked = comments_removed = _mask_quoted(source, language=language, strings=False)
    else:
        masked = _mask_quoted(source, language=language, strings=True)
        comments_removed = _mask_quoted(source, language=language, strings=False)
    starts = _line_starts(masked)
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, int]] = set()
    shell_assignments = (
        set(re.findall(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", comments_removed))
        if language == "shell"
        else set()
    )
    _finding(
        findings,
        kind="external_fact_execution",
        risk="dangerous",
        explanation=(
            f"Facter forks and executes this {language} external fact during agent fact "
            "collection; review host scope, effective identity, interpreter provenance, "
            "latency, output handling, and failure behavior."
        ),
    )
    if language in {"perl", "python", "ruby", "shell"} and not source.startswith("#!"):
        _finding(
            findings,
            kind="fact_shebang",
            risk="review",
            explanation=(
                "Unix executable external facts require a shebang; verify the deployed agent "
                "platform, interpreter path, and execute bit."
            ),
        )
    high_latency = False
    for kind, risk, pattern, explanation in _SCRIPT_FINDINGS[language]:
        for match in pattern.finditer(masked):
            if kind == "environment_input" and language == "shell":
                variable = next((group for group in match.groups() if group), "")
                if variable in shell_assignments:
                    continue
            line = bisect_right(starts, match.start())
            key = (kind, line)
            if key in seen:
                continue
            seen.add(key)
            _finding(
                findings,
                kind=kind,
                risk=risk,
                explanation=explanation,
                line=line,
            )
            high_latency = high_latency or kind in {"network_access", "process_execution"}
    comment_starts = _line_starts(comments_removed)
    for match in _SECRET_ASSIGNMENT.finditer(comments_removed):
        line = bisect_right(comment_starts, match.start())
        key = ("secret_handling", line)
        if key in seen:
            continue
        seen.add(key)
        _finding(
            findings,
            kind="secret_handling",
            risk="review",
            explanation=(
                "The executable fact assigns a secret-like value; facts and diagnostics must "
                "not expose credentials to Puppet Server, PuppetDB, logs, or console users."
            ),
            line=line,
        )
    if _OUTPUT_PATTERNS[language].search(comments_removed) is None:
        _finding(
            findings,
            kind="fact_output_interface",
            risk="review",
            explanation=(
                "No visible key-value, JSON, or YAML output operation was detected; verify the "
                "external fact contract and that diagnostics use standard error."
            ),
        )
    if high_latency and _TIMEOUT.search(comments_removed) is None:
        _finding(
            findings,
            kind="fact_collection_timeout",
            risk="dangerous",
            explanation=(
                "The executable fact performs process or network work without a visible timeout; "
                "fact collection can delay or block Puppet agent runs."
            ),
        )
    return findings


def _structured_findings(document: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    _finding(
        findings,
        kind="external_fact_data",
        risk="review",
        explanation=(
            "External fact data is loaded on agents, can influence catalog compilation, and may "
            "be submitted to Puppet Server and PuppetDB; review ownership, provenance, and data "
            "classification."
        ),
        line=None,
        action="configure",
    )
    for key in document:
        top_level = key.split(".", 1)[0].casefold()
        if top_level in _CORE_FACTS:
            _finding(
                findings,
                kind="core_fact_override",
                risk="dangerous",
                explanation=(
                    "An external fact uses a built-in fact name and can take precedence over "
                    "collected system data, changing catalog decisions."
                ),
                line=None,
                action="configure",
            )
    nested_keys: list[str] = []

    def collect_keys(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                nested_keys.append(key)
                collect_keys(child)
        elif isinstance(value, list):
            for child in value:
                collect_keys(child)

    collect_keys(document)
    for key in nested_keys:
        if _SECRET_NAME.search(key):
            _finding(
                findings,
                kind="secret_fact_data",
                risk="dangerous",
                explanation=(
                    "A secret-like fact name is defined; facts are not a secret store and can be "
                    "exposed through reports, PuppetDB, APIs, logs, or console access."
                ),
                line=None,
                action="configure",
            )
    return findings


def parse_puppet_external_fact(source: str, filename: str | None) -> dict[str, Any]:
    """Inspect a supported Puppet external fact without executing it."""
    line_count = _source_checks(source)
    metadata = puppet_external_fact_metadata(filename, source)
    if metadata is None:
        raise PuppetExternalFactInputError(
            "facts.d input must be supported JSON, YAML, text, shell, PowerShell, Python, Ruby, "
            "Perl, or batch source"
        )
    if metadata["external_fact_type"] == "structured_data":
        document = _parse_structured(source, metadata["format"])
        findings = _structured_findings(document)
        fact_count = len(document)
    else:
        findings = _executable_findings(source, metadata["language"])
        fact_count = 0
    return {
        **metadata,
        "fact_count": fact_count,
        "source_line_count": line_count,
        "findings": findings,
    }


def puppet_external_fact_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    findings = list(document["findings"])
    executable = document["external_fact_type"] == "executable"
    findings.append(
        {
            "Action": "execute" if executable else "configure",
            "Address": "puppet_external_fact.agent.collection_boundary",
            "Kind": "external_fact_boundary",
            "Risk": "review",
            "Explanation": (
                "Effective external-fact behavior also depends on pluginsync, file ownership and "
                "execute bits, agent platform and identity, Facter configuration and precedence, "
                "environment inputs, output parsing, timeouts, duplicate fact definitions, and "
                "the Puppet Server/PuppetDB consumers of collected values; readtheplan never "
                "executes the fact."
            ),
        }
    )
    return findings
