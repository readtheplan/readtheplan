from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class BicepInputError(ValueError):
    """Raised when input is not recognizable Bicep source."""


_DECLARATION = re.compile(
    r"(?m)^[ \t]*(?:@[A-Za-z][^\n]*\n[ \t]*)*"
    r"(?:targetScope\s*=|param\s+|var\s+|resource\s+|module\s+|output\s+|"
    r"type\s+|func\s+|assert\s+|metadata\s+|extension\s+|import\s+)"
)
_BLOCK_DECLARATION = re.compile(
    r"(?m)^[ \t]*(?P<decorators>(?:@[A-Za-z][^\n]*\n[ \t]*)*)"
    r"(?P<kind>resource|module)\s+(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"'(?P<reference>[^'\n]+)'(?P<existing>\s+existing)?\s*=\s*"
    r"(?P<condition>if\s*\([^\n]+\)\s*)?(?P<opener>[{[])"
)
_PARAMETER = re.compile(
    r"(?m)^[ \t]*(?P<decorators>(?:@[A-Za-z][^\n]*\n[ \t]*)*)"
    r"param\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?P<type>[A-Za-z0-9_?]+)(?:\s*=\s*(?P<default>[^\n]+))?"
)
_OUTPUT = re.compile(
    r"(?m)^[ \t]*(?P<decorators>(?:@[A-Za-z][^\n]*\n[ \t]*)*)"
    r"output\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?P<type>[A-Za-z0-9_?]+)\s*=\s*(?P<value>[^\n]+)"
)
_TARGET_SCOPE = re.compile(r"(?m)^[ \t]*targetScope\s*=\s*'(?P<scope>[^'\n]+)'")
_EXTENSION_OR_IMPORT = re.compile(r"(?m)^[ \t]*(?P<kind>extension|import)\s+(?P<value>[^\n]+)")
_SECRET_NAME = re.compile(
    r"(?:password|passwd|secret|token|credential|connectionstring|connection_string|"
    r"sas(?:token)?|privatekey|private_key|clientsecret|client_secret|api[_-]?key)",
    re.IGNORECASE,
)
_SECRET_FUNCTION = re.compile(
    r"\b(?:listKeys|listSecrets|listAccountSas|listServiceSas|getSecret)\s*\(",
    re.IGNORECASE,
)
_EXTERNAL_FILE_FUNCTION = re.compile(
    r"\b(?:loadTextContent|loadFileAsBase64|loadJsonContent|loadYamlContent)\s*\(",
    re.IGNORECASE,
)
_HARDCODED_AZURE_URL = re.compile(
    r"https://(?:management\.azure\.com|login\.microsoftonline\.com|"
    r"[^/'\s]+\.(?:core\.windows\.net|database\.windows\.net|vault\.azure\.net))",
    re.IGNORECASE,
)
_PUBLIC_ACCESS = re.compile(
    r"(?:publicNetworkAccess\s*:\s*'Enabled'|allowBlobPublicAccess\s*:\s*true|"
    r"defaultAction\s*:\s*'Allow'|sourceAddressPrefix\s*:\s*'(?:\*|0\.0\.0\.0/0)'|"
    r"ipAddress\s*:\s*'(?:\*|0\.0\.0\.0/0)')",
    re.IGNORECASE,
)
_BROAD_SCOPE = re.compile(r"\b(?:tenant|managementGroup|subscription)\s*\(", re.IGNORECASE)


def _strip_comments(source: str) -> str:
    """Remove Bicep comments while preserving strings and line numbers."""
    output: list[str] = []
    index = 0
    state = "code"
    while index < len(source):
        if state == "code" and source.startswith("'''", index):
            output.append("'''")
            index += 3
            state = "triple"
            continue
        if state == "triple" and source.startswith("'''", index):
            output.append("'''")
            index += 3
            state = "code"
            continue
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code" and char == "'":
            output.append(char)
            state = "string"
        elif state == "string" and char == "\\" and next_char:
            output.extend((char, next_char))
            index += 1
        elif state == "string" and char == "'":
            output.append(char)
            state = "code"
        elif state == "code" and char == "/" and next_char == "/":
            output.extend((" ", " "))
            index += 1
            state = "line-comment"
        elif state == "code" and char == "/" and next_char == "*":
            output.extend((" ", " "))
            index += 1
            state = "block-comment"
        elif state == "line-comment":
            output.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                output.extend((" ", " "))
                index += 1
                state = "code"
            else:
                output.append("\n" if char == "\n" else " ")
        else:
            output.append(char)
        index += 1
    return "".join(output)


def _find_balanced_end(source: str, start: int) -> int:
    pairs = {"{": "}", "[": "]", "(": ")"}
    stack: list[str] = []
    index = start
    string = False
    triple = False
    while index < len(source):
        if not string and source.startswith("'''", index):
            triple = not triple
            index += 3
            continue
        char = source[index]
        if triple:
            index += 1
            continue
        if string and char == "\\":
            index += 2
            continue
        if char == "'":
            string = not string
        elif not string and char in pairs:
            stack.append(pairs[char])
        elif not string and char in "}])":
            if not stack or char != stack.pop():
                raise BicepInputError("unbalanced brackets in Bicep declaration")
            if not stack:
                return index + 1
        index += 1
    raise BicepInputError("unterminated Bicep resource or module declaration")


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _blocks(source: str) -> Iterator[dict[str, Any]]:
    for match in _BLOCK_DECLARATION.finditer(source):
        end = _find_balanced_end(source, match.start("opener"))
        yield {
            **match.groupdict(),
            "body": source[match.start("opener") : end],
            "line": _line_number(source, match.start()),
        }


def _finding(
    kind: str,
    address: str,
    risk: str,
    explanation: str,
    line: int,
    *,
    actions: tuple[str, ...] = ("unknown",),
) -> dict[str, Any]:
    return {
        "kind": kind,
        "address": address,
        "risk": risk,
        "explanation": explanation,
        "line": line,
        "actions": actions,
        "_metadata": {"after": {"line": line, "source_kind": kind}},
    }


def _resource_finding(block: dict[str, Any]) -> dict[str, Any]:
    reference = str(block["reference"])
    resource_type = reference.split("@", 1)[0]
    normalized_type = resource_type.lower()
    address = f"resource.{block['symbol']}"
    body = str(block["body"])
    line = int(block["line"])

    if block.get("existing"):
        explanation = (
            f"Bicep references existing resource {resource_type}; its runtime state and "
            "accessibility are outside this source artifact."
        )
        if _BROAD_SCOPE.search(body):
            explanation += " The reference crosses a subscription or tenant boundary."
        return _finding("bicep_existing_resource", address, "review", explanation, line)

    kind = "bicep_resource"
    risk = "review"
    reasons = [
        f"Bicep declares {resource_type}; source alone cannot distinguish create from update."
    ]
    if normalized_type == "microsoft.resources/deploymentscripts":
        kind = "bicep_deployment_script"
        risk = "dangerous"
        reasons.append("Deployment Scripts execute Azure CLI or PowerShell during deployment.")
    elif normalized_type == "microsoft.authorization/roleassignments":
        kind = "bicep_role_assignment"
        risk = "dangerous"
        reasons.append("Role assignments change Azure authorization scope.")
    elif normalized_type.startswith("microsoft.authorization/policy"):
        kind = "bicep_policy"
        risk = "dangerous"
        reasons.append("Azure Policy can deny, mutate, audit, or remediate resources broadly.")
    elif normalized_type == "microsoft.authorization/locks":
        kind = "bicep_resource_lock"
        risk = "dangerous"
        reasons.append("Resource locks can block modification or deletion operations.")

    if _PUBLIC_ACCESS.search(body):
        kind = "bicep_public_access"
        risk = "dangerous"
        reasons.append("The declaration enables broad or public network access.")
    if re.search(r"\bmode\s*:\s*'Complete'", body, re.IGNORECASE):
        kind = "bicep_complete_deployment"
        risk = "irreversible"
        reasons.append("Complete deployment mode can delete resources omitted from the template.")
    if _BROAD_SCOPE.search(body):
        risk = "dangerous" if risk == "review" else risk
        reasons.append("The resource is deployed or referenced across a broad Azure scope.")
    if block.get("condition") or str(block.get("opener")) == "[":
        reasons.append("Conditional or loop expansion must be confirmed in compiled output.")
    return _finding(kind, address, risk, " ".join(reasons), line, actions=("create", "update"))


def _module_finding(block: dict[str, Any]) -> dict[str, Any]:
    reference = str(block["reference"])
    body = str(block["body"])
    risk = "review"
    reasons = [f"Bicep module {reference!r} is an external source boundary that is not expanded."]
    if reference.startswith(("br:", "ts:")):
        reasons.append("Confirm registry/template-spec provenance and immutable content upstream.")
    if _BROAD_SCOPE.search(body):
        risk = "dangerous"
        reasons.append("The module targets subscription, management-group, or tenant scope.")
    if block.get("condition") or str(block.get("opener")) == "[":
        reasons.append("Conditional or loop expansion must be confirmed after compilation.")
    return _finding(
        "bicep_module_source",
        f"module.{block['symbol']}",
        risk,
        " ".join(reasons),
        int(block["line"]),
        actions=("create", "update"),
    )


def parse_bicep_source(source: str) -> dict[str, Any]:
    """Parse security-relevant Bicep source without compiling or executing it."""
    if not source.strip():
        raise BicepInputError("input is empty")
    cleaned = _strip_comments(source)
    if not _DECLARATION.search(cleaned):
        raise BicepInputError("input does not contain a recognized Bicep declaration")

    findings: list[dict[str, Any]] = []
    findings.append(
        _finding(
            "bicep_source_boundary",
            "bicep.source",
            "review",
            "Bicep source analysis does not compile modules or predict operations; run "
            "Bicep lint/build and Azure What-If with FullResourcePayloads before deployment.",
            1,
        )
    )

    scope_match = _TARGET_SCOPE.search(cleaned)
    if scope_match:
        scope = scope_match.group("scope")
        risk = "dangerous" if scope in {"subscription", "managementGroup", "tenant"} else "review"
        findings.append(
            _finding(
                "bicep_target_scope",
                "bicep.targetScope",
                risk,
                f"Bicep targets {scope!r} scope; confirm deployment identity and blast radius.",
                _line_number(cleaned, scope_match.start()),
            )
        )

    for parameter in _PARAMETER.finditer(cleaned):
        name = parameter.group("name")
        decorators = parameter.group("decorators") or ""
        default = (parameter.group("default") or "").strip()
        secure = bool(re.search(r"@secure\s*\(\s*\)", decorators, re.IGNORECASE))
        line = _line_number(cleaned, parameter.start())
        if _SECRET_NAME.search(name) and not secure:
            findings.append(
                _finding(
                    "bicep_insecure_parameter",
                    f"param.{name}",
                    "dangerous",
                    "Credential-like Bicep parameter is missing @secure(); values may appear "
                    "in deployment history or logs.",
                    line,
                )
            )
        if secure and default and default not in {"''", "newGuid()"}:
            findings.append(
                _finding(
                    "bicep_secure_parameter_default",
                    f"param.{name}",
                    "dangerous",
                    "Secure Bicep parameter has a non-empty default; hard-coded secret material "
                    "remains visible in source and deployment metadata.",
                    line,
                )
            )

    blocks = list(_blocks(cleaned))
    declaration_count = len(re.findall(r"(?m)^[ \t]*(?:resource|module)\s+[A-Za-z_]", cleaned))
    if declaration_count > len(blocks):
        findings.append(
            _finding(
                "bicep_unparsed_declaration",
                "bicep.unparsed",
                "review",
                f"{declaration_count - len(blocks)} Bicep resource or module declaration(s) "
                "could not be expanded by the static scanner; inspect compiled ARM JSON.",
                1,
            )
        )

    for block in blocks:
        findings.append(
            _resource_finding(block) if block["kind"] == "resource" else _module_finding(block)
        )

    for output in _OUTPUT.finditer(cleaned):
        name = output.group("name")
        value = output.group("value")
        decorators = output.group("decorators") or ""
        if _SECRET_NAME.search(name) or _SECRET_FUNCTION.search(value):
            protected = bool(re.search(r"@secure\s*\(\s*\)", decorators, re.IGNORECASE))
            findings.append(
                _finding(
                    "bicep_sensitive_output",
                    f"output.{name}",
                    "review" if protected else "dangerous",
                    "Bicep output appears secret-bearing; keep it out of deployment history and "
                    "downstream logs." + (" @secure() is present." if protected else ""),
                    _line_number(cleaned, output.start()),
                )
            )

    for match in _EXTENSION_OR_IMPORT.finditer(cleaned):
        findings.append(
            _finding(
                f"bicep_{match.group('kind')}",
                f"{match.group('kind')}.line-{_line_number(cleaned, match.start())}",
                "review",
                f"Bicep {match.group('kind')} {match.group('value').strip()!r} adds syntax or "
                "provider behavior that must be resolved by the Bicep compiler.",
                _line_number(cleaned, match.start()),
            )
        )

    for pattern, kind, risk, explanation in (
        (
            _SECRET_FUNCTION,
            "bicep_secret_function",
            "dangerous",
            "Bicep retrieves secret material at deployment time; verify that it is consumed only "
            "by secure properties and never exposed as output.",
        ),
        (
            _EXTERNAL_FILE_FUNCTION,
            "bicep_external_file",
            "review",
            "Bicep loads an external file whose content is outside this submitted source artifact.",
        ),
        (
            _HARDCODED_AZURE_URL,
            "bicep_hardcoded_environment_url",
            "review",
            "Bicep hard-codes an Azure environment URL; use environment() for sovereign-cloud "
            "portability and verify the destination.",
        ),
    ):
        for index, match in enumerate(pattern.finditer(cleaned), start=1):
            findings.append(
                _finding(
                    kind,
                    f"{kind}.line-{_line_number(cleaned, match.start())}.{index}",
                    risk,
                    explanation,
                    _line_number(cleaned, match.start()),
                )
            )

    return {"bicep_source": source, "bicep_findings": findings}


class BicepAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "bicep"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        return isinstance(input_data.get("bicep_source"), str) and isinstance(
            input_data.get("bicep_findings"), list
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        findings = input_data.get("bicep_findings", [])
        return [item for item in findings if isinstance(item, dict)]

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw.get("address", "bicep.unknown")),
            resource_type=str(raw.get("kind", "bicep_unknown")),
            actions=tuple(str(action) for action in raw.get("actions", ("unknown",))),
            risk=str(raw.get("risk", "review")),
            explanation=str(raw.get("explanation", "Bicep source requires review.")),
        )


def analyze_bicep(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = BicepAdapter().analyze(data, tool_name="Azure Bicep")
    summary = PlanSummary(
        path=Path("bicep://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Azure Bicep")
    gate["adapter"] = "bicep"
    gate["total_changes"] = len(changes)
    return gate
