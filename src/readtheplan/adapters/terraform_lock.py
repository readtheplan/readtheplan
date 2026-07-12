from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class TerraformLockInputError(ValueError):
    """Raised when input is not a strict Terraform/OpenTofu dependency lock file."""


_ADDRESS = re.compile(
    r"(?P<host>[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)/"
    r"(?P<namespace>[a-z0-9][a-z0-9_-]*)/(?P<type>[a-z0-9][a-z0-9_-]*)$"
)
_VERSION = re.compile(
    r"(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_KNOWN_REGISTRIES = {"registry.terraform.io", "registry.opentofu.org"}
_ALLOWED_ATTRIBUTES = {"version", "constraints", "hashes"}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _strip_comments(source: str) -> str:
    output = list(source)
    state = "code"
    quote = ""
    index = 0
    while index < len(source):
        if state == "code":
            if source.startswith("/*", index):
                output[index : index + 2] = "  "
                index += 2
                state = "block"
                continue
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
        elif state == "block":
            if source.startswith("*/", index):
                output[index : index + 2] = "  "
                index += 2
                state = "code"
                continue
            if source[index] != "\n":
                output[index] = " "
        elif state == "string":
            if source[index] == "\\":
                index += 2
                continue
            if source[index] == quote:
                state = "code"
        index += 1
    if state == "block":
        raise TerraformLockInputError("unterminated block comment")
    if state == "string":
        raise TerraformLockInputError("unterminated quoted string")
    return "".join(output)


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


def _provider_blocks(source: str) -> list[tuple[str, int, int, str]]:
    pattern = re.compile(r'(?m)^\s*provider\s+"([^"\r\n]+)"\s*\{')
    blocks: list[tuple[str, int, int, str]] = []
    for match in pattern.finditer(source):
        opening = source.find("{", match.start())
        closing = _matching_brace(source, opening)
        if closing is None:
            raise TerraformLockInputError(
                f"unterminated provider block for {match.group(1)!r}"
            )
        blocks.append((match.group(1), match.start(), closing + 1, source[opening + 1 : closing]))
    return blocks


def _attribute_names(body: str) -> list[str]:
    result: list[str] = []
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
        if char in "[{(":
            depth += 1
            index += 1
            continue
        if char in "]})":
            depth = max(0, depth - 1)
            index += 1
            continue
        if depth == 0 and (char.isalpha() or char == "_"):
            end = index + 1
            while end < len(body) and (body[end].isalnum() or body[end] == "_"):
                end += 1
            equals = end
            while equals < len(body) and body[equals].isspace():
                equals += 1
            if equals < len(body) and body[equals] == "=":
                result.append(body[index:end])
            index = end
            continue
        index += 1
    return result


def _text(value: Any) -> str:
    return str(value).strip().strip("\"'")


def parse_terraform_lock(source: str) -> dict[str, Any]:
    """Parse a strict machine-generated .terraform.lock.hcl file."""
    if not source.strip():
        raise TerraformLockInputError("input is empty")
    clean = _strip_comments(source)
    blocks = _provider_blocks(clean)
    if not blocks:
        raise TerraformLockInputError("input contains no provider lock blocks")
    remainder = list(clean)
    seen_addresses: set[str] = set()
    for address, start, end, body in blocks:
        remainder[start:end] = " " * (end - start)
        if address in seen_addresses:
            raise TerraformLockInputError(f"duplicate provider lock block: {address}")
        seen_addresses.add(address)
        names = _attribute_names(body)
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise TerraformLockInputError(
                f"duplicate provider attribute(s) for {address}: {', '.join(duplicates)}"
            )
        unknown = sorted(set(names) - _ALLOWED_ATTRIBUTES)
        if unknown:
            raise TerraformLockInputError(
                f"unsupported provider attribute(s) for {address}: {', '.join(unknown)}"
            )
    if "".join(remainder).strip():
        raise TerraformLockInputError("lock file contains content outside provider blocks")
    try:
        import hcl2
        from hcl2.utils import SerializationOptions

        document = hcl2.loads(
            clean,
            serialization_options=SerializationOptions(
                explicit_blocks=False,
                strip_string_quotes=True,
            ),
        )
    except Exception as exc:
        raise TerraformLockInputError(f"invalid dependency lock HCL: {exc}") from exc
    raw_providers = document.get("provider") if isinstance(document, dict) else None
    if not isinstance(raw_providers, list) or len(raw_providers) != len(blocks):
        raise TerraformLockInputError("dependency lock provider blocks could not be decoded")
    providers: list[dict[str, Any]] = []
    for item in raw_providers:
        if not isinstance(item, dict) or len(item) != 1:
            raise TerraformLockInputError("provider lock block must have exactly one source label")
        address, body = next(iter(item.items()))
        if not isinstance(address, str) or not isinstance(body, dict):
            raise TerraformLockInputError("provider lock source and body must be literal values")
        address = _text(address)
        match = _ADDRESS.fullmatch(address)
        if not match:
            raise TerraformLockInputError(f"invalid provider source address: {address}")
        if "version" not in body:
            raise TerraformLockInputError(f"provider {address} is missing selected version")
        version = _text(body["version"])
        if not _VERSION.fullmatch(version) or "${" in version:
            raise TerraformLockInputError(
                f"provider {address} has invalid selected version: {version}"
            )
        constraints = body.get("constraints")
        if constraints is not None and (
            not isinstance(constraints, str) or "${" in constraints
        ):
            raise TerraformLockInputError(f"provider {address} constraints must be literal")
        hashes = body.get("hashes", [])
        if not isinstance(hashes, list) or not all(isinstance(value, str) for value in hashes):
            raise TerraformLockInputError(f"provider {address} hashes must be a string list")
        normalized_hashes = [_text(value) for value in hashes]
        if len(set(normalized_hashes)) != len(normalized_hashes):
            raise TerraformLockInputError(f"provider {address} contains duplicate hashes")
        for value in normalized_hashes:
            _validate_hash(address, value)
        providers.append(
            {
                "address": address,
                "host": match.group("host"),
                "namespace": match.group("namespace"),
                "type": match.group("type"),
                "version": version,
                "constraints": _text(constraints) if constraints is not None else None,
                "hashes": normalized_hashes,
            }
        )
    return {"terraform_lock": {"providers": providers}}


def _validate_hash(address: str, value: str) -> None:
    if value.startswith("zh:"):
        if not re.fullmatch(r"zh:[0-9a-fA-F]{64}", value):
            raise TerraformLockInputError(f"provider {address} has malformed zh checksum")
        return
    if value.startswith("h1:"):
        encoded = value[3:]
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise TerraformLockInputError(
                f"provider {address} has malformed h1 checksum"
            ) from exc
        if len(decoded) != 32:
            raise TerraformLockInputError(f"provider {address} has malformed h1 checksum")
        return
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*:.+", value):
        raise TerraformLockInputError(f"provider {address} has malformed checksum entry")


def _private_or_local_host(host: str) -> bool:
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".local", ".internal")):
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _numeric_version(value: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?", value)
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def _constraint_allows(version: str, constraint: str) -> bool | None:
    selected = _numeric_version(version)
    if selected is None:
        return None
    for raw_clause in constraint.split(","):
        clause = raw_clause.strip()
        match = re.fullmatch(
            r"(>=|<=|!=|==|=|>|<|~>)?\s*"
            r"((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,2})",
            clause,
        )
        if not match:
            return None
        operator = match.group(1) or "="
        requested = _numeric_version(match.group(2))
        if requested is None:
            return None
        if operator in {"=", "=="} and selected != requested:
            return False
        if operator == "!=" and selected == requested:
            return False
        if operator == ">" and selected <= requested:
            return False
        if operator == ">=" and selected < requested:
            return False
        if operator == "<" and selected >= requested:
            return False
        if operator == "<=" and selected > requested:
            return False
        if operator == "~>":
            components = match.group(2).count(".") + 1
            upper = (
                (requested[0] + 1, 0, 0)
                if components <= 2
                else (requested[0], requested[1] + 1, 0)
            )
            if selected < requested or selected >= upper:
                return False
    return True


def _provider_changes(provider: dict[str, Any]) -> list[dict[str, str]]:
    address = f"provider.{provider['address']}"
    version = str(provider["version"])
    hashes = list(provider["hashes"])
    schemes = {value.split(":", 1)[0] for value in hashes}
    changes = [
        _change(
            address,
            "locked_provider",
            "review",
            f"Dependency lock selects provider {provider['address']!r} at exact version "
            f"{version!r} with {len(hashes)} accepted package checksum(s).",
        )
    ]
    version_match = _VERSION.fullmatch(version)
    if version_match and version_match.group("pre"):
        changes.append(
            _change(
                f"{address}.version",
                "prerelease_provider",
                "dangerous",
                "The selected provider version is a pre-release build; review stability, "
                "publisher provenance, and upgrade intent.",
            )
        )
    elif version_match and version_match.group("major") == "0":
        changes.append(
            _change(
                f"{address}.version",
                "pre_one_provider",
                "review",
                "The selected provider has a zero major version; compatibility and security "
                "semantics may change between minor releases.",
            )
        )
    host = str(provider["host"])
    if host not in _KNOWN_REGISTRIES:
        local = _private_or_local_host(host)
        changes.append(
            _change(
                f"{address}.source",
                "local_provider_origin" if local else "custom_provider_origin",
                "dangerous" if local else "review",
                f"Provider is locked to custom registry host {host!r}; verify TLS, registry "
                "ownership, authentication, signing policy, and mirror/origin consistency.",
            )
        )
    constraints = provider.get("constraints")
    if constraints is None:
        changes.append(
            _change(
                f"{address}.constraints",
                "missing_constraint_context",
                "review",
                "The lock entry does not record the version constraints that informed selection; "
                "compare it with required_providers in the root and transitive modules.",
            )
        )
    elif str(constraints).strip() in {"*", ">= 0", ">= 0.0", ">= 0.0.0"}:
        changes.append(
            _change(
                f"{address}.constraints",
                "unbounded_constraint_context",
                "review",
                "The recorded provider constraint is effectively unbounded. The lock pins this "
                "selection, but future upgrades can choose any later version.",
            )
        )
    else:
        allowed = _constraint_allows(version, str(constraints))
        if allowed is False:
            changes.append(
                _change(
                    f"{address}.constraints",
                    "constraint_selection_mismatch",
                    "dangerous",
                    f"Selected provider version {version!r} does not satisfy the recorded "
                    f"constraint {constraints!r}; the lock may be stale relative to current "
                    "configuration.",
                )
            )
        elif allowed is None:
            changes.append(
                _change(
                    f"{address}.constraints",
                    "unverified_constraint_syntax",
                    "review",
                    f"The recorded constraint {constraints!r} uses syntax this static analyzer "
                    "does not evaluate; verify the selected version against required_providers.",
                )
            )
    if not hashes:
        changes.append(
            _change(
                f"{address}.hashes",
                "missing_checksums",
                "dangerous",
                "The selected provider has no accepted package checksum, so installation lacks "
                "the lock file's package-integrity verification boundary.",
            )
        )
    elif len(hashes) == 1:
        changes.append(
            _change(
                f"{address}.hashes",
                "single_package_checksum",
                "dangerous",
                "Only one package checksum is recorded; portability to other target platforms "
                "and consistency with the origin's signed checksum set require review.",
            )
        )
    if hashes and "h1" not in schemes:
        changes.append(
            _change(
                f"{address}.hashes.h1",
                "missing_preferred_hash",
                "review",
                "No h1 content checksum is recorded; unpacked or recompressed mirror packages "
                "may require Terraform/OpenTofu to learn an h1 checksum later.",
            )
        )
    if hashes and "zh" not in schemes:
        changes.append(
            _change(
                f"{address}.hashes.zh",
                "missing_registry_hashes",
                "review",
                "No zh registry-package checksum is recorded; the file alone cannot show "
                "coverage of the origin registry's signed cross-platform package set.",
            )
        )
    unknown = sorted(schemes - {"h1", "zh"})
    if unknown:
        changes.append(
            _change(
                f"{address}.hashes.unknown",
                "unsupported_hash_scheme",
                "dangerous",
                "The lock entry uses checksum scheme(s) this analyzer cannot validate: "
                + ", ".join(unknown)
                + ".",
            )
        )
    return changes


class TerraformLockAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "terraform-lock"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("terraform_lock")
        return isinstance(payload, dict) and isinstance(payload.get("providers"), list)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for provider in input_data["terraform_lock"]["providers"]:
            changes.extend(_provider_changes(provider))
        changes.append(
            _change(
                "terraform_lock.effective_dependencies",
                "lock_boundary",
                "review",
                "The dependency lock records provider selections and accepted hashes, but not "
                "remote module versions, signer identities, hash-to-platform mappings, registry "
                "or mirror configuration, plugin-cache provenance, or whether CI enforces "
                "read-only lock mode.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"terraform_lock_{raw['Kind']}",
            actions=("lock",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_terraform_lock(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = TerraformLockAdapter().analyze(data, tool_name="Terraform/OpenTofu lock")
    summary = PlanSummary(
        path=Path("terraform-lock://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(
        summary,
        catalog=catalog,
        tool_name="Terraform/OpenTofu lock",
    )
    gate["adapter"] = "terraform-lock"
    gate["provider_count"] = len(data["terraform_lock"]["providers"])
    gate["total_changes"] = len(changes)
    return gate
