from __future__ import annotations

import base64
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class OPAInputError(ValueError):
    """Raised when input is not recognizable standalone OPA/Rego configuration."""


_SECRET_NAME = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential)", re.I
)
_RULE = re.compile(r"(?m)^\s*(default\s+)?([A-Za-z_][\w]*)\s*(?:contains\b|if\b|:=|=|\[|\{)")
_PACKAGE = re.compile(r"(?m)^\s*package\s+([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\s*$")
_IMPORT = re.compile(r"(?m)^\s*import\s+([^\s]+)(?:\s+as\s+[A-Za-z_][\w]*)?\s*$")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OPAInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _clean_rego(source: str, *, blank_strings: bool = True) -> str:
    output = list(source)
    index = 0
    state = "code"
    quote = ""
    depth = 0
    while index < len(source):
        char = source[index]
        if state == "code":
            if char == "#":
                output[index] = " "
                state = "comment"
            elif char in {'"', "'", "`"}:
                quote = char
                state = "string"
                if blank_strings:
                    output[index] = " "
            elif char in "{([":
                depth += 1
            elif char in "})]":
                depth -= 1
                if depth < 0:
                    raise OPAInputError("unbalanced Rego delimiters")
        elif state == "comment":
            if char == "\n":
                state = "code"
            else:
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
        raise OPAInputError("unterminated Rego string")
    if depth != 0:
        raise OPAInputError("unbalanced Rego delimiters")
    return "".join(output)


def _parse_json(source: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(source, object_pairs_hook=_unique_object)
    except OPAInputError:
        raise
    except json.JSONDecodeError as exc:
        raise OPAInputError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise OPAInputError(f"{label} must be a JSON object")
    return value


def parse_opa(source: str, filename: str = "policy.rego") -> dict[str, Any]:
    """Recognize Rego, OPA bundle metadata, or Conftest config without evaluating it."""
    if not source.strip():
        raise OPAInputError("input is empty")
    name = Path(filename).name.lower()
    if name == "conftest.toml":
        try:
            document = tomllib.loads(source)
        except tomllib.TOMLDecodeError as exc:
            raise OPAInputError(f"invalid Conftest TOML: {exc}") from exc
        if not isinstance(document, dict) or not document:
            raise OPAInputError("Conftest configuration is empty")
        return {"opa": {"artifact_type": "conftest", "document": document}}
    if name == ".manifest":
        document = _parse_json(source, "OPA bundle manifest")
        if not (
            {"revision", "roots", "rego_version", "file_rego_versions", "wasm", "metadata"}
            & set(document)
        ):
            raise OPAInputError("JSON is not recognized as an OPA bundle manifest")
        return {"opa": {"artifact_type": "manifest", "document": document}}
    if name == ".signatures.json":
        document = _parse_json(source, "OPA bundle signatures")
        signatures = document.get("signatures")
        if (
            not isinstance(signatures, list)
            or not signatures
            or not all(isinstance(v, str) for v in signatures)
        ):
            raise OPAInputError("OPA bundle signatures must contain a non-empty string array")
        return {"opa": {"artifact_type": "signatures", "document": document}}
    clean = _clean_rego(source)
    comments_only = _clean_rego(source, blank_strings=False)
    package = _PACKAGE.search(clean)
    if not package:
        raise OPAInputError("Rego module must contain one package declaration")
    if len(_PACKAGE.findall(clean)) != 1:
        raise OPAInputError("Rego module must contain exactly one package declaration")
    return {
        "opa": {
            "artifact_type": "rego",
            "document": {
                "source": source,
                "clean": clean,
                "comments_only": comments_only,
                "package": package.group(1),
                "filename": name,
            },
        }
    }


def _line(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1


def _rego_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    source = str(document["source"])
    clean = str(document["clean"])
    comments_only = str(document["comments_only"])
    package = str(document["package"])
    changes: list[dict[str, str]] = []
    imports = [match.group(1) for match in _IMPORT.finditer(clean)]
    for index, imported in enumerate(imports):
        if imported.startswith("data.") and not imported.startswith("data.conftest"):
            changes.append(
                _change(
                    f"rego.import[{index}]",
                    "external_data_dependency",
                    "review",
                    f"Rego package {package!r} imports policy data whose provenance and "
                    "runtime value are outside this module.",
                )
            )
    dangerous_builtins = {
        "http.send": "make an outbound network request and can disclose policy input or data",
        "opa.runtime": "read evaluator configuration, version, and process environment variables",
    }
    for builtin, reason in dangerous_builtins.items():
        for match in re.finditer(rf"\b{re.escape(builtin)}\s*\(", clean):
            changes.append(
                _change(
                    f"source.line.{_line(clean, match.start())}.{builtin}",
                    "runtime_builtin",
                    "dangerous",
                    f"Rego calls {builtin}(), which can {reason} during evaluation.",
                )
            )
    for builtin in ("print", "trace"):
        for match in re.finditer(rf"\b{builtin}\s*\(", clean):
            changes.append(
                _change(
                    f"source.line.{_line(clean, match.start())}.{builtin}",
                    "debug_output",
                    "dangerous",
                    f"Rego calls {builtin}(); production evaluation output can expose "
                    "sensitive input, data, or decisions.",
                )
            )
    rules = [(m.group(2), m.start(), bool(m.group(1))) for m in _RULE.finditer(clean)]
    names = {name for name, _, _ in rules}
    if re.search(r"(?m)^\s*(?:default\s+)?allow\s*(?::=|=)\s*true\s*$", clean):
        changes.append(
            _change(
                "rego.allow",
                "unconditional_allow",
                "dangerous",
                "Rego defines an unconditional true allow decision; callers using it as "
                "authorization may fail open.",
            )
        )
    if re.search(r"(?m)^\s*default\s+allow\s*(?::=|=)\s*true\s*$", clean):
        changes.append(
            _change(
                "rego.default.allow",
                "fail_open_default",
                "dangerous",
                "Rego defaults allow to true, so unmatched or incomplete inputs may be authorized.",
            )
        )
    if any(name.startswith("exception") for name in names):
        broad = bool(
            re.search(
                r"(?m)^\s*rules\s*:?=\s*\[\s*[\"']{2}\s*\]",
                comments_only,
            )
        )
        changes.append(
            _change(
                "rego.exception",
                "broad_exception" if broad else "policy_exception",
                "dangerous" if broad else "review",
                "Conftest exception can exempt all deny/violation rules for matching input."
                if broad
                else "Conftest exception suppresses selected deny/violation rules; review "
                "scope, ownership, expiry, and reporting.",
            )
        )
    if (
        any(
            name in {"deny", "violation"} or name.startswith(("deny_", "violation_"))
            for name in names
        )
        is False
    ):
        changes.append(
            _change(
                "rego.enforcement",
                "enforcement_boundary",
                "review",
                "No Conftest deny or violation rule was recognized; the module may be "
                "advisory, use another entrypoint, or be ineffective for Conftest.",
            )
        )
    if not any(name.startswith("test_") for name in names) and not str(
        document["filename"]
    ).endswith("_test.rego"):
        changes.append(
            _change(
                "rego.tests",
                "test_coverage_boundary",
                "review",
                "No in-module Rego test rule was recognized; tests may live elsewhere and "
                "were not loaded.",
            )
        )
    if "import rego.v1" not in clean and "import future.keywords" not in clean:
        changes.append(
            _change(
                "rego.language",
                "rego_version_boundary",
                "review",
                "The module does not explicitly import rego.v1 or future keywords; effective "
                "syntax depends on OPA capabilities and bundle version settings.",
            )
        )
    if re.search(r"\bwith\s+(?:input|data)\b", clean):
        changes.append(
            _change(
                "rego.overrides",
                "evaluation_override",
                "review",
                "Rego uses with to replace input or data for a nested evaluation; review "
                "that overrides cannot bypass the intended policy path.",
            )
        )
    for match in re.finditer(r"([\"'`])([^\n]*?)\1", source):
        literal = match.group(2)
        if _SECRET_NAME.search(literal) and re.search(r"[:=]", literal):
            changes.append(
                _change(
                    f"source.line.{_line(source, match.start())}.secret",
                    "literal_secret",
                    "dangerous",
                    "Rego source contains a credential-like literal; values are intentionally "
                    "omitted from analysis output.",
                )
            )
    changes.append(
        _change(
            "opa.effective_evaluation",
            "evaluation_boundary",
            "review",
            "Static analysis does not execute OPA/Conftest, load input or data, resolve "
            "capabilities or custom built-ins, compile Wasm, verify bundles, or prove "
            "decision correctness.",
        )
    )
    return changes


def _manifest_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    revision = document.get("revision")
    if not isinstance(revision, str) or not revision.strip():
        changes.append(
            _change(
                "bundle.revision",
                "mutable_bundle_revision",
                "review",
                "OPA bundle manifest has no non-empty revision, weakening rollout identity "
                "and audit correlation.",
            )
        )
    roots = document.get("roots")
    if roots is None or roots == [""]:
        changes.append(
            _change(
                "bundle.roots",
                "global_bundle_root",
                "dangerous",
                "OPA bundle owns the entire policy and data namespace; activation can replace "
                "all loaded policy and data.",
            )
        )
    elif not isinstance(roots, list) or not all(isinstance(v, str) for v in roots):
        raise OPAInputError("OPA bundle roots must be an array of strings")
    else:
        normalized = [r.strip("/") for r in roots]
        for i, root in enumerate(normalized):
            for other in normalized[i + 1 :]:
                if root == other or root.startswith(other + "/") or other.startswith(root + "/"):
                    changes.append(
                        _change(
                            "bundle.roots",
                            "overlapping_bundle_roots",
                            "dangerous",
                            "OPA bundle manifest contains overlapping roots that make ownership "
                            "invalid or ambiguous.",
                        )
                    )
                    break
    version = document.get("rego_version")
    if version not in (None, 0, 1):
        raise OPAInputError("OPA bundle rego_version must be 0 or 1")
    if version in (None, 0):
        changes.append(
            _change(
                "bundle.rego_version",
                "legacy_rego_semantics",
                "review",
                "Bundle does not require Rego v1 semantics; compatibility behavior depends "
                "on OPA version and per-file overrides.",
            )
        )
    wasm = document.get("wasm", [])
    if wasm:
        if not isinstance(wasm, list) or not all(isinstance(v, dict) for v in wasm):
            raise OPAInputError("OPA bundle wasm must be an array of objects")
        for index, resolver in enumerate(wasm):
            if not isinstance(resolver.get("entrypoint"), str) or not isinstance(
                resolver.get("module"), str
            ):
                raise OPAInputError(
                    "OPA bundle Wasm resolver requires string entrypoint and module"
                )
            path = PurePosixPath(str(resolver["module"]))
            escaped = path.is_absolute() or ".." in path.parts
            changes.append(
                _change(
                    f"bundle.wasm[{index}]",
                    "wasm_policy",
                    "dangerous" if escaped else "review",
                    "OPA bundle declares compiled Wasm policy; static source analysis cannot "
                    "inspect or prove the executable decision logic.",
                )
            )
    changes.append(
        _change(
            "bundle.signature",
            "signature_boundary",
            "review",
            "A manifest does not prove bundle authenticity; unsigned bundles may activate "
            "unless OPA verification is configured and .signatures.json is present.",
        )
    )
    return changes


def _decode_jwt_part(value: str) -> dict[str, Any]:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        decoded = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OPAInputError("invalid JWT in OPA bundle signatures") from exc
    if not isinstance(decoded, dict):
        raise OPAInputError("OPA bundle signature JWT header and payload must be objects")
    return decoded


def _signature_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, token in enumerate(document["signatures"]):
        parts = token.split(".")
        if len(parts) != 3:
            raise OPAInputError("OPA bundle signature must be a three-part JWT")
        header = _decode_jwt_part(parts[0])
        payload = _decode_jwt_part(parts[1])
        algorithm = str(header.get("alg") or "").lower()
        if not algorithm or algorithm == "none":
            changes.append(
                _change(
                    f"bundle.signature[{index}].algorithm",
                    "unsigned_jwt",
                    "dangerous",
                    "OPA bundle signature JWT uses no cryptographic signing algorithm.",
                )
            )
        if not header.get("kid"):
            changes.append(
                _change(
                    f"bundle.signature[{index}].kid",
                    "implicit_verification_key",
                    "review",
                    "OPA bundle signature JWT omits kid; verification depends entirely on the "
                    "out-of-band default key configuration.",
                )
            )
        if not payload.get("scope"):
            changes.append(
                _change(
                    f"bundle.signature[{index}].scope",
                    "unscoped_signature",
                    "review",
                    "OPA bundle signature JWT omits scope, so out-of-band verification cannot "
                    "bind it to a narrower bundle purpose.",
                )
            )
        files = payload.get("files")
        if not isinstance(files, list) or not files:
            changes.append(
                _change(
                    f"bundle.signature[{index}].files",
                    "missing_signed_files",
                    "dangerous",
                    "OPA bundle signature JWT does not declare a non-empty file hash inventory.",
                )
            )
    changes.append(
        _change(
            "bundle.signature.verification",
            "verification_boundary",
            "review",
            "Static analysis decodes only non-secret JWT metadata; it does not load keys, "
            "verify signatures or hashes, compare archive members, or prove OPA verification "
            "configuration.",
        )
    )
    return changes


def _conftest_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    policy = document.get("policy", "policy")
    paths = policy if isinstance(policy, list) else [policy]
    if not all(isinstance(v, str) for v in paths):
        raise OPAInputError("Conftest policy must be a string or string array")
    for index, value in enumerate(paths):
        path = Path(value)
        remote = value.lower().startswith(("http://", "https://", "git://", "oci://"))
        escaped = path.is_absolute() or ".." in path.parts
        changes.append(
            _change(
                f"conftest.policy[{index}]",
                "external_policy_path" if remote or escaped else "policy_path",
                "dangerous" if remote or escaped else "review",
                "Conftest policy lookup references a remote or workspace-external location; "
                "review provenance and path confinement."
                if remote or escaped
                else "Conftest policy directory controls which Rego modules are evaluated; "
                "review ownership and completeness.",
            )
        )
    namespace = document.get("namespace", "main")
    if namespace == "":
        changes.append(
            _change(
                "conftest.namespace",
                "all_namespace_scope",
                "review",
                "Conftest namespace is empty; confirm whether invocation flags expand or "
                "replace the intended policy query scope.",
            )
        )
    for key in ("data", "capabilities"):
        if key in document:
            changes.append(
                _change(
                    f"conftest.{key}",
                    f"{key}_dependency",
                    "review",
                    f"Conftest {key} configuration affects effective policy evaluation and "
                    "was not loaded or validated by static analysis.",
                )
            )
    changes.append(
        _change(
            "conftest.effective_invocation",
            "invocation_boundary",
            "review",
            "Conftest flags and environment variables override conftest.toml; static analysis "
            "does not parse target inputs, pull policies, load data, or execute tests.",
        )
    )
    return changes


class OPAAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "opa"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("opa")
        return (
            isinstance(payload, dict)
            and payload.get("artifact_type") in {"rego", "manifest", "signatures", "conftest"}
            and isinstance(payload.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["opa"]
        handlers = {
            "rego": _rego_changes,
            "manifest": _manifest_changes,
            "signatures": _signature_changes,
            "conftest": _conftest_changes,
        }
        return handlers[payload["artifact_type"]](payload["document"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"opa_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_opa(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = OPAAdapter().analyze(data, tool_name="OPA/Rego")
    summary = PlanSummary(
        path=Path("opa://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="OPA/Rego")
    gate["adapter"] = "opa"
    gate["artifact_type"] = data["opa"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
