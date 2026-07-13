# Explanations are complete user-facing sentences; keeping them intact aids review.
# ruff: noqa: E501

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class JsonnetInputError(ValueError):
    """Raised when input is not a supported Jsonnet or Tanka artifact."""


_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)", re.I
)
_IMPORT = re.compile(r"\b(?P<kind>importstr|importbin|import)\s+(?P<value>[^,;\n}]+)")
_LITERAL = re.compile(r"^\s*(['\"])(?P<path>.*?)\1\s*[;)]?\s*$")
_FIELD = re.compile(r"(?m)(?P<name>[A-Za-z_][\w-]*|['\"][^'\"]+['\"])\s*[:+]?:\s*")
_SOURCE_MARKER = re.compile(
    r"\b(?:local|function|import|importstr|importbin|assert|error|self|super|std\.)\b|[{\[]"
)
_SHA256 = re.compile(r"^(?:sha256[-:]?)?[0-9a-fA-F]{64}$")
_COMMIT = re.compile(r"^[0-9a-fA-F]{7,64}$")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JsonnetInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _change(line: int, kind: str, risk: str, explanation: str) -> dict[str, Any]:
    return {
        "Address": f"line[{line}].{kind}",
        "Kind": kind,
        "Risk": risk,
        "Explanation": explanation,
    }


def _line(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _external_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return path.is_absolute() or ".." in path.parts or bool(re.match(r"^[A-Za-z]:/", normalized))


def parse_jsonnet(source: str, filename: str = "main.jsonnet") -> dict[str, Any]:
    """Parse metadata or conservatively scan source without evaluating Jsonnet."""
    if not source.strip():
        raise JsonnetInputError("input is empty")
    name = Path(filename).name.lower()
    if name in {"spec.json", "jsonnetfile.json", "jsonnetfile.lock.json"}:
        try:
            document = json.loads(source, object_pairs_hook=_reject_duplicates)
        except JsonnetInputError:
            raise
        except (json.JSONDecodeError, TypeError) as exc:
            raise JsonnetInputError(f"invalid JSON: {exc}") from exc
        if not isinstance(document, dict):
            raise JsonnetInputError("metadata root must be a JSON object")
        if name == "spec.json":
            if not (
                str(document.get("apiVersion", "")).startswith("tanka.dev/")
                and document.get("kind") == "Environment"
            ):
                raise JsonnetInputError("spec.json is not a Tanka Environment")
            artifact_type = "tanka-environment"
        elif name == "jsonnetfile.json":
            if not isinstance(document.get("dependencies"), list):
                raise JsonnetInputError("jsonnetfile.json must contain a dependencies array")
            artifact_type = "manifest"
        else:
            if not isinstance(document.get("dependencies"), list):
                raise JsonnetInputError("jsonnetfile.lock.json must contain a dependencies array")
            artifact_type = "lock"
        return {"jsonnet": {"artifact_type": artifact_type, "filename": name, "document": document}}
    if not (name.endswith(".jsonnet") or name.endswith(".libsonnet")):
        raise JsonnetInputError("source filename must end in .jsonnet or .libsonnet")
    if not _SOURCE_MARKER.search(source):
        raise JsonnetInputError("no recognizable Jsonnet syntax was found")
    return {
        "jsonnet": {"artifact_type": "source", "filename": Path(filename).name, "source": source}
    }


def _source_changes(source: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for match in _IMPORT.finditer(source):
        expression = match.group("value").strip()
        literal = _LITERAL.match(expression)
        if literal:
            path = literal.group("path")
            external = _external_path(path)
            vendor = path.startswith("vendor/") or "github.com/" in path
            risk = "dangerous" if external else "review"
            detail = (
                " escapes the project boundary"
                if external
                else " may load vendored or local content"
            )
            changes.append(
                _change(
                    _line(source, match.start()),
                    f"{match.group('kind')}_dependency",
                    risk,
                    f"Jsonnet {match.group('kind')} {detail}; review path confinement, provenance, sensitive data, and transitive imports."
                    + (
                        " Dependency identity and lock integrity must be checked." if vendor else ""
                    ),
                )
            )
        else:
            changes.append(
                _change(
                    _line(source, match.start()),
                    "dynamic_import",
                    "dangerous",
                    "Jsonnet computes an import target dynamically; effective files cannot be determined statically.",
                )
            )
    patterns = [
        (
            r"\bstd\.extVar\s*\(",
            "external_variable",
            "review",
            "Jsonnet consumes a host-supplied external variable; review injection source, type, scope, and secret handling.",
        ),
        (
            r"\bstd\.native\s*\(",
            "native_callback",
            "dangerous",
            "Jsonnet invokes a host-provided native callback whose behavior and side effects are outside the language model.",
        ),
        (
            r"\b(?:helm\.template|tanka\.helm|tk\.helm)\s*\(",
            "helm_render",
            "dangerous",
            "Tanka renders a Helm chart through the Helm CLI; review vendored chart provenance, values, CRDs, hooks, executable path, and rendered manifests.",
        ),
        (
            r"\b(?:kustomize|tk\.kustomize)\s*\(",
            "kustomize_render",
            "dangerous",
            "Tanka invokes Kustomize rendering; review bases, remote resources, plugins, generators, and rendered manifests.",
        ),
        (
            r"\bstd\.(?:trace|thisFile)\b|\b(?:assert|error)\b",
            "evaluation_control",
            "review",
            "Jsonnet evaluation behavior depends on diagnostics, assertions, errors, or the current source path.",
        ),
        (
            r"\b(?:apiVersion|kind)\s*:",
            "generated_kubernetes",
            "review",
            "Jsonnet appears to generate Kubernetes objects; review the fully rendered resource set, namespaces, RBAC, secrets, admission behavior, and cluster-scoped changes.",
        ),
        (
            r"\b(?:for\s+\w+\s+in|function\s*\(|if\s+.+\bthen\b|super\b|\+\s*{)",
            "generated_configuration",
            "review",
            "Jsonnet functions, comprehensions, conditionals, or inheritance generate effective configuration only during evaluation.",
        ),
    ]
    for pattern, kind, risk, explanation in patterns:
        found = re.search(pattern, source)
        if found:
            changes.append(_change(_line(source, found.start()), kind, risk, explanation))
    if re.search(r"\b(?:tla|target|environment|namespace|apiServer|contextNames)\b", source, re.I):
        changes.append(
            _change(
                1,
                "tanka_targeting",
                "dangerous",
                "Jsonnet contains Tanka environment or target selection; verify TLA inputs, kubeconfig context mapping, namespace, production scope, and apply/prune intent.",
            )
        )
    for match in _FIELD.finditer(source):
        name = match.group("name").strip("'\"")
        if _SECRET.search(name):
            changes.append(
                _change(
                    _line(source, match.start()),
                    "credential_data",
                    "dangerous",
                    "Jsonnet contains credential-like data or a credential reference; the value is omitted from analysis output.",
                )
            )
    changes.append(
        _change(
            1,
            "evaluation_boundary",
            "review",
            "Static analysis does not evaluate Jsonnet, resolve imports, accept ext-vars/TLAs, execute native callbacks, run Helm/Kustomize, read kubeconfig, contact Kubernetes, or inspect final generated objects.",
        )
    )
    return changes


def _environment_changes(document: dict[str, Any]) -> list[dict[str, Any]]:
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    changes = [
        _change(
            1,
            "tanka_environment",
            "dangerous",
            "Tanka Environment metadata selects a Kubernetes target; verify kubeconfig context ownership, API server identity, namespace, production scope, and operator authorization.",
        )
    ]
    server = str(spec.get("apiServer", ""))
    if server:
        changes.append(
            _change(
                1,
                "cluster_endpoint",
                "dangerous" if server.startswith("http://") else "review",
                "Tanka maps this environment to a Kubernetes API endpoint; verify TLS, cluster identity, credentials, and context matching.",
            )
        )
    if spec.get("contextNames"):
        changes.append(
            _change(
                1,
                "kubeconfig_context",
                "review",
                "Tanka selects one of the declared kubeconfig contexts; verify aliases cannot redirect deployment to an unintended cluster.",
            )
        )
    if str(spec.get("namespace", "")).lower() in {"default", "production", "prod", "kube-system"}:
        changes.append(
            _change(
                1,
                "sensitive_namespace",
                "dangerous",
                "Tanka targets a broad or sensitive namespace; review tenancy, RBAC, blast radius, and environment separation.",
            )
        )
    if spec.get("diffStrategy") == "subset":
        changes.append(
            _change(
                1,
                "subset_diff",
                "dangerous",
                "Tanka subset diff can omit server-side fields from review; confirm excluded state cannot conceal material changes.",
            )
        )
    if spec.get("injectLabels") is False:
        changes.append(
            _change(
                1,
                "ownership_labels_disabled",
                "dangerous",
                "Tanka ownership-label injection is disabled, weakening resource ownership tracking and safe garbage collection/pruning.",
            )
        )
    changes.append(
        _change(
            1,
            "cluster_boundary",
            "review",
            "Static analysis does not load kubeconfig, resolve context aliases, render Jsonnet, diff live state, contact Kubernetes, apply resources, or prune objects.",
        )
    )
    return changes


def _dependencies(document: dict[str, Any], locked: bool) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for index, dep in enumerate(document.get("dependencies", [])):
        if not isinstance(dep, dict):
            changes.append(
                _change(
                    index + 1,
                    "invalid_dependency",
                    "dangerous",
                    "Jsonnet dependency entry is not an object and cannot be validated.",
                )
            )
            continue
        source = dep.get("source") if isinstance(dep.get("source"), dict) else {}
        git = source.get("git") if isinstance(source.get("git"), dict) else {}
        remote = str(git.get("remote") or dep.get("source") or "")
        version = str(dep.get("version") or "")
        digest = str(dep.get("sum") or dep.get("sha256") or "")
        pinned = bool(_COMMIT.fullmatch(version)) or bool(
            re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][\w.-]+)?", version)
        )
        if locked:
            risk = "review" if pinned and _SHA256.fullmatch(digest) else "dangerous"
            explanation = "Jsonnet lock dependency records exact content; verify repository identity, immutable revision, SHA-256 integrity, and transitive ownership."
            if risk == "dangerous":
                explanation = "Jsonnet lock dependency lacks a recognizable immutable version or SHA-256 integrity value; installs may not be reproducible or tamper-evident."
        else:
            risk = "review" if pinned else "dangerous"
            explanation = "Jsonnet manifest declares a direct external dependency; verify source ownership, immutable version, lock-file coverage, credentials, and transitive packages."
        if remote.startswith("http://") or remote.startswith("git://"):
            risk = "dangerous"
            explanation = "Jsonnet dependency uses an insecure transport; source content and identity may be intercepted or replaced."
        changes.append(
            _change(
                index + 1, "locked_dependency" if locked else "direct_dependency", risk, explanation
            )
        )
    changes.append(
        _change(
            1,
            "dependency_resolution_boundary",
            "review",
            "Static analysis does not run jsonnet-bundler, authenticate, fetch repositories, inspect vendor content, resolve transitive dependencies, or recompute hashes.",
        )
    )
    return changes


class JsonnetAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "jsonnet"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("jsonnet")
        return isinstance(payload, dict) and payload.get("artifact_type") in {
            "source",
            "tanka-environment",
            "manifest",
            "lock",
        }

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["jsonnet"]
        artifact = payload["artifact_type"]
        if artifact == "source":
            return _source_changes(payload["source"])
        if artifact == "tanka-environment":
            return _environment_changes(payload["document"])
        return _dependencies(payload["document"], artifact == "lock")

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"jsonnet_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_jsonnet(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = JsonnetAdapter().analyze(data, tool_name="Jsonnet/Tanka")
    summary = PlanSummary(
        path=Path("jsonnet://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Jsonnet/Tanka")
    gate["adapter"] = "jsonnet"
    gate["artifact_type"] = data["jsonnet"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
