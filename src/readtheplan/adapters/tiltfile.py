from __future__ import annotations

import ast
import re
from pathlib import Path, PurePosixPath
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class TiltfileInputError(ValueError):
    """Raised when text is not recognizable Tiltfile source."""


_TILT_CALLS = {
    "allow_k8s_contexts",
    "custom_build",
    "default_registry",
    "docker_build",
    "docker_compose",
    "helm",
    "include",
    "k8s_custom_deploy",
    "k8s_resource",
    "k8s_yaml",
    "kustomize",
    "load",
    "load_dynamic",
    "local",
    "local_resource",
    "port_forward",
    "secret_settings",
    "sync",
}
_MARKER = re.compile(r"\b(" + "|".join(sorted(_TILT_CALLS)) + r")\s*\(")
_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)", re.I
)
_REMOTE = re.compile(r"^(?:https?|git|ssh|oci|ext)://|^[^/@\s]+@[^:\s]+:", re.I)
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$", re.I)


def _change(line: int, kind: str, risk: str, explanation: str) -> dict[str, Any]:
    return {
        "Address": f"line[{line}].{kind}",
        "Kind": kind,
        "Risk": risk,
        "Explanation": explanation,
    }


def _call_name(node: ast.Call) -> str:
    value: ast.AST = node.func
    parts: list[str] = []
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    return ".".join(reversed(parts))


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return None


def _argument(node: ast.Call, index: int, keyword: str) -> ast.AST | None:
    for item in node.keywords:
        if item.arg == keyword:
            return item.value
    return node.args[index] if len(node.args) > index else None


def _external_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        bool(_REMOTE.match(normalized))
        or path.is_absolute()
        or ".." in path.parts
        or bool(re.match(r"^[A-Za-z]:/", normalized))
    )


def _paths(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if isinstance(item, str)]
    return []


class _TiltVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.changes: list[dict[str, Any]] = []
        self.loaded_symbols: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        if any(_SECRET.search(name) for name in names) and _literal(node.value) not in (None, ""):
            self.changes.append(
                _change(
                    node.lineno,
                    "literal_secret",
                    "dangerous",
                    "Tiltfile assigns credential-like material; the value is omitted from output.",
                )
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: C901, PLR0912, PLR0915
        name = _call_name(node)
        leaf = name.rsplit(".", 1)[-1]
        line = node.lineno

        if leaf == "load":
            for symbol in node.args[1:]:
                value = _literal(symbol)
                if isinstance(value, str):
                    self.loaded_symbols.add(value)

        if leaf in {"local", "local_resource"}:
            self.changes.append(
                _change(
                    line,
                    "host_command",
                    "dangerous",
                    "Tilt executes a command on the host; review command/serve command, working "
                    "directory, environment, filesystem/network access, auto-init, probes, "
                    "parallelism, credentials, and dependency triggers.",
                )
            )
        elif leaf == "custom_build":
            self.changes.append(
                _change(
                    line,
                    "custom_image_build",
                    "dangerous",
                    "Tilt custom image builder executes a host command; review build context, "
                    "dependencies, environment, registry output, push behavior, and image inputs.",
                )
            )
        elif leaf == "docker_build":
            self.changes.append(
                _change(
                    line,
                    "docker_build",
                    "review",
                    "Tilt builds a container image; review context, Dockerfile or inline content, "
                    "build arguments/secrets, target, network, cache, platform, and live updates.",
                )
            )
        elif leaf == "docker_compose":
            self.changes.append(
                _change(
                    line,
                    "compose_deployment",
                    "dangerous",
                    "Tilt loads and operates Docker Compose services; review files, project name, "
                    "profiles, environment, builds, mounts, ports, privileges, and teardown scope.",
                )
            )
        elif leaf == "k8s_yaml":
            self.changes.append(
                _change(
                    line,
                    "kubernetes_deployment",
                    "dangerous",
                    "Tilt loads and applies Kubernetes resources; review manifest provenance, "
                    "rendered content, namespace, image injection, duplicates, and deletion scope.",
                )
            )
        elif leaf in {"helm", "kustomize"}:
            self.changes.append(
                _change(
                    line,
                    f"{leaf}_render",
                    "review",
                    f"Tilt invokes {leaf} rendering; review source confinement, dependencies, "
                    "values/flags/plugins, executable binaries, and rendered resources.",
                )
            )
        elif leaf == "k8s_custom_deploy":
            self.changes.append(
                _change(
                    line,
                    "custom_kubernetes_deploy",
                    "dangerous",
                    "Tilt custom deployer executes apply and delete commands against Kubernetes; "
                    "review cluster identity, commands, output discovery, dependencies, and scope.",
                )
            )
        elif leaf == "k8s_resource":
            self.changes.append(
                _change(
                    line,
                    "kubernetes_resource_control",
                    "review",
                    "Tilt changes resource grouping, dependencies, pod selectors, readiness, "
                    "auto-init, trigger behavior, and port forwarding for Kubernetes workloads.",
                )
            )
        elif leaf in {"load", "load_dynamic", "include"}:
            source = _literal(_argument(node, 0, "path"))
            dangerous = leaf == "load_dynamic" or (
                isinstance(source, str) and (_REMOTE.match(source) or _external_path(source))
            )
            self.changes.append(
                _change(
                    line,
                    "tiltfile_dependency",
                    "dangerous" if dangerous else "review",
                    "Tilt loads and executes another Tiltfile or extension; review source "
                    "provenance/version, path confinement, repository configuration, exported "
                    "symbols, transitive behavior, and runtime metaprogramming.",
                )
            )
        elif leaf in {"read_file", "read_json", "read_yaml", "read_yaml_stream", "listdir"}:
            self.changes.append(
                _change(
                    line,
                    "host_file_read",
                    "review",
                    "Tilt reads host filesystem content during Tiltfile evaluation; review path "
                    "confinement, sensitive data, generated inputs, and downstream use.",
                )
            )
        elif name == "os.getenv":
            self.changes.append(
                _change(
                    line,
                    "environment_dependency",
                    "review",
                    "Tiltfile behavior depends on a host environment variable resolved at runtime.",
                )
            )
        elif name in {"os.putenv", "os.unsetenv"}:
            self.changes.append(
                _change(
                    line,
                    "environment_mutation",
                    "dangerous",
                    "Tiltfile mutates its process environment during evaluation.",
                )
            )
        elif leaf == "secret_settings":
            disabled = _literal(_argument(node, 0, "disable_scrub")) is True
            self.changes.append(
                _change(
                    line,
                    "secret_scrubbing",
                    "dangerous" if disabled else "review",
                    "Tilt secret output scrubbing is disabled."
                    if disabled
                    else "Tilt configures secret output scrubbing; verify sensitive-data coverage.",
                )
            )
        elif leaf in {"allow_k8s_contexts", "default_registry"}:
            self.changes.append(
                _change(
                    line,
                    "cluster_or_registry_target",
                    "review",
                    "Tilt configures an allowed Kubernetes context or default image registry; "
                    "verify the effective target and credential boundary.",
                )
            )
        elif leaf in {"run", "exec_action"}:
            self.changes.append(
                _change(
                    line,
                    "container_or_probe_command",
                    "dangerous",
                    "Tilt executes a configured command during live update or readiness probing.",
                )
            )
        elif leaf == "sync":
            self.changes.append(
                _change(
                    line,
                    "live_file_sync",
                    "dangerous",
                    "Tilt synchronizes host files into a running container; review source and "
                    "destination confinement, overwrite behavior, secrets, and workload identity.",
                )
            )
        elif leaf == "port_forward":
            host = _literal(_argument(node, 2, "host"))
            self.changes.append(
                _change(
                    line,
                    "port_forward",
                    "dangerous" if host in {"0.0.0.0", "::", "*"} else "review",
                    "Tilt forwards a workload port to the host; review bind address, local port, "
                    "authentication, and workstation/network exposure.",
                )
            )
        elif leaf in self.loaded_symbols:
            self.changes.append(
                _change(
                    line,
                    "extension_invocation",
                    "dangerous",
                    "Tilt invokes a symbol loaded from another Tiltfile or extension; effective "
                    "build/deploy/host behavior is outside this source file.",
                )
            )

        if leaf in {
            "custom_build",
            "docker_build",
            "docker_compose",
            "helm",
            "include",
            "k8s_yaml",
            "kustomize",
            "load",
            "load_dynamic",
            "local_resource",
            "read_file",
        }:
            primary = _literal(
                _argument(node, 1 if leaf in {"custom_build", "docker_build"} else 0, "context")
            )
            for path in _paths(primary):
                if _external_path(path):
                    self.changes.append(
                        _change(
                            line,
                            "external_source_path",
                            "dangerous",
                            "Tilt source or build path is remote or escapes the project boundary.",
                        )
                    )
                    break

        if leaf in {"custom_build", "docker_build"}:
            image = _literal(_argument(node, 0, "ref"))
            if isinstance(image, str):
                self.changes.append(
                    _change(
                        line,
                        "image_target",
                        "review" if _DIGEST.search(image) else "dangerous",
                        "Tilt image reference is digest-pinned."
                        if _DIGEST.search(image)
                        else "Tilt image build target uses a mutable repository or tag reference.",
                    )
                )

        critical = leaf in _TILT_CALLS | {"run", "exec_action", "k8s_custom_deploy"}
        if critical and any(_literal(argument) is None for argument in node.args):
            self.changes.append(
                _change(
                    line,
                    "dynamic_argument",
                    "review",
                    "Tilt call contains computed arguments whose effective source, command, "
                    "target, or permissions require runtime evaluation.",
                )
            )
        self.generic_visit(node)


def _fallback_changes(source: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    dangerous = {
        "custom_build",
        "docker_compose",
        "k8s_custom_deploy",
        "k8s_yaml",
        "local",
        "local_resource",
        "run",
        "sync",
    }
    for line_number, line in enumerate(source.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", line):
            name = match.group(1)
            if name in _TILT_CALLS | dangerous:
                changes.append(
                    _change(
                        line_number,
                        "dynamic_tilt_call",
                        "dangerous" if name in dangerous else "review",
                        "Tiltfile contains a recognized call in source that could not be fully "
                        "parsed; review its executable and infrastructure effects.",
                    )
                )
    return changes


def parse_tiltfile(source: str) -> dict[str, Any]:
    """Conservatively scan Tiltfile source without evaluating Starlark."""
    if not source.strip():
        raise TiltfileInputError("input is empty")
    if not _MARKER.search(source):
        raise TiltfileInputError("no Tiltfile configuration API calls were found")
    parsed = True
    try:
        tree = ast.parse(source, filename="Tiltfile")
    except SyntaxError:
        parsed = False
        changes = _fallback_changes(source)
    else:
        visitor = _TiltVisitor()
        visitor.visit(tree)
        changes = visitor.changes
    changes.append(
        _change(
            1,
            "evaluation_boundary",
            "review",
            "Static analysis does not execute Starlark, loaded Tiltfiles/extensions, host or "
            "container commands, image builds, renderers, Compose/Kubernetes deployment, live "
            "updates, probes, file reads, environment access, or cluster/registry operations.",
        )
    )
    return {"tiltfile": {"changes": changes, "parsed": parsed}}


class TiltfileAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "tilt"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        document = input_data.get("tiltfile")
        return isinstance(document, dict) and isinstance(document.get("changes"), list)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        return list(input_data["tiltfile"]["changes"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"tilt_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_tiltfile(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = TiltfileAdapter().analyze(data, tool_name="Tilt")
    summary = PlanSummary(
        path=Path("tilt://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Tilt")
    gate["adapter"] = "tilt"
    gate["syntax_mode"] = "ast" if data["tiltfile"]["parsed"] else "conservative"
    gate["total_changes"] = len(changes)
    return gate
