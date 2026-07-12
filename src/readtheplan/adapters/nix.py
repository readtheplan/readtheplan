from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class NixInputError(ValueError):
    """Raised when input is not recognizable Nix project data."""


_SOURCE_MARKER = re.compile(
    r"\b(?:inputs|outputs|nixConfig|imports|services|networking|users|security|systemd|"
    r"environment|boot|virtualisation|fileSystems|nix\.settings)\b\s*(?:\.|=)"
)
_COMMIT = re.compile(r"[0-9a-f]{40,64}$", re.IGNORECASE)
_REMOTE_TYPES = {"file", "git", "github", "gitlab", "hg", "sourcehut", "tarball"}
_SECRET_NAME = re.compile(
    r"(?:password|passwd|passphrase|token|secret|private.?key|access.?key|credential)",
    re.IGNORECASE,
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NixInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _strip_comments(source: str) -> str:
    """Replace Nix comments with spaces while retaining line/column offsets."""
    output = list(source)
    index = 0
    state = "code"
    block_depth = 0
    while index < len(source):
        if state == "code":
            if source.startswith("/*", index):
                output[index : index + 2] = "  "
                block_depth = 1
                state = "block"
                index += 2
                continue
            if source[index] == "#":
                output[index] = " "
                state = "line"
            elif source[index] == '"':
                state = "double"
            elif source.startswith("''", index):
                state = "indented"
                index += 1
        elif state == "line":
            if source[index] == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block":
            if source.startswith("/*", index):
                output[index : index + 2] = "  "
                block_depth += 1
                index += 2
                continue
            if source.startswith("*/", index):
                output[index : index + 2] = "  "
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
                continue
            if source[index] != "\n":
                output[index] = " "
        elif state == "double":
            if source[index] == "\\":
                index += 2
                continue
            if source[index] == '"':
                state = "code"
        elif state == "indented" and source.startswith("''", index):
            state = "code"
            index += 2
            continue
        index += 1
    if state == "block":
        raise NixInputError("unterminated block comment")
    if state == "double":
        raise NixInputError("unterminated quoted string")
    return "".join(output)


def _parse_lock(source: str) -> dict[str, Any] | None:
    if not source.lstrip().startswith("{"):
        return None
    try:
        document = json.loads(source, object_pairs_hook=_unique_object)
    except NixInputError:
        raise
    except json.JSONDecodeError as exc:
        json_object_shape = source.lstrip()[1:].lstrip().startswith('"')
        if json_object_shape and any(
            marker in source for marker in ('"nodes"', '"root"', '"version"')
        ):
            raise NixInputError(f"invalid flake.lock JSON: {exc}") from exc
        return None
    if not isinstance(document, dict) or not {"nodes", "root", "version"} <= set(document):
        return None
    if not isinstance(document["version"], int) or document["version"] < 1:
        raise NixInputError("flake.lock version must be a positive integer")
    if not isinstance(document["root"], str) or not document["root"]:
        raise NixInputError("flake.lock root must be a non-empty node name")
    nodes = document["nodes"]
    if not isinstance(nodes, dict) or not nodes:
        raise NixInputError("flake.lock nodes must be a non-empty object")
    if document["root"] not in nodes:
        raise NixInputError("flake.lock root does not reference an existing node")
    for name, node in nodes.items():
        if not isinstance(node, dict):
            raise NixInputError(f"flake.lock node {name!r} must be an object")
        if "inputs" in node and not isinstance(node["inputs"], dict):
            raise NixInputError(f"flake.lock node {name!r} inputs must be an object")
        for key in ("locked", "original"):
            if key in node and not isinstance(node[key], dict):
                raise NixInputError(f"flake.lock node {name!r} {key} must be an object")
    return document


def parse_nix_project(source: str) -> dict[str, Any]:
    """Parse flake.lock or conservatively scan flake/NixOS module source."""
    if not source.strip():
        raise NixInputError("input is empty")
    lock = _parse_lock(source)
    if lock is not None:
        return {"nix_project": {"artifact_type": "lock", "document": lock}}
    clean = _strip_comments(source)
    if not _SOURCE_MARKER.search(clean) or ";" not in clean:
        raise NixInputError("input is not recognized as flake.nix or a NixOS module")
    flake = bool(re.search(r"\boutputs\s*=|\binputs(?:\.|\s*=)|\bnixConfig\s*=", clean))
    return {
        "nix_project": {
            "artifact_type": "flake" if flake else "module",
            "document": {"source": source, "clean": clean},
        }
    }


def _embedded_credential(value: str) -> bool:
    candidate = value.removeprefix("git+")
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _urls(value: Any) -> list[str]:
    result: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in {"url", "uri"} and isinstance(item, str):
                result.append(item)
            result.extend(_urls(item))
    elif isinstance(value, list):
        for item in value:
            result.extend(_urls(item))
    return result


def _input_refs(node: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for value in node.get("inputs", {}).values():
        if isinstance(value, str):
            refs.append(value)
    return refs


def _lock_cycles(nodes: dict[str, Any]) -> list[list[str]]:
    cycles: list[list[str]] = []
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            start = visiting.index(name)
            cycles.append([*visiting[start:], name])
            return
        if name in visited or name not in nodes:
            return
        visiting.append(name)
        for ref in _input_refs(nodes[name]):
            visit(ref)
        visiting.pop()
        visited.add(name)

    for name in nodes:
        visit(name)
    return cycles


def _lock_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    nodes = document["nodes"]
    root = document["root"]
    for name, node in nodes.items():
        for input_name, ref in node.get("inputs", {}).items():
            if isinstance(ref, str) and ref not in nodes:
                changes.append(
                    _change(
                        f"lock.nodes.{name}.inputs.{input_name}",
                        "missing_input_node",
                        "dangerous",
                        f"flake.lock input references missing node {ref!r}; dependency resolution "
                        "is incomplete or corrupted.",
                    )
                )
            elif isinstance(ref, list):
                if not ref or not all(isinstance(part, str) and part for part in ref):
                    changes.append(
                        _change(
                            f"lock.nodes.{name}.inputs.{input_name}",
                            "invalid_follows_path",
                            "dangerous",
                            "flake.lock contains an empty or malformed follows path.",
                        )
                    )
                else:
                    changes.append(
                        _change(
                            f"lock.nodes.{name}.inputs.{input_name}",
                            "follows_input",
                            "review",
                            f"flake.lock input follows dependency path {'/'.join(ref)!r}; review "
                            "the resolved upstream ownership boundary.",
                        )
                    )
            elif not isinstance(ref, str):
                changes.append(
                    _change(
                        f"lock.nodes.{name}.inputs.{input_name}",
                        "invalid_input_reference",
                        "dangerous",
                        "flake.lock input reference must be a node name or follows path.",
                    )
                )
        if name == root:
            continue
        locked = node.get("locked")
        original = node.get("original", {})
        if not isinstance(locked, dict) or not locked:
            changes.append(
                _change(
                    f"lock.nodes.{name}.locked",
                    "unlocked_input",
                    "dangerous",
                    "flake.lock dependency has no locked identity and may resolve differently "
                    "between evaluations.",
                )
            )
            continue
        input_type = str(locked.get("type") or original.get("type") or "unknown")
        reasons: list[str] = []
        risk = "review"
        if input_type in _REMOTE_TYPES and not locked.get("narHash"):
            risk = "dangerous"
            reasons.append("has no narHash content identity")
        if input_type in {"git", "github", "gitlab", "hg", "sourcehut"} and not _COMMIT.fullmatch(
            str(locked.get("rev", ""))
        ):
            risk = "dangerous"
            reasons.append("is not pinned to a full revision")
        if any(key in locked for key in ("dirtyRev", "dirtyShortRev")):
            risk = "dangerous"
            reasons.append("records a dirty working tree")
        if input_type == "path":
            reasons.append("depends on a local filesystem path")
        for url in _urls({"locked": locked, "original": original}):
            if url.lower().startswith(("http://", "git://")):
                risk = "dangerous"
                reasons.append("uses a plaintext or unauthenticated transport")
            if _embedded_credential(url):
                risk = "dangerous"
                reasons.append("embeds credentials in a URL")
        changes.append(
            _change(
                f"lock.nodes.{name}",
                "locked_input",
                risk,
                f"Nix flake input {name!r} resolves as type {input_type!r}; "
                + ", ".join(reasons or ["verify upstream ownership and update review"])
                + ".",
            )
        )
    for index, cycle in enumerate(_lock_cycles(nodes), start=1):
        changes.append(
            _change(
                f"lock.graph.cycle[{index}]",
                "input_cycle",
                "dangerous",
                "flake.lock contains a direct input cycle: " + " -> ".join(cycle) + ".",
            )
        )
    changes.append(
        _change(
            "lock.effective_graph",
            "lock_boundary",
            "review",
            f"flake.lock schema version {document['version']} pins the serialized input graph, "
            "but build outputs, signatures, substituter policy, and source evaluation remain "
            "outside the lock file.",
        )
    )
    return changes


def _line(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1


def _matching_brace(source: str, opening: int) -> int | None:
    depth = 0
    quoted = False
    escaped = False
    for index in range(opening, len(source)):
        char = source[index]
        if escaped:
            escaped = False
            continue
        if quoted and char == "\\":
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            continue
        if quoted:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _first_change(
    source: str,
    pattern: str,
    kind: str,
    risk: str,
    explanation: str,
    *,
    flags: int = re.IGNORECASE,
) -> dict[str, str] | None:
    match = re.search(pattern, source, flags)
    if match is None:
        return None
    return _change(f"source.line.{_line(source, match.start())}", kind, risk, explanation)


def _source_inputs(source: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    pattern = re.compile(
        r"\binputs\.([A-Za-z_][A-Za-z0-9_-]*)\.url\s*=\s*\"([^\"\n]+)\"",
        re.IGNORECASE,
    )
    matches: list[tuple[int, str, str]] = [
        (match.start(), match.group(1), match.group(2)) for match in pattern.finditer(source)
    ]
    block = re.search(r"\binputs\s*=\s*\{", source)
    if block is not None:
        opening = source.find("{", block.start())
        closing = _matching_brace(source, opening)
        if closing is not None:
            block_source = source[opening + 1 : closing]
            nested = re.compile(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_-]*)\.url\s*=\s*\"([^\"\n]+)\"")
            matches.extend(
                (opening + 1 + match.start(), match.group(1), match.group(2))
                for match in nested.finditer(block_source)
            )
    seen: set[tuple[str, str]] = set()
    for position, name, url in sorted(matches):
        if (name, url) in seen:
            continue
        seen.add((name, url))
        risk = "review"
        reasons = ["confirm that flake.lock pins its content and revision"]
        if url.lower().startswith(("http://", "git://")):
            risk = "dangerous"
            reasons.append("the input uses a plaintext or unauthenticated transport")
        if _embedded_credential(url):
            risk = "dangerous"
            reasons.append("the input URL embeds credentials")
        changes.append(
            _change(
                f"source.line.{_line(source, position)}.input.{name}",
                "flake_input",
                risk,
                f"Nix flake declares input {name!r} from {url!r}; " + "; ".join(reasons) + ".",
            )
        )
    follows = list(
        re.finditer(
            r"\binputs\.[A-Za-z_][A-Za-z0-9_-]*\.inputs\.[A-Za-z_][A-Za-z0-9_-]*\.follows\s*=",
            source,
        )
    )
    if follows:
        changes.append(
            _change(
                f"source.line.{_line(source, follows[0].start())}",
                "input_follows",
                "review",
                f"Nix flake contains {len(follows)} follows override(s); review which upstream "
                "dependency graph supplies each transitive input.",
            )
        )
    return changes


def _fetch_changes(source: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    fetcher = re.compile(
        r"\b(?:builtins\.)?(fetchGit|fetchTarball|fetchTree|fetchurl|getFlake)\b",
        re.IGNORECASE,
    )
    for match in fetcher.finditer(source):
        snippet = source[match.start() : match.start() + 1000]
        terminator = snippet.find(";")
        if terminator >= 0:
            snippet = snippet[: terminator + 1]
        has_hash = bool(re.search(r"\b(?:hash|sha256|narHash)\s*=", snippet))
        has_rev = bool(re.search(r"\brev\s*=\s*\"[0-9a-f]{40,64}\"", snippet, re.IGNORECASE))
        name = match.group(1)
        immutable = has_hash and (name.lower() not in {"fetchgit", "getflake"} or has_rev)
        changes.append(
            _change(
                f"source.line.{_line(source, match.start())}.{name}",
                "source_fetch",
                "review" if immutable else "dangerous",
                f"Nix evaluates {name} to obtain external source content. "
                + (
                    "The call includes content/revision identity; verify ownership and update "
                    "review."
                    if immutable
                    else (
                        "The scanned call is not pinned with sufficient content hash and full "
                        "revision identity."
                    )
                ),
            )
        )
    return changes


def _literal_secret_changes(source: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    assignment = re.compile(r"(?im)^\s*([A-Za-z0-9_.\"-]+)\s*=\s*(\"[^\"\n]*\"|[^;\n]+)\s*;")
    for match in assignment.finditer(source):
        name, value = match.groups()
        if not _SECRET_NAME.search(name):
            continue
        lowered_name = name.lower()
        value = value.strip()
        if value in {"null", "false", '""'}:
            continue
        reference = (
            lowered_name.endswith(("file", "path"))
            or "sops.secrets" in lowered_name
            or "age.secrets" in lowered_name
        )
        changes.append(
            _change(
                f"source.line.{_line(source, match.start())}.{name}",
                "secret_reference" if reference else "literal_secret",
                "review" if reference else "dangerous",
                "NixOS configuration references secret material from a managed file/backend; "
                "verify permissions, deployment identity, and decryption boundary."
                if reference
                else "Nix source assigns credential-like material directly; values may enter "
                "source control, evaluation traces, or the world-readable Nix store.",
            )
        )
    return changes


def _source_changes(document: dict[str, Any], artifact_type: str) -> list[dict[str, str]]:
    source = str(document["clean"])
    changes: list[dict[str, str]] = []
    if artifact_type == "flake":
        changes.extend(_source_inputs(source))
    changes.extend(_fetch_changes(source))

    rules = (
        (
            r"\b(?:nixConfig\.|nix\.settings\.)(?:trusted-users|trustedUsers)\s*=\s*\[[^\]]*\*",
            "wildcard_trusted_users",
            "dangerous",
            "Nix grants every local user trusted daemon rights, including the ability to add "
            "substituters or import unsigned store paths.",
        ),
        (
            r"\b(?:nixConfig\.|nix\.settings\.)sandbox\s*=\s*false\b",
            "sandbox_disabled",
            "dangerous",
            "Nix build sandboxing is disabled, allowing builders broader host filesystem and "
            "process access.",
        ),
        (
            r"\b(?:nixConfig\.|nix\.settings\.)(?:require-sigs|requireSigs)\s*=\s*false\b",
            "signature_verification_disabled",
            "dangerous",
            "Nix accepts unsigned store paths by disabling signature requirements.",
        ),
        (
            r"\b(?:nixConfig\.|nix\.settings\.)(?:allow-import-from-derivation|allowImportFromDerivation)\s*=\s*true\b",
            "import_from_derivation",
            "dangerous",
            "Nix permits evaluation to realise and read derivation outputs, adding an execution "
            "boundary before the build plan is complete.",
        ),
        (
            r"\b(?:nixConfig\.|nix\.settings\.)(?:substituters|extra-substituters|extraSubstituters)\s*=",
            "binary_substituters",
            "review",
            "Nix configures binary cache substituters; verify HTTPS transport, signing keys, "
            "cache ownership, priority, and fallback behavior.",
        ),
        (
            r"\b(?:nixConfig\.|nix\.settings\.)(?:substituters|extra-substituters|extraSubstituters)\s*=\s*\[[^\]]{0,1000}\"http://",
            "plaintext_substituter",
            "dangerous",
            "Nix downloads binary store paths from a plaintext HTTP substituter, allowing "
            "network interception even when signatures are configured.",
        ),
        (
            r"\b(?:nixConfig\.|nix\.settings\.)(?:trusted-public-keys|trustedPublicKeys)\s*=",
            "trusted_cache_keys",
            "review",
            "Nix trusts additional binary-cache signing keys; verify key ownership and rotation.",
        ),
        (
            r"\bnix\.settings\.accept-flake-config\s*=\s*true\b",
            "accept_flake_config",
            "dangerous",
            "Nix automatically accepts repository-provided flake configuration, including cache "
            "and trust-related settings.",
        ),
        (
            r"\bnetworking\.firewall\.enable\s*=\s*false\b",
            "firewall_disabled",
            "dangerous",
            "NixOS disables the host firewall.",
        ),
        (
            r"\bservices\.openssh\.settings\.PermitRootLogin\s*=\s*(?:\"yes\"|true)(?=\s*;)",
            "ssh_root_login",
            "dangerous",
            "NixOS OpenSSH permits direct root login.",
        ),
        (
            r"\bservices\.openssh\.settings\.PasswordAuthentication\s*=\s*true\b",
            "ssh_password_authentication",
            "dangerous",
            "NixOS OpenSSH permits password authentication; review brute-force controls and "
            "credential policy.",
        ),
        (
            r"\bservices\.openssh\.settings\.(?:PermitEmptyPasswords|KbdInteractiveAuthentication)\s*=\s*true\b",
            "weak_ssh_authentication",
            "dangerous",
            "NixOS OpenSSH enables empty-password or keyboard-interactive authentication; "
            "review credential and multi-factor enforcement.",
        ),
        (
            r"\bsecurity\.pam\.services\.[A-Za-z0-9_.\"-]+\.allowNullPassword\s*=\s*true\b",
            "null_pam_password",
            "dangerous",
            "NixOS PAM service permits null passwords.",
        ),
        (
            r"\bsecurity\.sudo\.wheelNeedsPassword\s*=\s*false\b",
            "passwordless_wheel_sudo",
            "dangerous",
            "NixOS allows wheel members to use sudo without a password challenge.",
        ),
        (
            r"\busers\.users\.root\.(?:password|initialPassword|hashedPassword)\s*=",
            "root_password",
            "dangerous",
            "NixOS configures root password material directly in the module source/evaluation.",
        ),
        (
            r"\b(?:system\.activationScripts|systemd\.services\.[A-Za-z0-9_.\"-]+\.(?:script|preStart|postStart)|serviceConfig\.ExecStart)\s*=",
            "host_script_execution",
            "dangerous",
            "NixOS installs executable activation or systemd service code that runs on the host.",
        ),
        (
            r"\bboot\.kernelParams\s*=",
            "kernel_parameters",
            "dangerous",
            "NixOS changes kernel boot parameters, affecting host security, isolation, and "
            "recoverability.",
        ),
        (
            r"\bboot\.kernel\.sysctl\s*=|\bboot\.kernel\.sysctl\.",
            "kernel_sysctl",
            "review",
            "NixOS changes persistent kernel sysctl policy; review networking, memory, "
            "namespace, and hardening effects.",
        ),
        (
            r"\b(?:__noChroot|noChroot)\s*=\s*true\b",
            "unsandboxed_derivation",
            "dangerous",
            "Nix derivation explicitly requests execution outside the normal build sandbox.",
        ),
        (
            r"\b(?:builtins\.)?(?:getEnv|currentTime|currentSystem|readFile|readDir|pathExists)\b",
            "impure_evaluation",
            "review",
            "Nix evaluation reads ambient time, platform, environment, or filesystem state; "
            "effective output may differ across evaluators.",
        ),
        (
            r"\b(?:pkgs\.)?(?:runCommand|writeShellScript|writeShellApplication|mkDerivation)\b",
            "build_code",
            "review",
            "Nix expression defines build or shell code; review the rendered derivation, sandbox "
            "settings, network access, and produced store paths.",
        ),
        (
            r"\bnixpkgs\.overlays(?:\.|\s*=)|\boverlays(?:\.|\s*=)",
            "package_overlay",
            "review",
            "Nix overlays can replace or modify packages across the evaluated package set.",
        ),
        (
            r"\bimports\s*=",
            "module_imports",
            "review",
            "NixOS imports additional modules whose merged options are not expanded in this file.",
        ),
        (
            r"\b(?:networking\.firewall\.allowed(?:TCP|UDP)Ports|openFirewall)\s*=",
            "network_exposure",
            "review",
            "NixOS opens host firewall ports or delegates firewall opening to a service module.",
        ),
        (
            r"\b(?:fileSystems|networking\.interfaces|networking\.bridges)\s*(?:\.|=)",
            "host_storage_network",
            "review",
            "NixOS changes host filesystem or network-interface topology.",
        ),
        (
            r"\b(?:virtualisation\.(?:docker|podman|libvirtd|containers|oci-containers)|containers)\s*(?:\.|=)",
            "virtualization",
            "review",
            "NixOS enables or configures container/virtualization control-plane behavior.",
        ),
        (
            r"\b(?:extraOptions|dockerFlags)\s*=\s*\[[^\]]{0,1000}(?:--privileged|--network=host|--pid=host)",
            "privileged_container",
            "dangerous",
            "NixOS container options grant privileged or host namespace access.",
        ),
        (
            r"\bnix\.buildMachines\s*=",
            "remote_builders",
            "review",
            "Nix delegates builds to remote machines; verify SSH identity, system features, "
            "substituter trust, and builder isolation.",
        ),
        (
            r"\bsshUser\s*=\s*\"root\"(?=\s*;)",
            "root_remote_builder",
            "dangerous",
            "Nix remote build configuration connects to a builder as root.",
        ),
    )
    for pattern, kind, risk, explanation in rules:
        finding = _first_change(source, pattern, kind, risk, explanation)
        if finding is not None:
            changes.append(finding)

    service_pattern = re.compile(r"\bservices\.([A-Za-z0-9_-]+)\.enable\s*=\s*true\b")
    seen_services: set[str] = set()
    for match in service_pattern.finditer(source):
        service = match.group(1)
        if service in seen_services:
            continue
        seen_services.add(service)
        changes.append(
            _change(
                f"source.line.{_line(source, match.start())}.service.{service}",
                "enabled_service",
                "review",
                f"NixOS enables service {service!r}; review listen addresses, identity, "
                "credentials, persistence, and firewall behavior.",
            )
        )
    changes.extend(_literal_secret_changes(source))
    changes.append(
        _change(
            "nix.effective_evaluation",
            "evaluation_boundary",
            "review",
            "Effective Nix behavior depends on lazy evaluation, functions, overlays, imported "
            "modules, option merging, flake.lock, package definitions, platform, daemon config, "
            "and command-line overrides. Run nix flake check/eval or nixos-rebuild build in the "
            "existing trust boundary before deployment.",
        )
    )
    return changes


class NixProjectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "nix"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        project = input_data.get("nix_project")
        return (
            isinstance(project, dict)
            and project.get("artifact_type") in {"flake", "lock", "module"}
            and isinstance(project.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        project = input_data["nix_project"]
        if project["artifact_type"] == "lock":
            return _lock_changes(project["document"])
        return _source_changes(project["document"], project["artifact_type"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"nix_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_nix_project(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = NixProjectAdapter().analyze(data, tool_name="Nix/NixOS")
    summary = PlanSummary(
        path=Path("nix://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Nix/NixOS")
    gate["adapter"] = "nix"
    gate["artifact_type"] = data["nix_project"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
