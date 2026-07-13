from __future__ import annotations

import csv
import json
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

import hcl2
import yaml
from hcl2.utils import SerializationOptions

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class DockerBakeInputError(ValueError):
    """Raised when input is not a recognizable Docker Buildx Bake definition."""


_SECRET_NAME = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)",
    re.IGNORECASE,
)
_EXPRESSION = re.compile(r"\$\{|\b(?:var|local)\.|\b(?:env|file|readfile)\s*\(")
_REMOTE = re.compile(r"^(?:https?|git|ssh)://|^[^/@\s]+@[^:\s]+:", re.IGNORECASE)
_COMMIT = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_SENSITIVE_PATH = re.compile(
    r"(?:^|[/\\])(?:\.ssh|\.aws|\.azure|\.config[/\\]gcloud|\.kube|"
    r"credentials?|id_(?:rsa|ed25519)|docker\.json)(?:[/\\]|$)",
    re.IGNORECASE,
)
_KNOWN_TARGET_KEYS = {
    "annotations",
    "args",
    "attest",
    "cache-from",
    "cache-to",
    "call",
    "context",
    "contexts",
    "description",
    "dockerfile",
    "dockerfile-inline",
    "entitlements",
    "extra-hosts",
    "inherits",
    "labels",
    "matrix",
    "name",
    "network",
    "no-cache",
    "no-cache-filter",
    "output",
    "outputs",
    "platforms",
    "policy",
    "pull",
    "resources",
    "secret",
    "secrets",
    "shm-size",
    "ssh",
    "tags",
    "target",
    "ulimits",
}


class _UniqueSafeLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _UniqueSafeLoader, node: yaml.MappingNode, deep: bool = False):
    explicit_keys: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in explicit_keys
        except TypeError as exc:
            raise DockerBakeInputError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise DockerBakeInputError(f"duplicate YAML key: {key}")
        explicit_keys.add(key)
    loader.flatten_mapping(node)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DockerBakeInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strip_internal(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _strip_internal(child)
            for key, child in value.items()
            if key != "__is_block__"
        }
    if isinstance(value, list):
        return [_strip_internal(child) for child in value]
    return value


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _named_blocks(document: dict[str, Any], block_name: str) -> dict[str, dict[str, Any]]:
    """Normalize python-hcl2 labeled blocks and Bake JSON objects."""
    raw = document.get(block_name)
    if raw is None:
        return {}
    items = raw if isinstance(raw, list) else [raw]
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise DockerBakeInputError(f"Docker Bake {block_name} must contain objects")
        for name, value in item.items():
            if not isinstance(value, dict):
                raise DockerBakeInputError(
                    f"Docker Bake {block_name} {name!r} must be an object"
                )
            if name in result:
                raise DockerBakeInputError(
                    f"duplicate Docker Bake {block_name} block: {name}"
                )
            result[str(name)] = value
    return result


def _compose_target(service_name: str, service: dict[str, Any]) -> dict[str, Any] | None:
    build = service.get("build")
    if build is None:
        return None
    if isinstance(build, str):
        target: dict[str, Any] = {"context": build}
    elif isinstance(build, dict):
        aliases = {
            "additional_contexts": "contexts",
            "cache_from": "cache-from",
            "cache_to": "cache-to",
            "dockerfile_inline": "dockerfile-inline",
            "extra_hosts": "extra-hosts",
            "no_cache": "no-cache",
        }
        target = {
            aliases.get(str(key), str(key)): value
            for key, value in build.items()
            if key != "x-bake"
        }
        extension = build.get("x-bake")
        if extension is not None:
            if not isinstance(extension, dict):
                raise DockerBakeInputError(
                    f"Compose service {service_name!r} build.x-bake must be an object"
                )
            target.update({str(key).replace("_", "-"): value for key, value in extension.items()})
    else:
        raise DockerBakeInputError(
            f"Compose service {service_name!r} build must be a string or object"
        )
    image = service.get("image")
    if image and not target.get("tags"):
        target["tags"] = [image]
    return target


def _compose_to_bake(document: dict[str, Any]) -> dict[str, Any]:
    services = document.get("services")
    if not isinstance(services, dict):
        raise DockerBakeInputError("Compose-backed Bake input must contain a services object")
    targets: dict[str, dict[str, Any]] = {}
    for name, service in services.items():
        if not isinstance(service, dict):
            raise DockerBakeInputError(f"Compose service {name!r} must be an object")
        target = _compose_target(str(name), service)
        if target is not None:
            targets[str(name)] = target
    if not targets:
        raise DockerBakeInputError("Compose input contains no build targets")
    return {
        "target": targets,
        "group": {"default": {"targets": list(targets)}},
        "_compose_secrets": document.get("secrets", {}),
    }


def parse_docker_bake(source: str, filename: str | None = None) -> dict[str, Any]:
    """Parse Docker Bake HCL/JSON or Compose YAML without executing Buildx."""
    if not source.strip():
        raise DockerBakeInputError("input is empty")
    name = (filename or "").lower()
    stripped = source.lstrip()
    representation = (
        "compose"
        if name.endswith((".yaml", ".yml"))
        else "json"
        if stripped.startswith("{")
        else "hcl"
    )
    try:
        if representation == "compose":
            document = yaml.load(source, Loader=_UniqueSafeLoader)
        elif representation == "json":
            document = json.loads(source, object_pairs_hook=_unique_object)
        else:
            document = hcl2.loads(
                source,
                serialization_options=SerializationOptions(
                    explicit_blocks=False,
                    strip_string_quotes=True,
                ),
            )
    except DockerBakeInputError:
        raise
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise DockerBakeInputError(f"invalid Docker Bake {representation}: {exc}") from exc
    except Exception as exc:
        raise DockerBakeInputError(f"invalid Docker Bake HCL: {exc}") from exc

    document = _strip_internal(document)
    if not isinstance(document, dict):
        raise DockerBakeInputError("Docker Bake definition must be an object")
    if representation == "compose":
        document = _compose_to_bake(document)
    elif not ({"target", "group", "variable", "function"} & set(document)):
        raise DockerBakeInputError("input is not recognized as a Docker Bake definition")

    # Validate labeled-block shape and require an executable graph.
    targets = _named_blocks(document, "target")
    groups = _named_blocks(document, "group")
    _named_blocks(document, "variable")
    _named_blocks(document, "function")
    if not targets and not groups:
        raise DockerBakeInputError("Docker Bake definition contains no targets or groups")
    return {
        "docker_bake": {
            "representation": representation,
            "document": document,
            "source_text": source,
            "filename": filename or "docker-bake.hcl",
        }
    }


def _change(
    address: str,
    kind: str,
    risk: str,
    explanation: str,
    action: str = "execute",
) -> dict[str, str]:
    return {
        "Address": address,
        "Kind": kind,
        "Risk": risk,
        "Explanation": explanation,
        "Action": action,
    }


def _is_expression(value: Any) -> bool:
    return bool(_EXPRESSION.search(str(value)))


def _path_escapes(value: str) -> bool:
    text = value.removeprefix("cwd://")
    if _is_expression(text):
        return False
    return (
        PurePosixPath(text).is_absolute()
        or PureWindowsPath(text).is_absolute()
        or text == ".."
        or text.startswith(("../", "..\\"))
    )


def _remote_is_immutable(value: str) -> bool:
    if "@sha256:" in value.lower():
        return True
    fragment = urlsplit(value).fragment if "://" in value else value.partition("#")[2]
    revision = fragment.split(":", 1)[0].split("?", 1)[0]
    return bool(_COMMIT.fullmatch(revision))


def _location_change(address: str, kind: str, value: Any) -> dict[str, str]:
    text = str(value)
    if _is_expression(text):
        return _change(
            address,
            kind,
            "review",
            "Docker Bake resolves this build location dynamically; review the effective path, "
            "source identity, and execution context.",
        )
    if text.startswith("target:"):
        return _change(
            address,
            "target_context",
            "review",
            f"Docker Bake consumes output from target {text[7:]!r} as a named build context.",
        )
    if _REMOTE.search(text) or text.startswith("docker-image://"):
        immutable = _remote_is_immutable(text)
        return _change(
            address,
            kind,
            "review" if immutable else "dangerous",
            "Docker Bake fetches an immutable remote build context; verify repository ownership "
            "and transport."
            if immutable
            else "Docker Bake fetches a remote build context without an immutable commit or "
            "digest; upstream content can change between builds.",
            "read",
        )
    if _path_escapes(text):
        return _change(
            address,
            kind,
            "dangerous",
            "Docker Bake reads a build path outside the project boundary.",
            "read",
        )
    explanation = (
        "Docker Bake reads a local Dockerfile; review its resolved path and executable "
        "instructions."
        if kind == "dockerfile"
        else "Docker Bake sends a local filesystem context to the builder; review ignored "
        "files and sensitive build-context contents."
    )
    return _change(address, kind, "review", explanation, "read")


def _csv_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {"value": value}
    try:
        fields = next(csv.reader([value]))
    except (csv.Error, StopIteration):
        fields = [value]
    result: dict[str, Any] = {}
    for index, field in enumerate(fields):
        key, separator, item = field.partition("=")
        if separator:
            result[key.strip()] = item.strip()
        elif index == 0:
            result["type"] = field.strip()
        else:
            result[f"value{index}"] = field.strip()
    return result


def _secret_changes(target_name: str, target: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    args = target.get("args")
    for key, value in args.items() if isinstance(args, dict) else []:
        if _SECRET_NAME.search(str(key)) and value not in (None, "", False):
            changes.append(
                _change(
                    f"target.{target_name}.args.{key}",
                    "secret_build_arg",
                    "review" if _is_expression(value) else "dangerous",
                    f"Docker Bake build argument {key!r} is credential-like; Build arguments "
                    "are not a safe secret channel and may persist in image metadata or cache.",
                )
            )
    secrets = _as_list(target.get("secret")) + _as_list(target.get("secrets"))
    for index, raw in enumerate(secrets):
        item = _csv_object(raw)
        secret_id = str(item.get("id") or item.get("source") or f"secret-{index}")
        source = str(item.get("src") or item.get("source") or "")
        sensitive_path = bool(_SENSITIVE_PATH.search(source))
        changes.append(
            _change(
                f"target.{target_name}.secret[{index}]",
                "secret_mount",
                "dangerous" if sensitive_path else "review",
                f"Docker Bake exposes secret input {secret_id!r} to build steps; verify least "
                "privilege, required mounts, cache behavior, and log handling.",
            )
        )
    for index, raw in enumerate(_as_list(target.get("ssh"))):
        item = _csv_object(raw)
        ssh_id = str(item.get("id") or "default")
        changes.append(
            _change(
                f"target.{target_name}.ssh[{index}]",
                "ssh_forwarding",
                "dangerous",
                f"Docker Bake forwards SSH identity {ssh_id!r} into build steps; a malicious "
                "Dockerfile can use the agent or key while the mount is active.",
            )
        )
    return changes


def _cache_changes(target_name: str, target: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for direction, action in (("cache-from", "read"), ("cache-to", "write")):
        for index, raw in enumerate(_as_list(target.get(direction))):
            item = _csv_object(raw)
            cache_type = str(item.get("type") or "registry")
            location = str(item.get("ref") or item.get("dest") or item.get("bucket") or "")
            remote = cache_type in {"registry", "s3", "azblob", "gha"}
            risk = "dangerous" if remote or (location and _path_escapes(location)) else "review"
            verb = (
                "imports executable build cache from"
                if direction == "cache-from"
                else "exports build cache to"
            )
            changes.append(
                _change(
                    f"target.{target_name}.{direction}[{index}]",
                    direction.replace("-", "_"),
                    risk,
                    f"Docker Bake {verb} a {cache_type!r} backend; verify trust, credentials, "
                    "cache poisoning, and sensitive-layer exposure.",
                    action,
                )
            )
    return changes


def _output_changes(target_name: str, target: dict[str, Any]) -> list[dict[str, str]]:
    outputs = _as_list(target.get("output")) + _as_list(target.get("outputs"))
    changes: list[dict[str, str]] = []
    for index, raw in enumerate(outputs):
        item = _csv_object(raw)
        output_type = str(item.get("type") or "local")
        destination = str(item.get("dest") or item.get("name") or "")
        mode = str(item.get("mode") or "")
        push = item.get("push") in (True, "true", "1")
        if mode == "delete" and output_type == "local":
            risk = "irreversible"
            explanation = (
                "Docker Bake local output uses mode=delete and can remove existing destination "
                "contents when the required filesystem entitlement is granted."
            )
        elif output_type == "registry" or (output_type == "image" and push):
            risk = "dangerous"
            explanation = (
                "Docker Bake publishes the built image to a registry; verify destination, "
                "credentials, signing, provenance, and tag mutability."
            )
        elif destination and _path_escapes(destination):
            risk = "dangerous"
            explanation = "Docker Bake writes build output outside the project boundary."
        elif output_type == "cacheonly":
            risk = "safe"
            explanation = "Docker Bake retains only build cache and does not export an image."
        else:
            risk = "review"
            explanation = (
                f"Docker Bake exports a {output_type!r} build artifact; review destination, "
                "overwrite behavior, ownership, and downstream trust."
            )
        changes.append(
            _change(
                f"target.{target_name}.output[{index}]",
                "output",
                risk,
                explanation,
                "write",
            )
        )
    return changes


def _attestation_changes(target_name: str, target: dict[str, Any]) -> list[dict[str, str]]:
    attestations = _as_list(target.get("attest"))
    if not attestations:
        return [
            _change(
                f"target.{target_name}.attest",
                "attestation_gap",
                "review",
                "Docker Bake target does not declare provenance or SBOM attestations; verify "
                "that the invocation or builder policy supplies required attestations.",
            )
        ]
    changes: list[dict[str, str]] = []
    for index, raw in enumerate(attestations):
        item = _csv_object(raw)
        kind = str(item.get("type") or "unknown")
        disabled = item.get("disabled") in (True, "true", "1")
        changes.append(
            _change(
                f"target.{target_name}.attest[{index}]",
                "attestation",
                "dangerous" if disabled else "safe",
                f"Docker Bake disables {kind!r} attestation generation."
                if disabled
                else f"Docker Bake requests {kind!r} build attestation metadata.",
            )
        )
    return changes


def _target_changes(name: str, target: dict[str, Any], targets: set[str]) -> list[dict[str, str]]:
    address = f"target.{name}"
    changes: list[dict[str, str]] = []
    context = target.get("context", ".")
    changes.append(_location_change(f"{address}.context", "context", context))
    contexts = target.get("contexts")
    if contexts is not None and not isinstance(contexts, dict):
        changes.append(
            _change(
                f"{address}.contexts",
                "invalid_contexts",
                "dangerous",
                "Docker Bake named contexts must be a map.",
            )
        )
    elif isinstance(contexts, dict):
        for context_name, value in contexts.items():
            changes.append(
                _location_change(f"{address}.contexts.{context_name}", "named_context", value)
            )
            text = str(value)
            if text.startswith("target:") and text[7:] not in targets:
                changes.append(
                    _change(
                        f"{address}.contexts.{context_name}",
                        "missing_target_context",
                        "dangerous",
                        f"Docker Bake named context references unknown target {text[7:]!r}.",
                    )
                )

    dockerfile = target.get("dockerfile")
    inline = target.get("dockerfile-inline")
    if dockerfile is not None:
        changes.append(_location_change(f"{address}.dockerfile", "dockerfile", dockerfile))
    if inline is not None:
        changes.append(
            _change(
                f"{address}.dockerfile-inline",
                "inline_dockerfile",
                "dangerous",
                "Docker Bake embeds executable Dockerfile instructions directly in the build "
                "definition; review commands, downloads, identities, and secret handling.",
            )
        )

    for entitlement in _as_list(target.get("entitlements")):
        name_value = str(entitlement)
        dangerous = name_value in {"network.host", "security.insecure"}
        changes.append(
            _change(
                f"{address}.entitlements.{name_value}",
                "entitlement",
                "dangerous" if dangerous else "review",
                f"Docker Bake target requests {name_value!r} build entitlement; invocation-time "
                "approval can grant host networking, insecure execution, or filesystem access.",
            )
        )

    network = target.get("network")
    if network is not None:
        network_value = str(network)
        network_risk = (
            "safe"
            if network_value == "none"
            else "dangerous"
            if network_value == "host"
            else "review"
        )
        changes.append(
            _change(
                f"{address}.network",
                "network",
                network_risk,
                "Docker Bake disables build-step network access."
                if network_value == "none"
                else f"Docker Bake build steps use network mode {network_value!r}; review egress, "
                "host reachability, and dependency integrity.",
            )
        )
    if target.get("extra-hosts"):
        changes.append(
            _change(
                f"{address}.extra-hosts",
                "host_mapping",
                "dangerous",
                "Docker Bake overrides hostname resolution inside build steps; verify traffic "
                "cannot be redirected to an untrusted or host-local endpoint.",
            )
        )

    policies = _as_list(target.get("policy"))
    for index, raw in enumerate(policies):
        item = _csv_object(raw)
        weakened = item.get("disabled") in (True, "true", "1") or item.get("strict") in (
            False,
            "false",
            "0",
        )
        changes.append(
            _change(
                f"{address}.policy[{index}]",
                "source_policy",
                "dangerous" if weakened else "review",
                "Docker Bake disables or weakens source policy enforcement."
                if weakened
                else "Docker Bake loads a source policy file; review its resolved rules and "
                "enforcement mode.",
            )
        )

    inherits = [str(item) for item in _as_list(target.get("inherits"))]
    for parent in inherits:
        changes.append(
            _change(
                f"{address}.inherits.{parent}",
                "inheritance",
                "dangerous" if parent not in targets else "review",
                f"Docker Bake target inherits unknown target {parent!r}."
                if parent not in targets
                else f"Docker Bake target inherits configuration from {parent!r}; review the "
                "effective merged target.",
            )
        )

    matrix = target.get("matrix")
    if matrix is not None:
        valid = isinstance(matrix, dict) and all(
            isinstance(values, list) and values for values in matrix.values()
        )
        combinations = 1
        if valid:
            for values in matrix.values():
                combinations *= len(values)
        changes.append(
            _change(
                f"{address}.matrix",
                "matrix",
                "review" if valid and combinations <= 64 else "dangerous",
                f"Docker Bake matrix expands this definition into {combinations} build target(s); "
                "review every generated name, platform, destination, and credential boundary."
                if valid
                else "Docker Bake matrix is empty or malformed and cannot produce a reliable "
                "static target graph.",
            )
        )

    tags = [str(item) for item in _as_list(target.get("tags"))]
    for index, tag in enumerate(tags):
        mutable = tag.endswith(":latest") or ":" not in tag.rsplit("/", 1)[-1]
        changes.append(
            _change(
                f"{address}.tags[{index}]",
                "image_tag",
                "dangerous" if mutable else "review",
                "Docker Bake assigns a mutable or implicit-latest image tag; publication can "
                "silently replace the artifact selected by downstream deployments."
                if mutable
                else "Docker Bake assigns a named image tag; verify registry ownership and "
                "promotion/signing policy.",
                "write",
            )
        )

    unknown = sorted(set(target) - _KNOWN_TARGET_KEYS)
    if unknown:
        changes.append(
            _change(
                f"{address}.unknown",
                "unknown_attributes",
                "review",
                "Docker Bake target contains attributes outside the recognized static schema: "
                + ", ".join(unknown),
            )
        )
    changes.extend(_secret_changes(name, target))
    changes.extend(_cache_changes(name, target))
    changes.extend(_output_changes(name, target))
    changes.extend(_attestation_changes(name, target))
    return changes


def _graph_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    targets = _named_blocks(document, "target")
    groups = _named_blocks(document, "group")
    changes: list[dict[str, str]] = []
    target_names = set(targets)
    for group_name, group in groups.items():
        selected = [str(item) for item in _as_list(group.get("targets"))]
        if not selected:
            changes.append(
                _change(
                    f"group.{group_name}",
                    "empty_group",
                    "dangerous",
                    "Docker Bake group contains no targets.",
                )
            )
        for target_name in selected:
            changes.append(
                _change(
                    f"group.{group_name}.targets.{target_name}",
                    "group_target",
                    "dangerous" if target_name not in target_names else "review",
                    f"Docker Bake group references unknown target {target_name!r}."
                    if target_name not in target_names
                    else f"Docker Bake group {group_name!r} selects target {target_name!r} for "
                    "execution.",
                )
            )

    # Detect inheritance cycles without attempting dynamic HCL evaluation.
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str, trail: list[str]) -> None:
        if name in visiting:
            cycle = " -> ".join([*trail, name])
            changes.append(
                _change(
                    f"target.{name}.inherits",
                    "inheritance_cycle",
                    "dangerous",
                    f"Docker Bake target inheritance contains a cycle: {cycle}.",
                )
            )
            return
        if name in visited or name not in targets:
            return
        visiting.add(name)
        for parent in _as_list(targets[name].get("inherits")):
            visit(str(parent), [*trail, name])
        visiting.remove(name)
        visited.add(name)

    for target_name in targets:
        visit(target_name, [])
    for target_name, target in targets.items():
        changes.extend(_target_changes(target_name, target, target_names))
    return changes


def docker_bake_changes(payload: dict[str, Any]) -> list[dict[str, str]]:
    document = payload["document"]
    changes = _graph_changes(document)
    variables = _named_blocks(document, "variable")
    for name, variable in variables.items():
        default = variable.get("default")
        if _SECRET_NAME.search(name) and default not in (None, "", False):
            changes.append(
                _change(
                    f"variable.{name}.default",
                    "secret_variable",
                    "review" if _is_expression(default) else "dangerous",
                    f"Docker Bake variable {name!r} has a credential-like default; use a "
                    "secret mount and avoid persisting the value in definitions or metadata.",
                )
            )
    if variables:
        changes.append(
            _change(
                "bake.environment_variables",
                "environment_override_boundary",
                "review",
                "Docker Bake variables can be overridden by same-named process environment "
                "variables unless environment lookup is disabled; effective values were not read.",
            )
        )
    functions = _named_blocks(document, "function")
    for name in functions:
        changes.append(
            _change(
                f"function.{name}",
                "custom_function",
                "review",
                f"Docker Bake evaluates custom HCL function {name!r}; review its effective "
                "inputs and generated build configuration.",
            )
        )
    changes.append(
        _change(
            "bake.effective_definition",
            "evaluation_boundary",
            "review",
            "Static analysis does not invoke Docker/Buildx, merge adjacent or remote Bake files, "
            "read .env or secret files, expand variables/functions, fetch contexts/cache, inspect "
            "Dockerfiles, evaluate source policies, contact builders, or publish artifacts.",
        )
    )
    return changes


class DockerBakeAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "docker-bake"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("docker_bake")
        return isinstance(payload, dict) and isinstance(payload.get("document"), dict)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        return docker_bake_changes(input_data["docker_bake"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        kind = str(raw.get("Kind") or "unknown")
        return ResourceChange(
            address=str(raw.get("Address") or "docker-bake"),
            resource_type=f"docker_bake_{kind}",
            actions=(str(raw.get("Action") or "execute"),),
            risk=str(raw.get("Risk") or "review"),
            explanation=str(raw.get("Explanation") or "Docker Bake change requires review."),
        )


def analyze_docker_bake(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = DockerBakeAdapter().analyze(data, tool_name="Docker Buildx Bake")
    summary = PlanSummary(
        path=Path("docker-bake://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Docker Buildx Bake")
    gate["adapter"] = "docker-bake"
    gate["artifact_type"] = data["docker_bake"].get("representation", "unknown")
    gate["total_changes"] = len(changes)
    return gate
