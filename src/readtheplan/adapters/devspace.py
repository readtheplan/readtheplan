from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class DevSpaceInputError(ValueError):
    """Raised when input is not strict recognizable DevSpace configuration."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise DevSpaceInputError("DevSpace YAML mapping keys must be scalar") from exc
        if duplicate:
            raise DevSpaceInputError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)

_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)", re.I
)
_REMOTE = re.compile(r"^(?:https?|git|ssh|oci)://|^[^/@\s]+@[^:\s]+:", re.I)
_SHELL = re.compile(
    r"(?:^|[\s;&|`$()])(?:sudo|sh|bash|zsh|pwsh|powershell|cmd|curl|wget|kubectl|helm|docker|git)\b",
    re.I,
)


def parse_devspace(source: str) -> dict[str, Any]:
    """Parse one DevSpace YAML/JSON config without resolving or executing it."""
    if not source.strip():
        raise DevSpaceInputError("input is empty")
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except DevSpaceInputError:
        raise
    except yaml.YAMLError as exc:
        raise DevSpaceInputError(f"invalid DevSpace YAML: {exc}") from exc
    configs = [document for document in documents if document is not None]
    if len(configs) != 1 or not isinstance(configs[0], dict):
        raise DevSpaceInputError("DevSpace input must contain exactly one configuration object")
    config = configs[0]
    version = str(config.get("version") or "")
    if not re.fullmatch(r"v(?:1beta\d+|2beta1)", version):
        raise DevSpaceInputError("configuration must declare a supported DevSpace version")
    return {"devspace": {"config": config}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _image_pinned(image: str) -> bool:
    return bool(re.search(r"@sha256:[0-9a-f]{64}$", image, re.I))


def _external_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        bool(_REMOTE.match(normalized))
        or path.is_absolute()
        or ".." in path.parts
        or bool(re.match(r"^[A-Za-z]:/", normalized))
    )


def _embedded_credential(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _contains_enabled_mapping(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        child = value.get(key)
        if isinstance(child, dict) and child.get("enabled") is not False:
            return True
        return any(_contains_enabled_mapping(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_enabled_mapping(item, key) for item in value)
    return False


def _secret_changes(value: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            address = f"{prefix}.{key}"
            if _SECRET.search(str(key)) and child not in (None, "", False, [], {}):
                text = str(child)
                reference = bool(
                    re.search(r"\$\{|\$\(|secretKeyRef|runtime\.variables", text, re.I)
                )
                changes.append(
                    _change(
                        address,
                        "secret_reference" if reference else "literal_secret",
                        "review" if reference else "dangerous",
                        "DevSpace references externally supplied credential-like data."
                        if reference
                        else "DevSpace configuration embeds credential-like material; the value "
                        "is omitted from analysis output.",
                    )
                )
            changes.extend(_secret_changes(child, address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            changes.extend(_secret_changes(child, f"{prefix}[{index}]"))
    return changes


def _source_changes(value: Any, prefix: str, kind: str) -> list[dict[str, str]]:
    entries = value if isinstance(value, list) else list(_mapping(value).values())
    changes: list[dict[str, str]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path") or "")
        git = str(entry.get("git") or "")
        revision = str(entry.get("revision") or "")
        tag = str(entry.get("tag") or "")
        branch = str(entry.get("branch") or "")
        pinned = bool(revision or tag) and not bool(branch)
        dangerous = (
            bool(git)
            and not pinned
            or _external_path(path)
            or _embedded_credential(git)
            or bool(entry.get("cloneArgs"))
        )
        changes.append(
            _change(
                f"{prefix}[{index}]",
                kind,
                "dangerous" if dangerous else "review",
                "DevSpace loads another configuration or project; review local path confinement, "
                "remote repository credentials, immutable revision, imported executable content, "
                "profiles, variables, namespace, and pipeline selection.",
            )
        )
    return changes


def _script_changes(value: Any, prefix: str, kind: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for name, raw in _mapping(value).items():
        config = _mapping(raw)
        script = str(config.get("run") or config.get("command") or raw or "")
        if not script:
            continue
        changes.append(
            _change(
                f"{prefix}.{name}",
                kind,
                "dangerous",
                "DevSpace executes configured POSIX or host commands; review command text, "
                "arguments, environment, credentials, network/filesystem access, failure policy, "
                "and any nested build/deploy/dependency operations.",
            )
        )
        if config.get("continueOnError") or config.get("after"):
            changes.append(
                _change(
                    f"{prefix}.{name}.failurePolicy",
                    "execution_failure_policy",
                    "dangerous",
                    "DevSpace execution continues after failure or runs cleanup code after errors "
                    "and interruption; review fail-open and recovery behavior.",
                )
            )
        if "$(" in script or _SHELL.search(script):
            changes.append(
                _change(
                    f"{prefix}.{name}.shell",
                    "dynamic_shell_execution",
                    "dangerous",
                    "DevSpace command contains shell composition or external tooling whose "
                    "effective behavior is resolved only at runtime.",
                )
            )
    return changes


def _image_changes(images: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for name, raw in _mapping(images).items():
        image = _mapping(raw)
        address = f"{prefix}.{name}"
        target = str(image.get("image") or "")
        if target:
            changes.append(
                _change(
                    f"{address}.image",
                    "image_target",
                    "review" if _image_pinned(target) else "dangerous",
                    "DevSpace image target is immutable."
                    if _image_pinned(target)
                    else "DevSpace image build or push target uses a mutable image reference.",
                )
            )
        context = str(image.get("context") or ".")
        if _external_path(context):
            changes.append(
                _change(
                    f"{address}.context",
                    "external_build_context",
                    "dangerous",
                    "DevSpace build context is remote or escapes the project boundary.",
                )
            )
        for engine in ("docker", "buildKit", "kaniko", "custom"):
            engine_config = _mapping(image.get(engine))
            if not engine_config:
                continue
            cluster = engine in {"buildKit", "kaniko"} and "inCluster" in engine_config
            custom = engine == "custom"
            changes.append(
                _change(
                    f"{address}.{engine}",
                    "image_builder",
                    "dangerous" if cluster or custom else "review",
                    f"DevSpace uses the {engine} image builder; review daemon/cluster identity, "
                    "commands, cache, build arguments, secrets, network, privileges, and output.",
                )
            )
        if image.get("appendDockerfileInstructions") or image.get("entrypoint") or image.get("cmd"):
            changes.append(
                _change(
                    f"{address}.inMemoryDockerfile",
                    "dockerfile_mutation",
                    "dangerous",
                    "DevSpace mutates Dockerfile instructions, entrypoint, or command in memory "
                    "before building the effective image.",
                )
            )
        changes.extend(_secret_changes(image, address))
    return changes


def _deployment_changes(deployments: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for name, raw in _mapping(deployments).items():
        deployment = _mapping(raw)
        address = f"{prefix}.{name}"
        helm = _mapping(deployment.get("helm"))
        if helm:
            chart = _mapping(helm.get("chart"))
            remote = bool(chart.get("repo") or _REMOTE.match(str(chart.get("name") or "")))
            pinned = bool(chart.get("version"))
            changes.append(
                _change(
                    f"{address}.helm",
                    "helm_deployment",
                    "dangerous" if remote and not pinned else "review",
                    "DevSpace deploys a Helm chart; review chart provenance/version, dependencies, "
                    "values, namespace, hooks, upgrade flags, and rendered resources.",
                )
            )
        kubectl = _mapping(deployment.get("kubectl"))
        if kubectl:
            changes.append(
                _change(
                    f"{address}.kubectl",
                    "kubernetes_deployment",
                    "dangerous",
                    "DevSpace deploys manifests or Kustomizations with kubectl; review source "
                    "confinement, patches, flags, namespace, pruning, and rendered resources.",
                )
            )
            for path_key in ("manifests", "kustomizations"):
                for index, path in enumerate(_items(kubectl.get(path_key))):
                    if _external_path(str(path)):
                        changes.append(
                            _change(
                                f"{address}.kubectl.{path_key}[{index}]",
                                "external_manifest_source",
                                "dangerous",
                                "DevSpace manifest source is remote or escapes the project "
                                "boundary.",
                            )
                        )
        changes.extend(_secret_changes(deployment, address))
    return changes


def _dev_changes(dev: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for name, raw in _mapping(dev).items():
        config = _mapping(raw)
        address = f"{prefix}.{name}"
        changes.append(
            _change(
                address,
                "development_session",
                "dangerous",
                "DevSpace selects and may mutate a live workload for development; review target "
                "context/namespace, pod/container selector, service account, and replacement "
                "scope.",
            )
        )
        text = str(config)
        if any(key in text for key in ("command", "args", "proxyCommands", "restartHelper")):
            changes.append(
                _change(
                    f"{address}.execution",
                    "container_execution",
                    "dangerous",
                    "DevSpace overrides or proxies commands in a workload container.",
                )
            )
        if any(key in text for key in ("sync", "download", "upload")):
            changes.append(
                _change(
                    f"{address}.sync",
                    "bidirectional_file_sync",
                    "dangerous",
                    "DevSpace transfers or synchronizes files between the local host and workload.",
                )
            )
        if any(key in text for key in ("forward", "ports", "portForwarding")):
            changes.append(
                _change(
                    f"{address}.ports",
                    "port_forward",
                    "review",
                    "DevSpace forwards ports between the workstation and workload; review bind "
                    "addresses, authentication, destination, and local network exposure.",
                )
            )
        if _contains_enabled_mapping(config, "ssh"):
            changes.append(
                _change(
                    f"{address}.ssh",
                    "ssh_tunnel",
                    "dangerous",
                    "DevSpace enables an SSH server/tunnel and can modify the user's SSH config.",
                )
            )
        changes.extend(_secret_changes(config, address))
    return changes


def _hook_changes(hooks: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, hook in enumerate(_items(hooks)):
        if not isinstance(hook, dict):
            continue
        address = f"{prefix}[{index}]"
        remote = bool(hook.get("container"))
        transfer = bool(hook.get("upload") or hook.get("download"))
        changes.append(
            _change(
                address,
                "container_hook" if remote else "host_hook",
                "dangerous",
                "DevSpace lifecycle hook executes commands or transfers data in a container."
                if remote
                else "DevSpace lifecycle hook executes commands or transfers data on the host.",
            )
        )
        if transfer:
            changes.append(
                _change(
                    f"{address}.transfer",
                    "hook_file_transfer",
                    "dangerous",
                    "DevSpace hook uploads or downloads files across the host/workload boundary.",
                )
            )
    return changes


def _profile_changes(profiles: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, profile in enumerate(_items(profiles)):
        if not isinstance(profile, dict):
            continue
        name = str(profile.get("name") or index)
        address = f"{prefix}.{name}"
        changes.append(
            _change(
                address,
                "profile_override",
                "review",
                "DevSpace profile activation can change the effective configuration and target.",
            )
        )
        if profile.get("patches") or profile.get("merge") or profile.get("replace"):
            changes.append(
                _change(
                    f"{address}.mutation",
                    "profile_patch",
                    "dangerous",
                    "DevSpace profile replaces, merges, or patches arbitrary configuration after "
                    "the base document is parsed.",
                )
            )
    return changes


def _config_changes(config: dict[str, Any]) -> list[dict[str, str]]:
    name = str(config.get("name") or "project")
    prefix = f"project.{name}"
    changes: list[dict[str, str]] = []
    version = str(config.get("version") or "")
    if version != "v2beta1":
        changes.append(
            _change(
                f"{prefix}.version",
                "legacy_config_version",
                "dangerous",
                f"DevSpace configuration uses legacy schema {version!r} and is converted at "
                "runtime.",
            )
        )
    changes.extend(_source_changes(config.get("imports"), f"{prefix}.imports", "config_import"))
    changes.extend(
        _source_changes(config.get("dependencies"), f"{prefix}.dependencies", "project_dependency")
    )
    changes.extend(
        _script_changes(config.get("functions"), f"{prefix}.functions", "shell_function")
    )
    changes.extend(
        _script_changes(config.get("pipelines"), f"{prefix}.pipelines", "pipeline_script")
    )
    changes.extend(_script_changes(config.get("commands"), f"{prefix}.commands", "custom_command"))
    changes.extend(_image_changes(config.get("images"), f"{prefix}.images"))
    changes.extend(_deployment_changes(config.get("deployments"), f"{prefix}.deployments"))
    changes.extend(_dev_changes(config.get("dev"), f"{prefix}.dev"))
    changes.extend(_hook_changes(config.get("hooks"), f"{prefix}.hooks"))
    changes.extend(_profile_changes(config.get("profiles"), f"{prefix}.profiles"))
    pull_secrets = _mapping(config.get("pullSecrets"))
    if pull_secrets:
        changes.append(
            _change(
                f"{prefix}.pullSecrets",
                "registry_credentials",
                "dangerous",
                "DevSpace creates image pull secrets in the target namespace; review registry "
                "identity, credential source, service accounts, and secret ownership.",
            )
        )
    local_registry = _mapping(config.get("localRegistry"))
    if local_registry and local_registry.get("enabled") is not False:
        image = str(local_registry.get("image") or "")
        changes.append(
            _change(
                f"{prefix}.localRegistry",
                "local_registry",
                "dangerous" if image and not _image_pinned(image) else "review",
                "DevSpace deploys or uses a local registry and optional in-cluster BuildKit; "
                "review image provenance, exposure, persistence, namespace, and credentials.",
            )
        )
    require = _mapping(config.get("require"))
    for index, plugin in enumerate(_items(require.get("plugins"))):
        changes.append(
            _change(
                f"{prefix}.require.plugins[{index}]",
                "required_plugin",
                "dangerous",
                "DevSpace requires a plugin that can extend CLI behavior; review source, version, "
                "installation, signature, and execution authority.",
            )
        )
    changes.extend(_secret_changes(config, prefix))
    changes.append(
        _change(
            f"{prefix}.effective_configuration",
            "evaluation_boundary",
            "review",
            "Static analysis does not resolve imports/dependencies/variables/expressions/profiles, "
            "execute pipelines/functions/commands/hooks/plugins, build images, render/deploy "
            "manifests, modify workloads, read kubeconfig, or contact registries/clusters.",
        )
    )
    return changes


class DevSpaceAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "devspace"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("devspace")
        return isinstance(payload, dict) and isinstance(payload.get("config"), dict)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        return _config_changes(input_data["devspace"]["config"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"devspace_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_devspace(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = DevSpaceAdapter().analyze(data, tool_name="DevSpace")
    summary = PlanSummary(
        path=Path("devspace://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="DevSpace")
    gate["adapter"] = "devspace"
    gate["project_name"] = str(data["devspace"]["config"].get("name") or "project")
    gate["total_changes"] = len(changes)
    return gate
