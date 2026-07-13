from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class SkaffoldInputError(ValueError):
    """Raised when input is not strict recognizable Skaffold configuration."""


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
            raise SkaffoldInputError("Skaffold YAML mapping keys must be scalar") from exc
        if duplicate:
            raise SkaffoldInputError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)

_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)", re.I
)
_REMOTE = re.compile(r"^(?:https?|git|ssh|oci)://", re.I)


def parse_skaffold(source: str) -> dict[str, Any]:
    """Parse one or more Skaffold YAML/JSON Config documents without resolving them."""
    if not source.strip():
        raise SkaffoldInputError("input is empty")
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except SkaffoldInputError:
        raise
    except yaml.YAMLError as exc:
        raise SkaffoldInputError(f"invalid Skaffold YAML: {exc}") from exc
    configs = [document for document in documents if document is not None]
    if not configs or not all(isinstance(document, dict) for document in configs):
        raise SkaffoldInputError("Skaffold input must contain configuration objects")
    for document in configs:
        if document.get("kind") != "Config" or not str(document.get("apiVersion", "")).startswith(
            "skaffold/"
        ):
            raise SkaffoldInputError("every document must be a Skaffold Config")
    return {"skaffold": {"configs": configs}}


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
    return (
        bool(_REMOTE.match(normalized))
        or PurePosixPath(normalized).is_absolute()
        or ".." in PurePosixPath(normalized).parts
        or bool(re.match(r"^[A-Za-z]:/", normalized))
    )


def _embedded_credential(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _secret_changes(value: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            address = f"{prefix}.{key}"
            if _SECRET.search(str(key)) and child not in (None, "", False, [], {}):
                text = str(child)
                reference = bool(re.search(r"\$\{|\{\{|env:|secretKeyRef", text, re.I))
                changes.append(
                    _change(
                        address,
                        "secret_reference" if reference else "literal_secret",
                        "review" if reference else "dangerous",
                        "Skaffold references externally supplied credential-like data."
                        if reference
                        else "Skaffold configuration embeds credential-like material; the "
                        "value is omitted from analysis output.",
                    )
                )
            changes.extend(_secret_changes(child, address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            changes.extend(_secret_changes(child, f"{prefix}[{index}]"))
    return changes


def _hook_changes(value: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    hooks = _mapping(value)
    for phase in ("before", "after"):
        for index, hook in enumerate(_items(hooks.get(phase))):
            if not isinstance(hook, dict):
                continue
            address = f"{prefix}.{phase}[{index}]"
            if hook.get("host") or hook.get("command"):
                changes.append(
                    _change(
                        address,
                        "host_hook",
                        "dangerous",
                        "Skaffold lifecycle hook executes a command on the host; review command, "
                        "working directory, environment, platform filters, credentials, and scope.",
                    )
                )
            if hook.get("container"):
                changes.append(
                    _change(
                        address,
                        "container_hook",
                        "dangerous",
                        "Skaffold lifecycle hook executes inside a workload container; review "
                        "pod/container targeting, command, identity, and cluster permissions.",
                    )
                )
    return changes


def _build_changes(build: dict[str, Any], prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for backend in ("local", "cluster", "googleCloudBuild"):
        if build.get(backend):
            risk = "dangerous" if backend in {"cluster", "googleCloudBuild"} else "review"
            changes.append(
                _change(
                    f"{prefix}.{backend}",
                    "build_backend",
                    risk,
                    f"Skaffold uses {backend} build execution; review daemon/cluster/project "
                    "identity, cache, push destination, concurrency, network, and build isolation.",
                )
            )
    insecure = _items(build.get("insecureRegistries"))
    if insecure:
        changes.append(
            _change(
                f"{prefix}.insecureRegistries",
                "insecure_registry",
                "dangerous",
                "Skaffold permits insecure container registries, weakening image transport and "
                "registry identity verification.",
            )
        )
    for index, artifact in enumerate(_items(build.get("artifacts"))):
        if not isinstance(artifact, dict):
            continue
        address = f"{prefix}.artifacts[{index}]"
        image = str(artifact.get("image") or "")
        if image:
            changes.append(
                _change(
                    f"{address}.image",
                    "image_target",
                    "review" if _image_pinned(image) else "dangerous",
                    "Skaffold build artifact target is immutable."
                    if _image_pinned(image)
                    else "Skaffold build artifact uses a mutable image name/tag destination.",
                )
            )
        context = str(artifact.get("context") or ".")
        if _external_path(context):
            changes.append(
                _change(
                    f"{address}.context",
                    "external_build_context",
                    "dangerous",
                    "Skaffold build context is remote or escapes the project boundary.",
                )
            )
        custom = _mapping(artifact.get("custom"))
        if custom:
            changes.append(
                _change(
                    f"{address}.custom",
                    "custom_build",
                    "dangerous",
                    "Skaffold custom builder executes user-defined build commands and dependency "
                    "discovery on the host or configured build environment.",
                )
            )
        for builder in ("docker", "kaniko", "jib", "bazel", "buildpacks", "ko"):
            config = _mapping(artifact.get(builder))
            if not config:
                continue
            changes.append(
                _change(
                    f"{address}.{builder}",
                    "artifact_builder",
                    "review",
                    f"Skaffold builds this artifact with {builder}; review source inputs, "
                    "build arguments, target, cache, secrets, platform, and generated image.",
                )
            )
            if config.get("noCache") or config.get("pullParent") is False:
                changes.append(
                    _change(
                        f"{address}.{builder}.reproducibility",
                        "build_reproducibility",
                        "review",
                        "Skaffold builder cache/base-image settings can change reproducibility.",
                    )
                )
        changes.extend(_hook_changes(artifact.get("hooks"), f"{address}.hooks"))
        changes.extend(
            _hook_changes(_mapping(artifact.get("sync")).get("hooks"), f"{address}.sync.hooks")
        )
        changes.extend(_secret_changes(artifact, address))
    changes.extend(_hook_changes(build.get("hooks"), f"{prefix}.hooks"))
    tag_policy = _mapping(build.get("tagPolicy"))
    if (
        tag_policy.get("dateTime")
        or tag_policy.get("envTemplate")
        or tag_policy.get("customTemplate")
    ):
        changes.append(
            _change(
                f"{prefix}.tagPolicy",
                "mutable_tag_policy",
                "review",
                "Skaffold tag policy depends on time, environment, or templates; effective image "
                "identity is resolved only during execution.",
            )
        )
    return changes


def _manifest_changes(manifests: dict[str, Any], prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for path_key in ("rawYaml", "remoteManifests"):
        for index, path in enumerate(_items(manifests.get(path_key))):
            text = str(path)
            dangerous = path_key == "remoteManifests" or _external_path(text)
            changes.append(
                _change(
                    f"{prefix}.{path_key}[{index}]",
                    "manifest_source",
                    "dangerous" if dangerous else "review",
                    "Skaffold loads Kubernetes manifests; review source confinement, immutable "
                    "provenance, rendered content, namespaces, and deletion behavior.",
                )
            )
    kustomize = _mapping(manifests.get("kustomize"))
    if kustomize:
        changes.append(
            _change(
                f"{prefix}.kustomize",
                "kustomize_render",
                "review",
                "Skaffold invokes Kustomize with configured paths and build arguments; rendered "
                "resources and plugin behavior are unresolved.",
            )
        )
        build_args = " ".join(str(arg) for arg in _items(kustomize.get("buildArgs")))
        if re.search(
            r"--enable-(?:alpha-)?plugins|--load-restrictor(?:=|\s+)LoadRestrictionsNone",
            build_args,
            re.I,
        ):
            changes.append(
                _change(
                    f"{prefix}.kustomize.buildArgs",
                    "kustomize_plugin_boundary",
                    "dangerous",
                    "Skaffold enables Kustomize plugins or disables load restrictions; plugin "
                    "code and file access are unresolved by static analysis.",
                )
            )
    helm = _mapping(manifests.get("helm"))
    for index, release in enumerate(_items(helm.get("releases"))):
        if not isinstance(release, dict):
            continue
        remote = bool(release.get("remoteChart"))
        pinned = bool(release.get("version"))
        changes.append(
            _change(
                f"{prefix}.helm.releases[{index}]",
                "helm_render",
                "dangerous" if remote and not pinned else "review",
                "Skaffold renders a Helm chart; review repository/chart provenance, version, "
                "dependencies, values files, set values, flags, hooks, and rendered manifests.",
            )
        )
        changes.extend(_secret_changes(release, f"{prefix}.helm.releases[{index}]"))
    changes.extend(_hook_changes(manifests.get("hooks"), f"{prefix}.hooks"))
    return changes


def _deploy_changes(deploy: dict[str, Any], prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for engine in ("kubectl", "helm", "kustomize", "kpt", "cloudrun", "docker"):
        config = _mapping(deploy.get(engine))
        if not config:
            continue
        changes.append(
            _change(
                f"{prefix}.{engine}",
                "deployment_engine",
                "dangerous",
                f"Skaffold deploys with {engine}; review target context/project, namespace, "
                "flags, credentials, server-side behavior, hooks, pruning, and rollback.",
            )
        )
        flags = str(config.get("flags") or config)
        if re.search(
            r"--(?:validate=false|force|insecure|disable-openapi-validation)", flags, re.I
        ):
            changes.append(
                _change(
                    f"{prefix}.{engine}.flags",
                    "deployment_validation_bypass",
                    "dangerous",
                    "Skaffold deployer flags bypass validation, force replacement, or weaken "
                    "transport verification.",
                )
            )
        changes.extend(_hook_changes(config.get("hooks"), f"{prefix}.{engine}.hooks"))
        changes.extend(_secret_changes(config, f"{prefix}.{engine}"))
    return changes


def _requires_changes(requires: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, requirement in enumerate(_items(requires)):
        if not isinstance(requirement, dict):
            continue
        address = f"{prefix}[{index}]"
        path = str(requirement.get("path") or "")
        git = _mapping(requirement.get("git"))
        repo = str(git.get("repo") or "")
        ref = str(git.get("ref") or "")
        cloud = _mapping(requirement.get("googleCloudBuildRepoV2"))
        remote = bool(git or cloud or _REMOTE.match(path))
        pinned = bool(ref and ref not in {"main", "master", "HEAD"})
        dangerous = (remote and not pinned) or _external_path(path) or _embedded_credential(repo)
        changes.append(
            _change(
                address,
                "config_dependency",
                "dangerous" if dangerous else "review",
                "Skaffold imports another configuration; review repository/path confinement, "
                "immutable ref, sync behavior, active profiles, ownership, and credentials.",
            )
        )
    return changes


def _execution_container_changes(containers: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, container in enumerate(_items(containers)):
        if not isinstance(container, dict):
            continue
        address = f"{prefix}[{index}]"
        image = str(container.get("image") or "")
        if image:
            changes.append(
                _change(
                    f"{address}.image",
                    "execution_image",
                    "review" if _image_pinned(image) else "dangerous",
                    "Skaffold execution container image is immutable."
                    if _image_pinned(image)
                    else "Skaffold execution container uses a mutable image reference.",
                )
            )
        if container.get("command") or container.get("args"):
            changes.append(
                _change(
                    f"{address}.command",
                    "container_command",
                    "dangerous",
                    "Skaffold execution container runs configured commands or arguments.",
                )
            )
        changes.extend(_secret_changes(container, address))
    return changes


def _config_changes(config: dict[str, Any], index: int) -> list[dict[str, str]]:
    metadata = _mapping(config.get("metadata"))
    name = str(metadata.get("name") or f"config-{index}")
    prefix = f"config.{name}"
    changes: list[dict[str, str]] = []
    api_version = str(config.get("apiVersion") or "")
    if not api_version.startswith("skaffold/v4"):
        changes.append(
            _change(
                f"{prefix}.apiVersion",
                "legacy_api_version",
                "dangerous",
                f"Skaffold configuration uses legacy or unknown schema {api_version!r}.",
            )
        )
    changes.extend(_requires_changes(config.get("requires"), f"{prefix}.requires"))
    changes.extend(_build_changes(_mapping(config.get("build")), f"{prefix}.build"))
    changes.extend(_manifest_changes(_mapping(config.get("manifests")), f"{prefix}.manifests"))
    changes.extend(_deploy_changes(_mapping(config.get("deploy")), f"{prefix}.deploy"))
    for verify_index, verify in enumerate(_items(config.get("verify"))):
        if not isinstance(verify, dict):
            continue
        address = f"{prefix}.verify[{verify_index}]"
        changes.append(
            _change(
                address,
                "verification_action",
                "review",
                "Skaffold verification runs a container locally or as a Kubernetes Job; review "
                "image, command, cluster identity, job overrides, timeout, and failure policy.",
            )
        )
        execution_mode = _mapping(verify.get("executionMode"))
        if "kubernetesCluster" in execution_mode:
            cluster = _mapping(execution_mode.get("kubernetesCluster"))
            changes.append(
                _change(
                    f"{address}.executionMode.kubernetesCluster",
                    "cluster_verification",
                    "dangerous" if cluster else "review",
                    "Skaffold runs verification as a Kubernetes Job; review cluster identity, "
                    "namespace, service account, pod overrides, and job manifest provenance.",
                )
            )
        changes.extend(_execution_container_changes([verify], address))
    for action_index, action in enumerate(_items(config.get("customActions"))):
        if not isinstance(action, dict):
            continue
        address = f"{prefix}.customActions[{action_index}]"
        remote = "kubernetesCluster" in _mapping(action.get("executionMode"))
        changes.append(
            _change(
                address,
                "custom_action",
                "dangerous",
                "Skaffold custom action executes containers as local Docker workloads or "
                + ("Kubernetes Jobs." if remote else "host-connected local actions."),
            )
        )
        changes.extend(
            _execution_container_changes(action.get("containers"), f"{address}.containers")
        )
    for forward_index, forward in enumerate(_items(config.get("portForward"))):
        if isinstance(forward, dict):
            address = str(forward.get("address") or "")
            changes.append(
                _change(
                    f"{prefix}.portForward[{forward_index}]",
                    "port_forward",
                    "dangerous" if address in {"0.0.0.0", "::", "*"} else "review",
                    "Skaffold forwards a workload port to the local host; review address, port, "
                    "resource selection, authentication, and developer-machine exposure.",
                )
            )
    for profile_index, profile in enumerate(_items(config.get("profiles"))):
        if not isinstance(profile, dict):
            continue
        profile_name = str(profile.get("name") or profile_index)
        address = f"{prefix}.profiles.{profile_name}"
        changes.append(
            _change(
                address,
                "profile_override",
                "review",
                "Skaffold profile overlays build, render, test, deploy, forwarding, or action "
                "configuration based on command, environment, or Kubernetes context.",
            )
        )
        if profile.get("patches"):
            changes.append(
                _change(
                    f"{address}.patches",
                    "profile_patch",
                    "dangerous",
                    "Skaffold JSON patches can replace, remove, copy, or move arbitrary pipeline "
                    "configuration after the base document is parsed.",
                )
            )
        changes.extend(_build_changes(_mapping(profile.get("build")), f"{address}.build"))
        changes.extend(
            _manifest_changes(_mapping(profile.get("manifests")), f"{address}.manifests")
        )
        changes.extend(_deploy_changes(_mapping(profile.get("deploy")), f"{address}.deploy"))
    changes.extend(_secret_changes(config, prefix))
    changes.append(
        _change(
            f"{prefix}.effective_pipeline",
            "evaluation_boundary",
            "review",
            "Static analysis does not resolve required configs/profiles/patches, build images, "
            "run hooks/tests/actions, render manifests, invoke deployment CLIs, read kubeconfig, "
            "contact registries/cloud builders, or access a Kubernetes cluster.",
        )
    )
    return changes


class SkaffoldAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "skaffold"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("skaffold")
        return isinstance(payload, dict) and isinstance(payload.get("configs"), list)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for index, config in enumerate(input_data["skaffold"]["configs"]):
            if isinstance(config, dict):
                changes.extend(_config_changes(config, index))
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"skaffold_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_skaffold(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = SkaffoldAdapter().analyze(data, tool_name="Skaffold")
    summary = PlanSummary(
        path=Path("skaffold://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Skaffold")
    gate["adapter"] = "skaffold"
    gate["config_count"] = len(data["skaffold"]["configs"])
    gate["total_changes"] = len(changes)
    return gate
