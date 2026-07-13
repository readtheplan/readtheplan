# Long explanations are kept as complete user-facing sentences.
# ruff: noqa: E501

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class HelmfileInputError(ValueError):
    """Raised when input is not recognizable Helmfile state or lock data."""


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
            raise HelmfileInputError("Helmfile YAML mapping keys must be scalar") from exc
        if duplicate:
            raise HelmfileInputError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)

_KNOWN_KEYS = {
    "apiVersions",
    "bases",
    "environments",
    "helmDefaults",
    "helmfiles",
    "hooks",
    "kubeVersion",
    "releases",
    "repositories",
    "templates",
}
_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)", re.I
)
_REMOTE = re.compile(r"^(?:https?|git|ssh|s3|oci)[:+]//|^[^/@\s]+@[^:\s]+:", re.I)
_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.I)
_TEMPLATE = re.compile(r"{{-?.*?-?}}", re.S)


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _enabled(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def _disabled(value: Any) -> bool:
    return value is False or str(value).strip().lower() in {"0", "false", "no", "off"}


def _external(value: str) -> bool:
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
        parsed = urlsplit(value.removeprefix("git::"))
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _merge_documents(documents: list[Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for document in documents:
        if document is None:
            continue
        if not isinstance(document, dict):
            raise HelmfileInputError("each Helmfile YAML document must be an object")
        for key, value in document.items():
            if key in merged:
                raise HelmfileInputError(f"duplicate Helmfile section across documents: {key}")
            merged[key] = value
    return merged


def parse_helmfile(source: str, filename: str = "helmfile.yaml") -> dict[str, Any]:
    """Parse Helmfile state or lock YAML without rendering templates or executing tools."""
    if not source.strip():
        raise HelmfileInputError("input is empty")
    if source.count("{{") != source.count("}}"):
        raise HelmfileInputError("Go template has unbalanced action delimiters")
    sanitized = _TEMPLATE.sub("", source)
    try:
        documents = list(yaml.load_all(sanitized, Loader=_UniqueKeyLoader))  # noqa: S506
    except HelmfileInputError:
        raise
    except yaml.YAMLError as exc:
        raise HelmfileInputError(f"invalid Helmfile YAML: {exc}") from exc
    document = _merge_documents(documents)
    name = Path(filename).name.lower()
    lock_like = name.endswith(".lock") or (
        "digest" in document and isinstance(document.get("dependencies"), list)
    )
    if lock_like:
        if not isinstance(document.get("dependencies"), list):
            raise HelmfileInputError("Helmfile lock must contain a dependencies array")
        artifact_type = "lock"
    else:
        if not (_KNOWN_KEYS & set(document)):
            raise HelmfileInputError("no recognizable Helmfile state sections were found")
        artifact_type = "state"
    return {
        "helmfile": {
            "artifact_type": artifact_type,
            "filename": Path(filename).name,
            "document": document,
            "source": source,
        }
    }


def _secret_changes(value: Any, address: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_address = f"{address}.{key}"
            if _SECRET.search(str(key)) and child not in (None, "", False, [], {}):
                text = str(child)
                reference = bool(
                    re.search(r"ref\+(?:vault|awsssm|gcpsecrets|sops)|secretKeyRef|{{", text, re.I)
                )
                changes.append(
                    _change(
                        child_address,
                        "secret_reference" if reference else "literal_secret",
                        "review" if reference else "dangerous",
                        "Helmfile references externally resolved credential-like data."
                        if reference
                        else "Helmfile embeds credential-like material; the value is omitted from analysis output.",
                    )
                )
            changes.extend(_secret_changes(child, child_address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            changes.extend(_secret_changes(child, f"{address}[{index}]"))
    return changes


def _path_entries(value: Any, address: str, kind: str) -> list[dict[str, str]]:
    entries = value if isinstance(value, list) else [value]
    changes: list[dict[str, str]] = []
    for index, entry in enumerate(entries):
        path = str(entry.get("path") if isinstance(entry, dict) else entry or "")
        if not path or isinstance(entry, dict) and not entry.get("path"):
            continue
        dynamic = "{{" in path
        remote = bool(_REMOTE.match(path))
        pinned = bool(re.search(r"(?:[?&]ref=|@)[0-9a-f]{7,64}(?:$|[?&/])", path, re.I))
        changes.append(
            _change(
                f"{address}[{index}]",
                kind,
                "dangerous" if _external(path) or dynamic or remote and not pinned else "review",
                "Helmfile loads local, templated, or remote content; review path confinement, immutable revision, credentials, cache behavior, imported templates, and transitive execution.",
            )
        )
        if _embedded_credential(path):
            changes.append(
                _change(
                    f"{address}[{index}]",
                    "embedded_repository_credential",
                    "dangerous",
                    "Helmfile URL embeds repository credentials; the credential value is omitted from analysis output.",
                )
            )
    return changes


def _template_changes(source: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    probes = (
        (
            r"{{-?[^}]*\bexec\s",
            "template_exec",
            "dangerous",
            "Helmfile Go templating executes a host process; review command, arguments, environment, credentials, network/filesystem access, and output trust.",
        ),
        (
            r"{{-?[^}]*\benvExec\s",
            "template_env_exec",
            "dangerous",
            "Helmfile Go templating executes a host process with supplied environment variables; review command and secret exposure.",
        ),
        (
            r"{{-?[^}]*\b(?:readFile|readDir|readDirEntries)\s",
            "template_file_read",
            "dangerous",
            "Helmfile Go templating reads host filesystem content; review path confinement, symlinks, sensitive data, and generated configuration.",
        ),
        (
            r"{{-?[^}]*\b(?:fetchSecretValue|expandSecretRefs)\b",
            "remote_secret_resolution",
            "dangerous",
            "Helmfile resolves remote secrets through vals providers; review backend identity, authentication, authorization, versioning, and disclosure paths.",
        ),
        (
            r"{{-?[^}]*\b(?:env|requiredEnv)\s",
            "environment_input",
            "review",
            "Helmfile behavior depends on host environment variables; review CI injection, defaults, secret handling, and reproducibility.",
        ),
        (
            r"{{-?[^}]*\b(?:tpl|include)\s",
            "dynamic_template",
            "dangerous",
            "Helmfile performs nested or included template evaluation; effective state depends on additional content and template context.",
        ),
    )
    for pattern, kind, risk, explanation in probes:
        if re.search(pattern, source, re.S):
            changes.append(_change(f"template.{kind}", kind, risk, explanation))
    return changes


def _repository_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, repository in enumerate(_items(document.get("repositories"))):
        if not isinstance(repository, dict):
            continue
        address = f"repositories[{index}]"
        url = str(repository.get("url") or "")
        dangerous = (
            url.startswith("http://")
            or _enabled(repository.get("plainHttp"))
            or _enabled(repository.get("skipTLSVerify"))
            or _enabled(repository.get("passCredentials"))
        )
        changes.append(
            _change(
                address,
                "chart_repository",
                "dangerous" if dangerous else "review",
                "Helmfile configures a chart repository; verify TLS, repository ownership, authentication scope, plugins, index integrity, and package provenance.",
            )
        )
        if any(repository.get(key) for key in ("username", "password", "certFile", "keyFile")):
            changes.append(
                _change(
                    address,
                    "repository_authentication",
                    "dangerous",
                    "Helmfile supplies chart repository authentication or client-key material; values are omitted from analysis output.",
                )
            )
    return changes


def _hook_changes(hooks: Any, address: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, hook in enumerate(_items(hooks)):
        if not isinstance(hook, dict):
            continue
        hook_address = f"{address}[{index}]"
        if hook.get("command"):
            changes.append(
                _change(
                    hook_address,
                    "host_command_hook",
                    "dangerous",
                    "Helmfile lifecycle hook executes a host command; review lifecycle events, arguments, environment, credentials, filesystem/network access, logs, failure behavior, and side effects.",
                )
            )
        if hook.get("kubectlApply"):
            changes.append(
                _change(
                    hook_address,
                    "kubectl_apply_hook",
                    "dangerous",
                    "Helmfile lifecycle hook applies or deletes Kubernetes resources directly with kubectl; review manifest source, context, namespace, lifecycle ordering, deletion scope, and rollback.",
                )
            )
        if _enabled(hook.get("showlogs")):
            changes.append(
                _change(
                    hook_address,
                    "hook_log_disclosure",
                    "review",
                    "Helmfile displays hook output, which may disclose credentials or sensitive command results in CI logs.",
                )
            )
    return changes


def _release_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, release in enumerate(_items(document.get("releases"))):
        if not isinstance(release, dict):
            continue
        address = f"releases[{index}]"
        chart = str(release.get("chart") or "")
        version = str(release.get("version") or "")
        local_chart = chart.startswith(("./", "../", "/"))
        pinned = bool(_SEMVER.fullmatch(version)) or "@sha256:" in chart
        changes.append(
            _change(
                address,
                "helm_release",
                "dangerous",
                "Helmfile can install, upgrade, or uninstall this Helm release; review rendered Kubernetes resources, target cluster/namespace, values, hooks, dependencies, ownership, and rollback.",
            )
        )
        if not local_chart and not pinned:
            changes.append(
                _change(
                    f"{address}.version",
                    "unpinned_chart",
                    "dangerous",
                    "Helmfile release does not use an exact chart version or OCI digest; repository updates or ranges can change deployed content.",
                )
            )
        namespace = str(release.get("namespace") or "").lower()
        if namespace in {"", "default", "production", "prod", "kube-system"}:
            changes.append(
                _change(
                    f"{address}.namespace",
                    "sensitive_namespace",
                    "dangerous",
                    "Helmfile release targets an implicit, broad, production, or system namespace; review tenancy, RBAC, and blast radius.",
                )
            )
        if release.get("kubeContext"):
            changes.append(
                _change(
                    f"{address}.kubeContext",
                    "cluster_target",
                    "dangerous",
                    "Helmfile release selects a kubeconfig context; verify cluster identity, credentials, environment separation, and operator authorization.",
                )
            )
        if _disabled(release.get("installed")):
            changes.append(
                _change(
                    f"{address}.installed",
                    "release_uninstall",
                    "dangerous",
                    "Helmfile marks the release absent, causing uninstall and possible workload or persistent-data removal.",
                )
            )
        risky_flags = {
            "atomic": False,
            "cleanupOnFail": False,
            "disableValidation": True,
            "force": True,
            "recreatePods": True,
            "replace": True,
            "reuseValues": True,
            "skipDeps": True,
            "skipSchemaValidation": True,
            "wait": False,
        }
        for key, risky_value in risky_flags.items():
            if release.get(key) is risky_value:
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "unsafe_release_option",
                        "dangerous",
                        "Helmfile release enables an unsafe or weakly verified Helm lifecycle option; review failure atomicity, validation, dependency freshness, mutation strategy, and rollback behavior.",
                    )
                )
        if release.get("postRenderer"):
            changes.append(
                _change(
                    f"{address}.postRenderer",
                    "post_renderer",
                    "dangerous",
                    "Helmfile executes a post-renderer that can arbitrarily transform generated Kubernetes manifests before review or apply.",
                )
            )
        if release.get("needs"):
            changes.append(
                _change(
                    f"{address}.needs",
                    "release_dependency_dag",
                    "review",
                    "Helmfile dependency ordering controls concurrent install and reverse deletion order; verify cross-context/namespace references and failure propagation.",
                )
            )
        changes.extend(
            _path_entries(release.get("values", []), f"{address}.values", "release_values_source")
        )
        changes.extend(
            _path_entries(release.get("secrets", []), f"{address}.secrets", "release_secret_source")
        )
        changes.extend(_hook_changes(release.get("hooks"), f"{address}.hooks"))
        for dep_index, dependency in enumerate(_items(release.get("dependencies"))):
            if isinstance(dependency, dict):
                dep_version = str(dependency.get("version") or "")
                changes.append(
                    _change(
                        f"{address}.dependencies[{dep_index}]",
                        "adhoc_chart_dependency",
                        "dangerous" if not _SEMVER.fullmatch(dep_version) else "review",
                        "Helmfile injects an ad-hoc chart dependency into a temporary chart; verify source, exact version, alias/condition, generated Chart metadata, and lock coverage.",
                    )
                )
    return changes


def _environment_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for name, environment in _mapping(document.get("environments")).items():
        if not isinstance(environment, dict):
            continue
        address = f"environments.{name}"
        if str(name).lower() in {"production", "prod"}:
            changes.append(
                _change(
                    address,
                    "production_environment",
                    "dangerous",
                    "Helmfile defines a production environment; require explicit selection, approval, evidence, target verification, and rollback planning.",
                )
            )
        if environment.get("kubeContext"):
            changes.append(
                _change(
                    f"{address}.kubeContext",
                    "environment_cluster_target",
                    "dangerous",
                    "Helmfile environment selects a kubeconfig context for releases and hooks; verify cluster identity and authorization.",
                )
            )
        changes.extend(
            _path_entries(
                environment.get("values", []), f"{address}.values", "environment_values_source"
            )
        )
        changes.extend(
            _path_entries(
                environment.get("secrets", []), f"{address}.secrets", "environment_secret_source"
            )
        )
        if str(environment.get("missingFileHandler", "Error")).lower() != "error":
            changes.append(
                _change(
                    f"{address}.missingFileHandler",
                    "missing_input_fail_open",
                    "dangerous",
                    "Helmfile environment continues when a values or secrets input is missing, allowing incomplete effective configuration.",
                )
            )
    return changes


def _state_changes(document: dict[str, Any], source: str) -> list[dict[str, str]]:
    changes = [
        _change(
            "helmfile",
            "desired_state",
            "review",
            "Helmfile declaratively coordinates Helm repositories, releases, values, secrets, environments, and Kubernetes targets.",
        )
    ]
    changes.extend(_template_changes(source))
    changes.extend(_repository_changes(document))
    changes.extend(_release_changes(document))
    changes.extend(_environment_changes(document))
    changes.extend(_path_entries(document.get("bases", []), "bases", "base_state"))
    changes.extend(_path_entries(document.get("helmfiles", []), "helmfiles", "nested_state"))
    changes.extend(_hook_changes(document.get("hooks"), "hooks"))
    defaults = _mapping(document.get("helmDefaults"))
    if defaults.get("kubeContext"):
        changes.append(
            _change(
                "helmDefaults.kubeContext",
                "default_cluster_target",
                "dangerous",
                "Helmfile defaults all releases to a kubeconfig context; verify cluster identity, credentials, and environment separation.",
            )
        )
    for key in ("helmBinary", "kustomizeBinary", "lockFilePath"):
        value = str(document.get(key) or "")
        if value and (_external(value) or "{{" in value):
            changes.append(
                _change(
                    key,
                    "external_tool_or_lock_path",
                    "dangerous",
                    "Helmfile uses an external or templated executable/lock path; review path confinement, binary trust, environment selection, and reproducibility.",
                )
            )
    if defaults.get("postRenderer"):
        changes.append(
            _change(
                "helmDefaults.postRenderer",
                "default_post_renderer",
                "dangerous",
                "Helmfile executes a default post-renderer that can transform every generated Kubernetes manifest.",
            )
        )
    if any(
        _enabled(defaults.get(key)) for key in ("insecureSkipTLSVerify", "plainHttp", "skipDeps")
    ):
        changes.append(
            _change(
                "helmDefaults",
                "unsafe_helm_defaults",
                "dangerous",
                "Helmfile defaults weaken transport verification or dependency preparation for all releases.",
            )
        )
    if document.get("apiVersions") or document.get("kubeVersion"):
        changes.append(
            _change(
                "capabilities",
                "synthetic_cluster_capabilities",
                "review",
                "Helmfile overrides Kubernetes API or version capabilities used during rendering; verify compatibility with the real target cluster.",
            )
        )
    changes.extend(_secret_changes(document, "helmfile"))
    changes.append(
        _change(
            "helmfile.effective_state",
            "execution_boundary",
            "review",
            "Static analysis does not render Go templates, execute commands/hooks/post-renderers, read files or environment variables, decrypt/fetch secrets, resolve nested states, refresh repositories, download/render charts, load kubeconfig, diff live state, contact Kubernetes, install/upgrade/uninstall releases, or delete resources.",
        )
    )
    return changes


def _lock_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, dependency in enumerate(_items(document.get("dependencies"))):
        if not isinstance(dependency, dict):
            changes.append(
                _change(
                    f"dependencies[{index}]",
                    "invalid_locked_dependency",
                    "dangerous",
                    "Helmfile lock dependency is not a structured object.",
                )
            )
            continue
        repository = str(dependency.get("repository") or "")
        version = str(dependency.get("version") or "")
        risk = (
            "review"
            if _SEMVER.fullmatch(version) and repository.startswith(("https://", "oci://"))
            else "dangerous"
        )
        changes.append(
            _change(
                f"dependencies[{index}]",
                "locked_chart",
                risk,
                "Helmfile lock records an exact chart selection; verify repository ownership, TLS, immutable package provenance, dependency identity, and correspondence with state intent.",
            )
        )
    digest = str(document.get("digest") or "")
    changes.append(
        _change(
            "digest",
            "lock_integrity",
            "review" if _DIGEST.fullmatch(digest) else "dangerous",
            "Helmfile lock includes a SHA-256 state digest that protects dependency resolution reproducibility."
            if _DIGEST.fullmatch(digest)
            else "Helmfile lock lacks a recognizable SHA-256 state digest and may not provide tamper-evident reproducibility.",
        )
    )
    changes.append(
        _change(
            "helmfile.lock",
            "lock_resolution_boundary",
            "review",
            "Static analysis does not run helmfile deps, refresh repositories, download charts, validate package contents/signatures, or recompute the lock digest.",
        )
    )
    return changes


class HelmfileAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "helmfile"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("helmfile")
        return (
            isinstance(payload, dict)
            and payload.get("artifact_type") in {"state", "lock"}
            and isinstance(payload.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["helmfile"]
        if payload["artifact_type"] == "lock":
            return _lock_changes(payload["document"])
        return _state_changes(payload["document"], payload["source"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"helmfile_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_helmfile(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = HelmfileAdapter().analyze(data, tool_name="Helmfile")
    summary = PlanSummary(
        path=Path("helmfile://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Helmfile")
    gate["adapter"] = "helmfile"
    gate["artifact_type"] = data["helmfile"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
