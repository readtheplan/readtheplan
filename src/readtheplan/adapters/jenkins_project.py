from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class JenkinsProjectInputError(ValueError):
    """Raised when input is not a Jenkins plugin installation catalog."""


_PLUGIN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*$")
_VERSION_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]*$")
_INCREMENTAL_VERSION = re.compile(
    r"incrementals;[A-Za-z0-9_.-]+;[A-Za-z0-9][A-Za-z0-9.+_-]*$",
    re.IGNORECASE,
)
_DYNAMIC_VALUE = re.compile(r"(?:\$\{|\$[A-Za-z_]|\{\{|<%|#\{)")
_PRIVILEGED_PLUGINS = {
    "active-directory": "authentication",
    "authorize-project": "build authorization",
    "configuration-as-code": "controller configuration",
    "credentials": "credential storage",
    "credentials-binding": "credential exposure to builds",
    "docker-workflow": "container execution",
    "job-dsl": "dynamic job creation",
    "kubernetes": "cluster-backed build agents",
    "ldap": "authentication",
    "matrix-auth": "controller authorization",
    "oic-auth": "authentication",
    "role-strategy": "controller authorization",
    "saml": "authentication",
    "script-security": "Groovy script approval and sandboxing",
    "ssh-credentials": "SSH credential storage",
    "workflow-cps": "Pipeline Groovy execution",
}
_MAX_PLUGINS = 5_000


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    keys: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in keys
        except TypeError as exc:
            raise JenkinsProjectInputError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise JenkinsProjectInputError(f"duplicate YAML key: {key}")
        keys.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _validate_plugin_id(value: Any, *, location: str) -> str:
    plugin_id = str(value).strip() if value is not None else ""
    if not _PLUGIN_ID.fullmatch(plugin_id):
        raise JenkinsProjectInputError(f"invalid plugin artifact ID at {location}")
    return plugin_id


def _validate_catalog(plugins: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not plugins:
        raise JenkinsProjectInputError("plugin catalog does not contain any plugins")
    if len(plugins) > _MAX_PLUGINS:
        raise JenkinsProjectInputError(f"plugin catalog exceeds {_MAX_PLUGINS} entries")
    seen: dict[str, int] = {}
    for index, plugin in enumerate(plugins, start=1):
        normalized = str(plugin["artifact_id"]).casefold()
        if normalized in seen:
            raise JenkinsProjectInputError(
                f"duplicate plugin artifact ID on entries {seen[normalized]} and {index}"
            )
        seen[normalized] = index
    return plugins


def _looks_like_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.scheme and (parsed.netloc or parsed.scheme == "file"))


def _parse_text_plugin(line: str, line_number: int) -> dict[str, Any]:
    artifact, separator, remainder = line.partition(":")
    artifact_id = _validate_plugin_id(artifact, location=f"line {line_number}")
    version = ""
    url = ""
    ambiguous_url = False
    if separator:
        if _looks_like_url(remainder):
            url = remainder
            ambiguous_url = True
        else:
            version, url_separator, candidate_url = remainder.partition(":")
            if url_separator:
                if not _looks_like_url(candidate_url):
                    raise JenkinsProjectInputError(
                        f"invalid plugin download URL on line {line_number}"
                    )
                url = candidate_url
            elif not version:
                raise JenkinsProjectInputError(f"missing plugin version on line {line_number}")
    version = version.strip()
    if version and not (
        _VERSION_TOKEN.fullmatch(version)
        or _INCREMENTAL_VERSION.fullmatch(version)
        or _DYNAMIC_VALUE.search(version)
    ):
        raise JenkinsProjectInputError(f"invalid plugin version on line {line_number}")
    return {
        "artifact_id": artifact_id,
        "version": version,
        "url": url.strip(),
        "group_id": "",
        "location": f"line.{line_number}",
        "ambiguous_url": ambiguous_url,
    }


def _parse_text_catalog(source: str) -> dict[str, Any]:
    plugins: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if any(character.isspace() for character in line):
            raise JenkinsProjectInputError(
                f"plugin entry on line {line_number} must not contain whitespace"
            )
        plugins.append(_parse_text_plugin(line, line_number))
    return {
        "artifact_type": "plugins_txt",
        "document": {"plugins": _validate_catalog(plugins)},
    }


def _string_field(value: Any, *, field: str, entry: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise JenkinsProjectInputError(f"plugin {field} on entry {entry} must be scalar")
    return str(value).strip()


def _parse_yaml_catalog(source: str) -> dict[str, Any]:
    try:
        document = yaml.load(source, Loader=_UniqueKeyLoader)  # noqa: S506
    except JenkinsProjectInputError:
        raise
    except yaml.YAMLError as exc:
        raise JenkinsProjectInputError(str(exc)) from exc
    if not isinstance(document, dict) or set(document) != {"plugins"}:
        raise JenkinsProjectInputError("YAML plugin catalog must contain only a plugins list")
    raw_plugins = document["plugins"]
    if not isinstance(raw_plugins, list):
        raise JenkinsProjectInputError("YAML plugins must be a list")
    plugins: list[dict[str, Any]] = []
    for index, item in enumerate(raw_plugins, start=1):
        if not isinstance(item, dict):
            raise JenkinsProjectInputError(f"YAML plugin entry {index} must be a mapping")
        unknown = set(item) - {"artifactId", "groupId", "source"}
        if unknown:
            raise JenkinsProjectInputError(
                f"unsupported YAML plugin key(s) on entry {index}: "
                + ", ".join(sorted(map(str, unknown)))
            )
        artifact_id = _validate_plugin_id(item.get("artifactId"), location=f"entry {index}")
        group_id = _string_field(item.get("groupId"), field="groupId", entry=index)
        source_value = item.get("source", {})
        if source_value is None:
            source_value = {}
        if not isinstance(source_value, dict):
            raise JenkinsProjectInputError(f"plugin source on entry {index} must be a mapping")
        source_unknown = set(source_value) - {"url", "version"}
        if source_unknown:
            raise JenkinsProjectInputError(
                f"unsupported plugin source key(s) on entry {index}: "
                + ", ".join(sorted(map(str, source_unknown)))
            )
        version = _string_field(source_value.get("version"), field="version", entry=index)
        url = _string_field(source_value.get("url"), field="url", entry=index)
        if version and not (
            _VERSION_TOKEN.fullmatch(version)
            or _INCREMENTAL_VERSION.fullmatch(version)
            or _DYNAMIC_VALUE.search(version)
        ):
            raise JenkinsProjectInputError(f"invalid plugin version on entry {index}")
        if url and not _looks_like_url(url):
            raise JenkinsProjectInputError(f"invalid plugin download URL on entry {index}")
        plugins.append(
            {
                "artifact_id": artifact_id,
                "version": version,
                "url": url,
                "group_id": group_id,
                "location": f"entry.{index}",
                "ambiguous_url": False,
            }
        )
    return {
        "artifact_type": "plugins_yaml",
        "document": {"plugins": _validate_catalog(plugins)},
    }


def parse_jenkins_project(source: str, *, filename: str = "") -> dict[str, Any]:
    """Parse Plugin Installation Manager text or YAML without resolving plugins."""
    if not source.strip():
        raise JenkinsProjectInputError("input is empty")
    suffix = Path(filename).suffix.casefold()
    first = next(
        (
            line.strip()
            for line in source.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ),
        "",
    )
    parsed = (
        _parse_yaml_catalog(source)
        if suffix in {".yaml", ".yml"} or first == "plugins:"
        else _parse_text_catalog(source)
    )
    return {"jenkins_project": parsed}


def _embedded_credentials(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.password or parsed.username)


def _plugin_change(plugin: dict[str, Any]) -> dict[str, str]:
    artifact_id = str(plugin["artifact_id"])
    version = str(plugin["version"])
    url = str(plugin["url"])
    group_id = str(plugin["group_id"])
    lowered_version = version.casefold()
    reasons: list[str] = []
    risk = "review"

    if not version and not url:
        risk = "dangerous"
        reasons.append(
            "No version is specified, so the installer resolves a mutable latest release."
        )
    elif lowered_version == "latest":
        risk = "dangerous"
        reasons.append("The version explicitly follows the mutable latest release.")
    elif lowered_version == "experimental":
        risk = "dangerous"
        reasons.append("The plugin is selected from the experimental update center.")
    elif _DYNAMIC_VALUE.search(version):
        risk = "dangerous"
        reasons.append("The effective version is dynamically interpolated and cannot be pinned.")
    elif lowered_version.startswith("incrementals;"):
        if _INCREMENTAL_VERSION.fullmatch(version):
            reasons.append("The plugin uses a pinned incremental development build.")
        else:
            risk = "dangerous"
            reasons.append("The incremental build coordinate is incomplete or mutable.")
    elif version:
        reasons.append("The requested plugin version is explicit.")

    if url:
        risk = "dangerous"
        parsed = urlsplit(url)
        reasons.append(
            "A direct binary URL bypasses normal update-center location and catalog integrity "
            "metadata."
        )
        if parsed.scheme.casefold() in {"file", "http"}:
            reasons.append("The binary source uses local or plaintext transport.")
        if _embedded_credentials(url):
            reasons.append("The download URL embeds credentials that can leak in logs or metadata.")
        if plugin.get("ambiguous_url"):
            reasons.append(
                "The two-field URL form is ambiguous; use an empty version placeholder before "
                "the URL."
            )

    if group_id:
        reasons.append("A custom Maven group selects the Jenkins incrementals repository path.")
    capability = _PRIVILEGED_PLUGINS.get(artifact_id.casefold())
    if capability:
        reasons.append(f"This plugin extends {capability}, a privileged controller boundary.")

    return {
        "Address": f"jenkins_plugins.{plugin['location']}.{artifact_id}",
        "Kind": "plugin",
        "Risk": risk,
        "Explanation": f"Jenkins installs executable controller plugin {artifact_id!r}. "
        + " ".join(reasons),
    }


class JenkinsProjectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "jenkins-project"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        project = input_data.get("jenkins_project")
        return (
            isinstance(project, dict)
            and project.get("artifact_type") in {"plugins_txt", "plugins_yaml"}
            and isinstance(project.get("document"), dict)
            and isinstance(project["document"].get("plugins"), list)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        plugins = input_data["jenkins_project"]["document"]["plugins"]
        changes = [_plugin_change(plugin) for plugin in plugins]
        changes.append(
            {
                "Address": "jenkins_plugins.effective_set",
                "Kind": "resolution_boundary",
                "Risk": "review",
                "Explanation": (
                    "Effective Jenkins plugin code also depends on the Jenkins core version, "
                    "installed and bundled plugins, update-center metadata, transitive dependency "
                    "selection, security advisories, download hashes, and installer latest-mode "
                    "flags; readtheplan does not contact update centers or download plugins."
                ),
            }
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"jenkins_project_{raw['Kind']}",
            actions=("install",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_jenkins_project(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = JenkinsProjectAdapter().analyze(data, tool_name="Jenkins project")
    summary = PlanSummary(
        path=Path("jenkins-project://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Jenkins project")
    project = data["jenkins_project"]
    gate["adapter"] = "jenkins-project"
    gate["artifact_type"] = project["artifact_type"]
    gate["plugin_count"] = len(project["document"]["plugins"])
    gate["total_changes"] = len(changes)
    return gate
