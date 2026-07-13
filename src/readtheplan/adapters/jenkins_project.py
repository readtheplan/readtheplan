from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class JenkinsProjectInputError(ValueError):
    """Raised when input is not recognizable static Jenkins project configuration."""


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
_MAX_DEFINITIONS = 10_000
_MAX_GROOVY_SOURCE_BYTES = 2 * 1024 * 1024
_SECRET_NAME = re.compile(
    r"(?:password|passwd|token|secret|private.?key|client.?secret|api.?key|credential)",
    re.IGNORECASE,
)
_GROOVY_IDENTIFIER = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*")
_GROOVY_FINDINGS = (
    (
        "dependency_loader",
        "dangerous",
        re.compile(r"(?:@Grab\b|\bGrape\.grab\s*\()"),
        "The shared library loads a third-party JVM dependency into Jenkins' runtime; review "
        "repository trust, artifact integrity, and controller cache effects.",
    ),
    (
        "controller_api",
        "dangerous",
        re.compile(
            r"(?:\bJenkins\s*\.(?:get|instance)\b|\bjenkins\.model\.|\bhudson\.|"
            r"\bScriptApproval\b|\bACL\s*\.)"
        ),
        "The shared library accesses Jenkins or Hudson controller internals that can bypass "
        "ordinary Pipeline abstractions and sandbox boundaries.",
    ),
    (
        "raw_build_api",
        "dangerous",
        re.compile(r"(?:\brawBuild\b|\bgetRawBuild\s*\(|\bgetContext\s*\()"),
        "The shared library accesses raw build or execution context objects with controller-side "
        "capabilities outside the stable Pipeline step boundary.",
    ),
    (
        "dynamic_code",
        "dangerous",
        re.compile(
            r"(?:\bGroovyShell\b|\bEval\.me\s*\(|\bClass\.forName\s*\(|"
            r"\bclassLoader\b|\bmetaClass\b|\bevaluate\s*\(|\bload\s*\()"
        ),
        "The shared library dynamically loads or evaluates code, so the executed behavior cannot "
        "be established from this source alone.",
    ),
    (
        "process_execution",
        "dangerous",
        re.compile(
            r"(?:\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|"
            r"\bProcessBuilder\s*\(|\bSystem\.exit\s*\(|\.execute\s*\()"
        ),
        "The shared library can start a process or terminate a JVM process outside Jenkins' "
        "audited Pipeline command-step boundary.",
    ),
    (
        "agent_command",
        "dangerous",
        re.compile(r"\b(?:sh|bat|powershell|pwsh)\s*(?:\(|\b)"),
        "The shared library invokes a command-capable Pipeline step on a build agent.",
    ),
    (
        "credential_access",
        "dangerous",
        re.compile(r"\b(?:withCredentials|sshagent|credentials)\s*\("),
        "The shared library exposes a Jenkins-managed credential to Pipeline code or agent "
        "processes.",
    ),
    (
        "filesystem_access",
        "dangerous",
        re.compile(
            r"(?:\bnew\s+File\s*\(|\bFile\s*\.(?:newInstance|createTempFile)\s*\(|"
            r"\bFiles\s*\.|\bwriteFile\s*(?:\(|\b)|\bdeleteDir\s*\()"
        ),
        "The shared library reads, writes, or deletes filesystem state; the effective target and "
        "agent/controller location require review.",
    ),
    (
        "network_access",
        "dangerous",
        re.compile(
            r"(?:\bnew\s+(?:URL|URI|Socket)\s*\(|\.openConnection\s*\(|"
            r"\bhttpRequest\s*(?:\(|\b))"
        ),
        "The shared library can communicate across a network trust boundary and may transmit "
        "build data or credentials.",
    ),
    (
        "mutable_global_state",
        "dangerous",
        re.compile(r"(?:^|\s)@Field\b"),
        "A global-variable script declares shared mutable field state; Jenkins may retain the "
        "script object across calls within a build, creating concurrency and serialization risk.",
    ),
    (
        "non_cps",
        "review",
        re.compile(r"(?:^|\s)@NonCPS\b"),
        "The method opts out of Pipeline CPS transformation; Pipeline steps and non-serializable "
        "state must not cross this execution boundary.",
    ),
    (
        "declarative_pipeline",
        "dangerous",
        re.compile(r"\bpipeline\s*\{"),
        "The global variable defines a Declarative Pipeline and can determine an entire job's "
        "execution behavior.",
    ),
    (
        "downstream_build",
        "review",
        re.compile(r"\bbuild\s*(?:\(|job\s*:)"),
        "The shared library can invoke another Jenkins job; review parameter flow, permissions, "
        "and downstream deployment effects.",
    ),
)
_LIBRARY_RESOURCE = re.compile(r"\blibraryResource\s*\(")
_DYNAMIC_LIBRARY_RESOURCE = re.compile(r"\blibraryResource\s*\(\s*[A-Za-z_$]")
_CLASS_DECLARATION = re.compile(r"\bclass\s+[A-Za-z_$][A-Za-z0-9_$]*")
_SERIALIZABLE_CLASS = re.compile(r"\bimplements\s+[^\n{]*\bSerializable\b")
_JJB_DEFINITION_TYPES = {
    "builder",
    "defaults",
    "folder",
    "job",
    "job-group",
    "job-template",
    "notification",
    "parameter",
    "project",
    "property",
    "publisher",
    "reporter",
    "scm",
    "trigger",
    "view",
    "view-template",
    "wrapper",
}
_JJB_STRONG_DEFINITION_TYPES = {
    "folder",
    "job",
    "job-group",
    "job-template",
    "project",
    "view",
    "view-template",
}
_JJB_COMPONENT_SECTIONS = {
    "builders": "builder",
    "notifications": "notification",
    "parameters": "parameter",
    "properties": "property",
    "publishers": "publisher",
    "reporters": "reporter",
    "scm": "scm",
    "triggers": "trigger",
    "wrappers": "wrapper",
}
_COMMAND_COMPONENTS = {
    "ant",
    "batch",
    "conditional-step",
    "gradle",
    "groovy",
    "maven-target",
    "msbuild",
    "powershell",
    "python",
    "ruby",
    "shell",
    "system-groovy",
}
_SECRET_COMPONENTS = {
    "credentials-binding",
    "file",
    "password",
    "secret-text",
    "ssh-agent",
    "username-password",
}
_SIDE_EFFECT_PUBLISHERS = {
    "deploy",
    "email",
    "ftp",
    "postbuildscript",
    "scp",
    "ssh",
    "trigger",
    "trigger-parameterized-builds",
}
_AUTOMATIC_TRIGGERS = {
    "bitbucket",
    "build-result",
    "dockerhub-notification",
    "generic-webhook-trigger",
    "gerrit",
    "github",
    "github-pull-request",
    "gitlab",
    "pollscm",
    "reverse-build",
    "timed",
}


@dataclass(frozen=True)
class _JJBTaggedValue:
    tag: str
    value: Any


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    keys: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
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


def _construct_jjb_tag(
    loader: _UniqueKeyLoader,
    tag_suffix: str,
    node: yaml.Node,
) -> _JJBTaggedValue:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    elif isinstance(node, yaml.MappingNode):
        value = _construct_unique_mapping(loader, node, deep=True)
    else:  # pragma: no cover - PyYAML currently exposes only these node types
        raise JenkinsProjectInputError("unsupported YAML tag value")
    return _JJBTaggedValue(tag=f"!{tag_suffix}", value=value)


def _construct_python_tuple(
    loader: _UniqueKeyLoader,
    node: yaml.SequenceNode,
) -> list[Any]:
    """Read JJB's documented tuple syntax as inert sequence data."""
    return loader.construct_sequence(node, deep=True)


_UniqueKeyLoader.add_multi_constructor("!", _construct_jjb_tag)
_UniqueKeyLoader.add_constructor(
    "tag:yaml.org,2002:python/tuple",
    _construct_python_tuple,
)


def _load_yaml(source: str) -> Any:
    try:
        return yaml.load(source, Loader=_UniqueKeyLoader)  # noqa: S506
    except JenkinsProjectInputError:
        raise
    except yaml.YAMLError as exc:
        raise JenkinsProjectInputError(str(exc)) from exc


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JenkinsProjectInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


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
    document = _load_yaml(source)
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


def _definition_name(body: dict[str, Any], *, kind: str, entry: int) -> str:
    value = body.get("id", body.get("name"))
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise JenkinsProjectInputError(
            f"Jenkins Job Builder {kind} definition {entry} requires a scalar name or id"
        )
    name = str(value).strip()
    if not name:
        raise JenkinsProjectInputError(
            f"Jenkins Job Builder {kind} definition {entry} has an empty name or id"
        )
    return name


def _parse_job_builder_document(document: Any, *, artifact_type: str) -> dict[str, Any]:
    if not isinstance(document, list):
        raise JenkinsProjectInputError("Jenkins Job Builder input must be a list of definitions")
    if not document:
        raise JenkinsProjectInputError("Jenkins Job Builder input does not contain definitions")
    if len(document) > _MAX_DEFINITIONS:
        raise JenkinsProjectInputError(
            f"Jenkins Job Builder input exceeds {_MAX_DEFINITIONS} definitions"
        )

    definitions: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], int] = {}
    strong_definition = False
    for entry, item in enumerate(document, start=1):
        if not isinstance(item, dict) or len(item) != 1:
            raise JenkinsProjectInputError(
                f"Jenkins Job Builder definition {entry} must be a one-key mapping"
            )
        raw_kind, body = next(iter(item.items()))
        if not isinstance(raw_kind, str):
            raise JenkinsProjectInputError(
                f"Jenkins Job Builder definition {entry} type must be a string"
            )
        kind = raw_kind.casefold()
        if kind.startswith("_"):
            continue
        if kind not in _JJB_DEFINITION_TYPES:
            raise JenkinsProjectInputError(
                f"unsupported Jenkins Job Builder definition type on entry {entry}: {raw_kind}"
            )
        if not isinstance(body, dict):
            raise JenkinsProjectInputError(
                f"Jenkins Job Builder {kind} definition {entry} must be a mapping"
            )
        name = _definition_name(body, kind=kind, entry=entry)
        identity = (kind, name.casefold())
        if identity in seen:
            raise JenkinsProjectInputError(
                f"duplicate Jenkins Job Builder {kind} name on entries "
                f"{seen[identity]} and {entry}"
            )
        seen[identity] = entry
        definitions.append(
            {
                "kind": kind,
                "body": body,
                "location": f"definition.{entry}",
            }
        )
        strong_definition = strong_definition or kind in _JJB_STRONG_DEFINITION_TYPES

    if not definitions or not strong_definition:
        raise JenkinsProjectInputError(
            "input does not contain a Jenkins Job Builder job, project, folder, or view definition"
        )
    return {
        "artifact_type": artifact_type,
        "document": {"definitions": definitions},
    }


def _parse_job_builder_yaml(source: str) -> dict[str, Any]:
    return _parse_job_builder_document(
        _load_yaml(source),
        artifact_type="job_builder_yaml",
    )


def _parse_job_builder_json(source: str) -> dict[str, Any]:
    try:
        document = json.loads(source, object_pairs_hook=_json_object)
    except JenkinsProjectInputError:
        raise
    except json.JSONDecodeError as exc:
        raise JenkinsProjectInputError(str(exc)) from exc
    return _parse_job_builder_document(document, artifact_type="job_builder_json")


def _mask_groovy_comments_and_strings(
    source: str,
) -> tuple[str, list[tuple[int, str, bool]]]:
    """Mask Groovy comments and quoted strings while preserving offsets and lines."""
    output = list(source)
    literals: list[tuple[int, str, bool]] = []
    state = "code"
    quote = ""
    triple = False
    literal: list[str] = []
    literal_line = 1
    line = 1
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and following == "/":
                output[index] = output[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == "/" and following == "*":
                output[index] = output[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char in {"'", '"'}:
                quote = char
                triple = source.startswith(char * 3, index)
                width = 3 if triple else 1
                for offset in range(width):
                    output[index + offset] = " "
                literal = []
                literal_line = line
                state = "string"
                index += width
                continue
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block_comment":
            if char == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                output[index] = " "
        else:
            width = 3 if triple else 1
            if source.startswith(quote * width, index):
                for offset in range(width):
                    output[index + offset] = " "
                value = "".join(literal)
                interpolated = quote == '"' and bool(
                    re.search(r"(?:\$\{|\$[A-Za-z_])", value)
                )
                literals.append((literal_line, value, interpolated))
                state = "code"
                index += width
                continue
            output[index] = "\n" if char == "\n" else " "
            if char == "\\" and index + 1 < len(source):
                literal.extend((char, source[index + 1]))
                if source[index + 1] == "\n":
                    line += 1
                    output[index + 1] = "\n"
                else:
                    output[index + 1] = " "
                index += 2
                continue
            literal.append(char)
        if char == "\n":
            line += 1
        index += 1
    if state == "string":
        raise JenkinsProjectInputError("unterminated Groovy string")
    if state == "block_comment":
        raise JenkinsProjectInputError("unterminated Groovy block comment")
    return "".join(output), literals


def _parse_shared_library(source: str, *, filename: str) -> dict[str, Any]:
    if len(source.encode("utf-8")) > _MAX_GROOVY_SOURCE_BYTES:
        raise JenkinsProjectInputError("Groovy input exceeds the static-analysis size limit")
    normalized = filename.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.suffix.casefold() != ".groovy":
        raise JenkinsProjectInputError("shared library source must use a .groovy filename")
    directories = tuple(part.casefold() for part in path.parts[:-1])
    under_vars = "vars" in directories
    under_src = "src" in directories
    if under_vars == under_src:
        raise JenkinsProjectInputError(
            "Groovy input must be identified by exactly one shared-library vars/ or src/ path"
        )
    if under_vars and directories[-1] != "vars":
        raise JenkinsProjectInputError("shared-library vars Groovy files cannot be nested")
    _mask_groovy_comments_and_strings(source)
    return {
        "artifact_type": "shared_library_var" if under_vars else "shared_library_class",
        "document": {
            "source": source,
            "line_count": len(source.splitlines()),
        },
    }


def parse_jenkins_project(source: str, *, filename: str = "") -> dict[str, Any]:
    """Parse Jenkins project artifacts without rendering templates or executing source."""
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
    if suffix == ".groovy":
        parsed = _parse_shared_library(source, filename=filename)
    elif suffix == ".json":
        parsed = _parse_job_builder_json(source)
    elif suffix in {".yaml", ".yml"} or first == "plugins:" or first.startswith("-"):
        document = _load_yaml(source)
        if isinstance(document, dict) and set(document) == {"plugins"}:
            parsed = _parse_yaml_catalog(source)
        else:
            parsed = _parse_job_builder_document(document, artifact_type="job_builder_yaml")
    else:
        parsed = _parse_text_catalog(source)
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
        "Action": "install",
        "Risk": risk,
        "Explanation": f"Jenkins installs executable controller plugin {artifact_id!r}. "
        + " ".join(reasons),
    }


def _iter_fields(value: Any):
    if isinstance(value, _JJBTaggedValue):
        yield "__tag__", value.tag
        yield from _iter_fields(value.value)
    elif isinstance(value, dict):
        for key, child in value.items():
            yield str(key).casefold(), child
            yield from _iter_fields(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_fields(child)


def _scalar_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for child in value for item in _scalar_strings(child)]
    return []


def _component_type(value: Any) -> str:
    if isinstance(value, dict) and value:
        return str(next(iter(value))).casefold()
    if isinstance(value, str):
        return "macro"
    if isinstance(value, _JJBTaggedValue):
        return "tagged"
    return "unknown"


def _has_truthy_field(value: Any, names: set[str]) -> bool:
    for key, child in _iter_fields(value):
        if key in names and child is True:
            return True
    return False


def _definition_change(definition: dict[str, Any]) -> dict[str, str]:
    kind = str(definition["kind"])
    body = definition["body"]
    risk = "review"
    reasons = ["The definition creates or updates Jenkins controller-managed job configuration."]

    if kind in {"job-template", "project", "job-group", "view-template"}:
        reasons.append("Template expansion and inherited defaults determine the effective objects.")
    if kind == "project":
        combinations = 1
        dimensions = 0
        for key, value in body.items():
            if key in {"exclude", "jobs", "name", "templates"} or not isinstance(value, list):
                continue
            dimensions += 1
            combinations *= max(len(value), 1)
            if combinations > 64:
                risk = "dangerous"
                reasons.append(
                    "Project list variables can expand to more than 64 job combinations before "
                    "exclusions are applied."
                )
                break
        if dimensions:
            reasons.append("Project list variables expand as a Cartesian product.")
    if kind in {"job-template", "view-template"}:
        name = body.get("name", "")
        if isinstance(name, str) and "{" not in name:
            reasons.append("The template name has no visible substitution variable.")
    for key, value in _iter_fields(body):
        if key in {"auth-token", "authentication-token"}:
            risk = "dangerous"
            reasons.append("The definition configures a remotely usable authentication token.")
            break
        if key in {"custom-workspace", "workspace"} and value:
            risk = "dangerous"
            reasons.append("The job selects a custom workspace path on its build agent.")
            break
    for key, value in body.items():
        if key.casefold() in {"node", "assigned-node"} and isinstance(value, str):
            if value.strip().casefold() in {"built-in", "master"}:
                risk = "dangerous"
                reasons.append("The job explicitly targets the Jenkins controller for execution.")
        if key.casefold() == "concurrent" and value is True:
            reasons.append("Concurrent builds can race over shared external or workspace state.")
    project_type = str(body.get("project-type", "")).casefold()
    if project_type in {"pipeline", "workflow"} and "dsl" in body:
        risk = "dangerous"
        reasons.append("The job contains inline Pipeline Groovy that executes as build logic.")
        if body.get("sandbox") is False:
            reasons.append("The inline Pipeline explicitly disables the Groovy sandbox.")

    return {
        "Address": f"jenkins_job_builder.{definition['location']}.{kind}",
        "Kind": "definition",
        "Action": "configure",
        "Risk": risk,
        "Explanation": " ".join(reasons),
    }


def _scm_component_risk(value: Any) -> tuple[str, list[str]]:
    risk = "review"
    reasons = ["The SCM component selects external source code used by a Jenkins job."]
    for key, child in _iter_fields(value):
        if key in {"url", "repository", "repo", "remote"}:
            for candidate in _scalar_strings(child):
                if _DYNAMIC_VALUE.search(candidate):
                    risk = "dangerous"
                    reasons.append("The repository location is dynamically interpolated.")
                try:
                    parsed = urlsplit(candidate)
                except ValueError:
                    continue
                if parsed.scheme.casefold() in {"file", "http"}:
                    risk = "dangerous"
                    reasons.append("A repository uses local or plaintext transport.")
                if parsed.username or parsed.password:
                    risk = "dangerous"
                    reasons.append("A repository URL embeds credentials.")
        if key in {"branch", "branches", "ref", "refspec", "revision"}:
            for candidate in _scalar_strings(child):
                normalized = candidate.strip()
                if not re.fullmatch(r"[0-9a-fA-F]{40,64}", normalized):
                    risk = "dangerous"
                    reasons.append("The selected SCM revision is mutable or dynamically resolved.")
                    break
        if key in {"credentials-id", "credential-id"} and child:
            reasons.append("The checkout exposes a managed Jenkins credential to SCM operations.")
    return risk, list(dict.fromkeys(reasons))


def _component_change(
    definition: dict[str, Any],
    section: str,
    index: int,
    value: Any,
) -> dict[str, str]:
    kind = _JJB_COMPONENT_SECTIONS[section]
    component_type = _component_type(value)
    risk = "review"
    reasons = [f"The Jenkins Job Builder {kind} component changes job behavior."]

    if kind == "builder":
        risk = "dangerous"
        reasons.append("Build steps can execute code on a Jenkins agent.")
        if component_type not in _COMMAND_COMPONENTS and component_type != "raw":
            reasons.append("Plugin-provided builder behavior remains an external code boundary.")
    elif kind == "trigger":
        if component_type in _AUTOMATIC_TRIGGERS or component_type in {"macro", "unknown"}:
            risk = "dangerous"
            reasons.append(
                "The trigger can start builds automatically from time or external events."
            )
    elif kind == "publisher":
        if component_type in _SIDE_EFFECT_PUBLISHERS:
            risk = "dangerous"
            reasons.append("The publisher can send data or trigger changes outside the build.")
    elif kind == "wrapper":
        if component_type in _SECRET_COMPONENTS:
            risk = "dangerous"
            reasons.append("The wrapper exposes managed credentials or secret material to a build.")
        if _has_truthy_field(value, {"privileged"}):
            risk = "dangerous"
            reasons.append("The wrapper enables privileged execution.")
    elif kind == "parameter":
        if component_type in _SECRET_COMPONENTS or "credential" in component_type:
            risk = "dangerous"
            reasons.append("The parameter crosses a Jenkins credential or secret boundary.")
    elif kind == "property":
        if component_type in {"authorization", "auth-token", "ownership"}:
            risk = "dangerous"
            reasons.append("The property changes job authorization or remote invocation controls.")
    elif kind == "scm":
        risk, reasons = _scm_component_risk(value)

    if component_type == "raw":
        risk = "dangerous"
        reasons.append("Raw XML bypasses JJB's typed module validation and plugin abstractions.")

    return {
        "Address": (
            f"jenkins_job_builder.{definition['location']}.{section}.{index}"
        ),
        "Kind": kind,
        "Action": "configure",
        "Risk": risk,
        "Explanation": " ".join(dict.fromkeys(reasons)),
    }


def _tag_changes(definition: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for key, value in _iter_fields(definition["body"]):
        if key != "__tag__" or not isinstance(value, str):
            continue
        normalized = value.casefold()
        dangerous = any(token in normalized for token in ("raw", "jinja", "j2"))
        explanation = (
            "A Jenkins Job Builder custom YAML tag references or transforms content that "
            "readtheplan intentionally does not load or render."
        )
        if dangerous:
            explanation += " The tag can inject templated or executable source into a job."
        changes.append(
            {
                "Address": (
                    f"jenkins_job_builder.{definition['location']}.external_source."
                    f"{len(changes) + 1}"
                ),
                "Kind": "external_source",
                "Action": "configure",
                "Risk": "dangerous" if dangerous else "review",
                "Explanation": explanation,
            }
        )
    return changes


def _job_builder_changes(definitions: list[dict[str, Any]]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for definition in definitions:
        changes.append(_definition_change(definition))
        body = definition["body"]
        for section in _JJB_COMPONENT_SECTIONS:
            if section not in body:
                continue
            raw_components = body[section]
            if isinstance(raw_components, list):
                components = raw_components
            else:
                components = [raw_components]
            for index, value in enumerate(components, start=1):
                changes.append(_component_change(definition, section, index, value))
        changes.extend(_tag_changes(definition))
    changes.append(
        {
            "Address": "jenkins_job_builder.effective_configuration",
            "Kind": "resolution_boundary",
            "Action": "configure",
            "Risk": "review",
            "Explanation": (
                "Effective Jenkins jobs also depend on included files, template/default and macro "
                "expansion, JJB and plugin versions, installed controller plugins, credentials, "
                "Jenkins permissions, and live controller state; readtheplan does not resolve or "
                "execute those inputs."
            ),
        }
    )
    return changes


def _shared_library_change(
    line: int,
    kind: str,
    risk: str,
    explanation: str,
) -> dict[str, str]:
    return {
        "Address": f"jenkins_shared_library.line.{line}.{kind}",
        "Kind": kind,
        "Action": "execute",
        "Risk": risk,
        "Explanation": explanation,
    }


def _has_secret_assignment(line: str) -> bool:
    for match in _GROOVY_IDENTIFIER.finditer(line):
        if not _SECRET_NAME.search(match.group()):
            continue
        remainder = line[match.end() :].lstrip()
        if remainder.startswith("=") and not remainder.startswith("=="):
            return True
    return False


def _shared_library_changes(source: str, *, artifact_type: str) -> list[dict[str, str]]:
    code, literals = _mask_groovy_comments_and_strings(source)
    literal_lines = {line_number for line_number, _, _ in literals}
    changes: list[dict[str, str]] = [
        _shared_library_change(
            1,
            "executable_source",
            "review",
            (
                "This file defines executable Jenkins Shared Library Groovy. Its effective "
                "privileges depend on global or folder library configuration, SCM ownership, "
                "sandboxing, and script approvals."
            ),
        )
    ]
    for line_number, line in enumerate(code.splitlines(), start=1):
        for kind, risk, pattern, explanation in _GROOVY_FINDINGS:
            if pattern.search(line):
                changes.append(_shared_library_change(line_number, kind, risk, explanation))
        if _LIBRARY_RESOURCE.search(line):
            dynamic = bool(_DYNAMIC_LIBRARY_RESOURCE.search(line))
            changes.append(
                _shared_library_change(
                    line_number,
                    "library_resource",
                    "dangerous" if dynamic else "review",
                    (
                        "The resource path is computed at runtime, so static analysis cannot "
                        "establish which bundled content will be loaded."
                        if dynamic
                        else "The shared library loads bundled resource content; review its "
                        "integrity, sensitivity, and subsequent use."
                    ),
                )
            )
        if line_number in literal_lines and _has_secret_assignment(line):
            changes.append(
                _shared_library_change(
                    line_number,
                    "literal_secret",
                    "dangerous",
                    "A credential-like variable is assigned a literal value in shared-library "
                    "source; the identifier and value are intentionally redacted.",
                )
            )

    for line_number, literal, interpolated in literals:
        if _SECRET_NAME.search(literal) and re.search(r"[:=]", literal):
            changes.append(
                _shared_library_change(
                    line_number,
                    "literal_secret",
                    "dangerous",
                    "Shared-library source contains a credential-like literal; its contents are "
                    "intentionally redacted.",
                )
            )
        if interpolated:
            changes.append(
                _shared_library_change(
                    line_number,
                    "runtime_interpolation",
                    "review",
                    "A double-quoted Groovy value is computed from runtime state; review the "
                    "effective command, path, endpoint, or data flow.",
                )
            )

    if artifact_type == "shared_library_class":
        class_match = _CLASS_DECLARATION.search(code)
        if class_match and not _SERIALIZABLE_CLASS.search(code):
            line_number = code.count("\n", 0, class_match.start()) + 1
            changes.append(
                _shared_library_change(
                    line_number,
                    "cps_serialization",
                    "review",
                    "A shared-library class does not visibly implement Serializable; retained "
                    "instances or Pipeline state may fail across CPS suspension and restart.",
                )
            )

    changes.append(
        {
            "Address": "jenkins_shared_library.effective_execution",
            "Kind": "resolution_boundary",
            "Action": "execute",
            "Risk": "review",
            "Explanation": (
                "Effective Shared Library behavior also depends on library trust level, SCM "
                "revision and ownership, implicit loading and version override settings, folder "
                "permissions, controller plugins, sandbox approvals, replay, CPS transformation, "
                "bundled resources, credentials, and runtime values; readtheplan does not contact "
                "Jenkins or execute Groovy."
            ),
        }
    )
    unique: dict[tuple[str, str], dict[str, str]] = {}
    for change in changes:
        unique[(change["Address"], change["Kind"])] = change
    return list(unique.values())


class JenkinsProjectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "jenkins-project"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        project = input_data.get("jenkins_project")
        if not isinstance(project, dict) or not isinstance(project.get("document"), dict):
            return False
        artifact_type = project.get("artifact_type")
        if artifact_type in {"plugins_txt", "plugins_yaml"}:
            return isinstance(project["document"].get("plugins"), list)
        if artifact_type in {"job_builder_yaml", "job_builder_json"}:
            return isinstance(project["document"].get("definitions"), list)
        if artifact_type in {"shared_library_var", "shared_library_class"}:
            return isinstance(project["document"].get("source"), str)
        return False

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        project = input_data["jenkins_project"]
        if project["artifact_type"] in {"job_builder_yaml", "job_builder_json"}:
            return _job_builder_changes(project["document"]["definitions"])
        if project["artifact_type"] in {"shared_library_var", "shared_library_class"}:
            return _shared_library_changes(
                project["document"]["source"],
                artifact_type=project["artifact_type"],
            )
        plugins = project["document"]["plugins"]
        changes = [_plugin_change(plugin) for plugin in plugins]
        changes.append(
            {
                "Address": "jenkins_plugins.effective_set",
                "Kind": "resolution_boundary",
                "Action": "install",
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
            actions=(str(raw["Action"]),),
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
    if project["artifact_type"] in {"plugins_txt", "plugins_yaml"}:
        gate["plugin_count"] = len(project["document"]["plugins"])
    elif project["artifact_type"] in {"job_builder_yaml", "job_builder_json"}:
        definitions = project["document"]["definitions"]
        gate["definition_count"] = len(definitions)
        gate["job_count"] = sum(
            definition["kind"] in {"job", "job-template"} for definition in definitions
        )
    else:
        gate["source_kind"] = (
            "global_variable"
            if project["artifact_type"] == "shared_library_var"
            else "class"
        )
        gate["source_line_count"] = project["document"]["line_count"]
    gate["total_changes"] = len(changes)
    return gate
