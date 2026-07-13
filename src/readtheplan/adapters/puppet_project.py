from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters._puppet_hocon import PuppetHoconError, parse_puppet_hocon
from readtheplan.adapters.base import BaseAdapter
from readtheplan.adapters.bolt_content import (
    BoltContentInputError,
    bolt_content_metadata,
    bolt_task_metadata_changes,
    bolt_yaml_plan_changes,
    is_bolt_task_metadata,
    is_bolt_yaml_plan,
    parse_bolt_task_metadata,
    parse_bolt_yaml_plan,
)
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class PuppetProjectInputError(ValueError):
    """Raised when input is not recognizable Puppet project configuration."""


_CALL = re.compile(r"^\s*(?P<name>[a-z_][a-z0-9_]*)\s*(?P<args>.*?)\s*$", re.IGNORECASE)
_OPTION_KEY = re.compile(
    r"(?::(?P<rocket>[a-z_][a-z0-9_]*)\s*=>|(?P<modern>[a-z_][a-z0-9_]*)\s*:)[ \t]*",
    re.IGNORECASE,
)
_COMMIT = re.compile(r"[0-9a-f]{40,64}$", re.IGNORECASE)
_EXACT_VERSION = re.compile(r"v?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?$")
_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|client.?secret|api.?key|credential)",
    re.IGNORECASE,
)
_RUBY_EXECUTION = re.compile(
    r"(?:^|\W)(?:eval|exec|spawn|system|require|load|IO\.popen|Open3\.)\s*(?:\(|['\"])"
    r"|`[^`]+`|%x\s*\W"
)
_RUBY_DYNAMIC = re.compile(
    r"(?:ENV\s*\[|File\.|Dir\.|\#\{|\.each\b|\bif\b|\bunless\b|\bcase\b|\bbegin\b)"
)
_BUILTIN_DATA_HASHES = {"json_data", "yaml_data"}
_BUILTIN_LOOKUP_KEYS = {"eyaml_lookup_key"}
_PUPPET_CONFIG_SECTIONS = {"main", "server", "agent", "user"}
_PUPPET_CONFIG_SETTING = re.compile(
    r"^[ \t]*(?P<name>[a-z_][a-z0-9_]*)[ \t]*=[ \t]*(?P<value>.*)$",
    re.IGNORECASE,
)
_PUPPET_SECRET_SETTINGS = {
    "forge_authorization",
    "http_proxy_password",
    "password",
    "passphrase",
    "token",
}
_PUPPET_COMMAND_SETTINGS = {
    "config_version",
    "diff",
    "external_nodes",
    "postrun_command",
    "prerun_command",
    "trusted_external_command",
}
_PUPPET_CODE_PATH_SETTINGS = {
    "basemodulepath",
    "binder_config",
    "codedir",
    "default_manifest",
    "environmentpath",
    "factpath",
    "hiera_config",
    "libdir",
    "manifest",
    "modulepath",
    "pluginsource",
    "route_file",
    "vendormoduledir",
}
_PUPPET_ENDPOINT_SETTINGS = {
    "ca_server",
    "http_proxy_host",
    "report_server",
    "server",
    "server_list",
}
_PUPPET_IDENTITY_SETTINGS = {
    "certname",
    "node_name_fact",
    "node_name_value",
    "user",
    "group",
}
_PUPPET_TERMINUS_SETTINGS = {
    "catalog_cache_terminus",
    "catalog_terminus",
    "data_binding_terminus",
    "node_cache_terminus",
    "node_terminus",
    "storeconfigs_backend",
}
_PUPPET_BUILTIN_REPORTS = {"console", "http", "log", "puppetdb", "store"}
_METADATA_REQUIRED = {
    "author",
    "dependencies",
    "license",
    "name",
    "source",
    "summary",
    "version",
}
_R10K_ROOT_KEYS = {
    "cachedir",
    "deploy",
    "deploy_settings",
    "forge",
    "forge_settings",
    "git",
    "git_settings",
    "logging",
    "pool_size",
    "postrun",
    "proxy",
    "purgedirs",
    "remote",
    "r10k_basedir",
    "sources",
}
_R10K_SOURCE_KEYS = {
    "basedir",
    "command",
    "filter_command",
    "ignore_branch_prefixes",
    "invalid_branches",
    "overrides",
    "prefix",
    "puppetfile_name",
    "remote",
    "strip_component",
    "type",
}
_R10K_GIT_KEYS = {
    "default_ref",
    "github_app_id",
    "github_app_key",
    "github_app_ttl",
    "oauth_token",
    "private_key",
    "provider",
    "proxy",
    "repositories",
    "username",
}
_R10K_REPOSITORY_KEYS = {
    "github_app_id",
    "github_app_key",
    "github_app_ttl",
    "ignore_branch_prefixes",
    "oauth_token",
    "private_key",
    "proxy",
    "remote",
}
_R10K_FORGE_KEYS = {
    "allow_puppetfile_override",
    "authorization_token",
    "baseurl",
    "proxy",
}
_R10K_DEPLOY_KEYS = {
    "exclude_spec",
    "generate_types",
    "puppet_conf",
    "puppet_path",
    "purge_allowlist",
    "purge_levels",
    "write_lock",
}
_R10K_LOGGING_KEYS = {"disable_default_stderr", "level", "outputs"}
_R10K_DYNAMIC = re.compile(r"(?:\$\{|%\{|\{\{|<%|\$[A-Za-z_])")
_PUPPET_SERVER_HOCON_FILES = {
    "auth.conf": "server_auth",
    "ca.conf": "server_ca",
    "puppetserver.conf": "server_runtime",
    "web-routes.conf": "server_routes",
    "webserver.conf": "server_web",
}
_ENVIRONMENT_SETTINGS = {"config_version", "environment_timeout", "manifest", "modulepath"}


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    explicit_keys: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in explicit_keys
        except TypeError as exc:
            raise PuppetProjectInputError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise PuppetProjectInputError(f"duplicate YAML key: {key}")
        explicit_keys.add(key)
    loader.flatten_mapping(node)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PuppetProjectInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strip_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
        elif char == "#" and quote is None:
            return line[:index]
    return line


def _contains_unquoted(line: str, needle: str) -> bool:
    quote: str | None = None
    escaped = False
    for char in line:
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
        elif char == needle and quote is None:
            return True
    return False


def _read_quoted(text: str, start: int) -> tuple[str, int] | None:
    if start >= len(text) or text[start] not in {"'", '"'}:
        return None
    quote = text[start]
    value: list[str] = []
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == quote:
            return "".join(value), index + 1
        if char == "\\" and index + 1 < len(text):
            value.extend((char, text[index + 1]))
            index += 2
            continue
        value.append(char)
        index += 1
    return None


def _quoted_values(text: str) -> list[str]:
    values: list[str] = []
    index = 0
    while index < len(text):
        if text[index] not in {"'", '"'}:
            index += 1
            continue
        parsed = _read_quoted(text, index)
        if parsed is None:
            break
        value, index = parsed
        values.append(value)
    return values


def _options(text: str) -> dict[str, str]:
    options: dict[str, str] = {}
    for match in _OPTION_KEY.finditer(text):
        parsed = _read_quoted(text, match.end())
        if parsed is not None:
            key = match.group("rocket") or match.group("modern")
            options[key.lower()] = parsed[0]
    return options


def _parse_puppetfile(source: str) -> dict[str, Any]:
    calls: list[dict[str, Any]] = []
    dynamic: list[dict[str, Any]] = []
    buffered = ""
    buffered_line = 0
    for line_number, original in enumerate(source.splitlines(), start=1):
        line = _strip_comment(original).strip()
        if not line:
            continue
        if buffered:
            buffered = f"{buffered} {line}"
        else:
            buffered = line
            buffered_line = line_number
        if line.endswith(","):
            continue
        match = _CALL.match(buffered)
        if not match:
            dynamic.append({"line": buffered_line, "source": buffered})
            buffered = ""
            continue
        name = match.group("name").lower()
        args = match.group("args")
        if name in {"forge", "mod", "moduledir"}:
            calls.append(
                {
                    "name": name,
                    "args": args,
                    "values": _quoted_values(args),
                    "options": _options(args),
                    "line": buffered_line,
                }
            )
            if (
                _RUBY_EXECUTION.search(args)
                or _RUBY_DYNAMIC.search(args)
                or _contains_unquoted(args, ";")
            ):
                dynamic.append({"line": buffered_line, "source": args})
        else:
            dynamic.append({"line": buffered_line, "source": buffered})
        buffered = ""
    if buffered:
        dynamic.append({"line": buffered_line, "source": buffered})
    if not any(call["name"] in {"forge", "mod", "moduledir"} for call in calls):
        raise PuppetProjectInputError("input is not a recognized Puppetfile")
    return {"artifact_type": "puppetfile", "document": {"calls": calls, "dynamic": dynamic}}


def _parse_json(source: str) -> dict[str, Any] | None:
    if not source.lstrip().startswith("{"):
        return None
    try:
        document = json.loads(source, object_pairs_hook=_unique_object)
    except PuppetProjectInputError:
        raise
    except json.JSONDecodeError as exc:
        raise PuppetProjectInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise PuppetProjectInputError("Puppet project JSON must be an object")
    metadata_shape = {"name", "version"} <= set(document) and bool(
        {"author", "dependencies", "license", "source", "summary"} & set(document)
    )
    if metadata_shape:
        _validate_metadata(document)
        return {"artifact_type": "metadata", "document": document}
    if {"version", "hierarchy", "defaults", "default_hierarchy"} & set(document):
        _validate_hiera(document)
        return {"artifact_type": "hiera", "document": document}
    raise PuppetProjectInputError("JSON is not recognized as Puppet metadata or Hiera config")


def _validate_metadata(document: dict[str, Any]) -> None:
    for key in ("dependencies", "requirements", "operatingsystem_support"):
        if key in document and not isinstance(document[key], list):
            raise PuppetProjectInputError(f"metadata {key} must be a JSON list")
    for key in ("dependencies", "requirements"):
        for index, item in enumerate(document.get(key, []), start=1):
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise PuppetProjectInputError(f"metadata {key} item {index} must have a name")
            if "version_requirement" in item and not isinstance(item["version_requirement"], str):
                raise PuppetProjectInputError(
                    f"metadata {key} item {index} version_requirement must be a string"
                )


def _parse_hiera(source: str) -> dict[str, Any]:
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except PuppetProjectInputError:
        raise
    except yaml.YAMLError as exc:
        raise PuppetProjectInputError(str(exc)) from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise PuppetProjectInputError("Hiera input must contain one YAML mapping")
    document = documents[0]
    if not ({"version", "hierarchy", "defaults", "default_hierarchy"} & set(document)):
        raise PuppetProjectInputError("input is not recognized as hiera.yaml")
    _validate_hiera(document)
    return {"artifact_type": "hiera", "document": document}


def _parse_bolt_yaml(source: str, artifact_type: str) -> dict[str, Any]:
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except PuppetProjectInputError:
        raise
    except yaml.YAMLError as exc:
        raise PuppetProjectInputError(str(exc)) from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise PuppetProjectInputError("Bolt input must contain one YAML mapping")
    document = documents[0]
    if artifact_type == "bolt_project":
        for key in (
            "apply-settings",
            "future",
            "log",
            "module-install",
            "plugin-cache",
            "plugin-hooks",
            "plugins",
            "puppetdb",
            "puppetdb-instances",
        ):
            if key in document and not isinstance(document[key], dict):
                raise PuppetProjectInputError(f"Bolt project {key} must be a mapping")
        for key in ("disable-warnings", "modules", "plans", "policies", "tasks"):
            if key in document and not isinstance(document[key], list):
                raise PuppetProjectInputError(f"Bolt project {key} must be a list")
        if "modulepath" in document and not isinstance(document["modulepath"], (str, list)):
            raise PuppetProjectInputError("Bolt project modulepath must be a string or list")
    else:
        allowed = {"config", "facts", "features", "groups", "targets", "vars", "version"}
        unknown = set(document) - allowed
        if unknown:
            raise PuppetProjectInputError(
                "unsupported top-level Bolt inventory key(s): "
                + ", ".join(sorted(map(str, unknown)))
            )
        for key in ("config", "facts", "vars"):
            if key in document and not isinstance(document[key], dict):
                raise PuppetProjectInputError(f"Bolt inventory {key} must be a mapping")
        if "features" in document and not (
            isinstance(document["features"], list)
            or (
                isinstance(document["features"], dict)
                and isinstance(document["features"].get("_plugin"), str)
            )
        ):
            raise PuppetProjectInputError(
                "Bolt inventory features must be a list or plugin mapping"
            )
        for key in ("groups", "targets"):
            value = document.get(key, [])
            if not isinstance(value, (list, dict)):
                raise PuppetProjectInputError(
                    f"Bolt inventory {key} must be a list or plugin mapping"
                )
        _validate_bolt_inventory_group(document, "inventory", require_name=False)
    return {"artifact_type": artifact_type, "document": document}


def _r10k_mapping(
    document: dict[str, Any],
    key: str,
    *,
    allowed: set[str],
) -> dict[str, Any]:
    value = document.get(key, {})
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise PuppetProjectInputError(f"r10k {key} must be a mapping")
    unknown = set(value) - allowed
    if unknown:
        raise PuppetProjectInputError(
            f"unsupported r10k {key} key(s): " + ", ".join(sorted(map(str, unknown)))
        )
    return value


def _r10k_scalar(value: Any, *, address: str) -> None:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise PuppetProjectInputError(f"r10k {address} must be a scalar value")


def _validate_r10k_source(name: Any, source: Any, index: int) -> None:
    if not isinstance(name, str) or not name.strip():
        raise PuppetProjectInputError(f"r10k source {index} must have a non-empty string name")
    if not isinstance(source, dict):
        raise PuppetProjectInputError(f"r10k source {index} must be a mapping")
    unknown = set(source) - _R10K_SOURCE_KEYS
    if unknown:
        raise PuppetProjectInputError(
            f"unsupported r10k source key(s) on entry {index}: "
            + ", ".join(sorted(map(str, unknown)))
        )
    source_type = source.get("type", "git")
    if not isinstance(source_type, str):
        raise PuppetProjectInputError(f"r10k source {index} type must be a string")
    if source_type.casefold() == "git" and not isinstance(source.get("remote"), str):
        raise PuppetProjectInputError(f"r10k Git source {index} requires a string remote")
    if not isinstance(source.get("basedir"), str):
        raise PuppetProjectInputError(f"r10k source {index} requires a string basedir")
    for key in (
        "command",
        "filter_command",
        "invalid_branches",
        "puppetfile_name",
        "remote",
        "strip_component",
    ):
        if key in source and not isinstance(source[key], str):
            raise PuppetProjectInputError(f"r10k source {index} {key} must be a string")
    if "prefix" in source and not isinstance(source["prefix"], (bool, str)):
        raise PuppetProjectInputError(f"r10k source {index} prefix must be a boolean or string")
    if "ignore_branch_prefixes" in source and not (
        isinstance(source["ignore_branch_prefixes"], list)
        and all(isinstance(item, str) for item in source["ignore_branch_prefixes"])
    ):
        raise PuppetProjectInputError(
            f"r10k source {index} ignore_branch_prefixes must be a string list"
        )
    if "overrides" in source and not isinstance(source["overrides"], dict):
        raise PuppetProjectInputError(f"r10k source {index} overrides must be a mapping")


def _validate_r10k_git(document: dict[str, Any]) -> None:
    git = _r10k_mapping(document, "git", allowed=_R10K_GIT_KEYS)
    for key in _R10K_GIT_KEYS - {"repositories"}:
        if key in git:
            _r10k_scalar(git[key], address=f"git {key}")
    repositories = git.get("repositories", [])
    if not isinstance(repositories, list):
        raise PuppetProjectInputError("r10k git repositories must be a list")
    for index, repository in enumerate(repositories, start=1):
        if not isinstance(repository, dict):
            raise PuppetProjectInputError(f"r10k git repository {index} must be a mapping")
        unknown = set(repository) - _R10K_REPOSITORY_KEYS
        if unknown:
            raise PuppetProjectInputError(
                f"unsupported r10k git repository key(s) on entry {index}: "
                + ", ".join(sorted(map(str, unknown)))
            )
        if not isinstance(repository.get("remote"), str):
            raise PuppetProjectInputError(f"r10k git repository {index} requires a string remote")
        for key, value in repository.items():
            if key == "ignore_branch_prefixes":
                if not (isinstance(value, list) and all(isinstance(item, str) for item in value)):
                    raise PuppetProjectInputError(
                        f"r10k git repository {index} ignore_branch_prefixes must be a string list"
                    )
            else:
                _r10k_scalar(value, address=f"git repository {index} {key}")


def _validate_r10k_document(document: dict[str, Any]) -> None:
    unknown = set(document) - _R10K_ROOT_KEYS
    if unknown:
        raise PuppetProjectInputError(
            "unsupported top-level r10k key(s): " + ", ".join(sorted(map(str, unknown)))
        )
    if not document:
        raise PuppetProjectInputError("r10k input does not contain settings")
    for alias, canonical in (
        ("git_settings", "git"),
        ("forge_settings", "forge"),
        ("deploy_settings", "deploy"),
    ):
        if alias in document and canonical in document:
            raise PuppetProjectInputError(
                f"r10k input cannot define both {canonical} and legacy {alias}"
            )
        if alias in document:
            document[canonical] = document.pop(alias)

    sources = document.get("sources", {})
    if not isinstance(sources, dict):
        raise PuppetProjectInputError("r10k sources must be a mapping")
    for index, (name, source) in enumerate(sources.items(), start=1):
        _validate_r10k_source(name, source, index)
    if "remote" in document:
        _r10k_scalar(document["remote"], address="remote")
    if "r10k_basedir" in document:
        _r10k_scalar(document["r10k_basedir"], address="r10k_basedir")
    if sources and ({"remote", "r10k_basedir"} & set(document)):
        raise PuppetProjectInputError(
            "r10k sources cannot be combined with legacy remote or r10k_basedir"
        )

    _validate_r10k_git(document)
    forge = _r10k_mapping(document, "forge", allowed=_R10K_FORGE_KEYS)
    deploy = _r10k_mapping(document, "deploy", allowed=_R10K_DEPLOY_KEYS)
    logging = _r10k_mapping(document, "logging", allowed=_R10K_LOGGING_KEYS)
    for key in ("authorization_token", "baseurl", "proxy"):
        if key in forge:
            _r10k_scalar(forge[key], address=f"forge {key}")
    if "allow_puppetfile_override" in forge and not isinstance(
        forge["allow_puppetfile_override"], bool
    ):
        raise PuppetProjectInputError("r10k forge allow_puppetfile_override must be boolean")
    for key in ("exclude_spec", "generate_types"):
        if key in deploy and not isinstance(deploy[key], bool):
            raise PuppetProjectInputError(f"r10k deploy {key} must be boolean")
    for key in ("puppet_conf", "puppet_path", "write_lock"):
        if key in deploy:
            _r10k_scalar(deploy[key], address=f"deploy {key}")
    for key in ("purge_allowlist", "purge_levels"):
        if key in deploy and not (
            isinstance(deploy[key], list) and all(isinstance(item, str) for item in deploy[key])
        ):
            raise PuppetProjectInputError(f"r10k deploy {key} must be a string list")
    if "outputs" in logging and not isinstance(logging["outputs"], list):
        raise PuppetProjectInputError("r10k logging outputs must be a list")
    if "disable_default_stderr" in logging and not isinstance(
        logging["disable_default_stderr"], bool
    ):
        raise PuppetProjectInputError("r10k logging disable_default_stderr must be boolean")
    if "level" in logging:
        _r10k_scalar(logging["level"], address="logging level")
    if "postrun" in document and not (
        isinstance(document["postrun"], list)
        and document["postrun"]
        and all(isinstance(item, str) for item in document["postrun"])
    ):
        raise PuppetProjectInputError("r10k postrun must be a non-empty string list")
    if "pool_size" in document and (
        not isinstance(document["pool_size"], int)
        or isinstance(document["pool_size"], bool)
        or document["pool_size"] < 1
    ):
        raise PuppetProjectInputError("r10k pool_size must be a positive integer")
    for key in ("cachedir", "proxy"):
        if key in document:
            _r10k_scalar(document[key], address=key)
    if "purgedirs" in document and not isinstance(document["purgedirs"], list):
        raise PuppetProjectInputError("r10k purgedirs must be a list")


def _parse_r10k_yaml(source: str) -> dict[str, Any]:
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except PuppetProjectInputError:
        raise
    except yaml.YAMLError as exc:
        raise PuppetProjectInputError(str(exc)) from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise PuppetProjectInputError("r10k input must contain one YAML mapping")
    document = documents[0]
    _validate_r10k_document(document)
    return {"artifact_type": "r10k", "document": document}


def _validate_bolt_inventory_group(
    group: dict[str, Any], address: str, *, require_name: bool
) -> None:
    allowed = {"config", "facts", "features", "groups", "name", "targets", "vars"}
    if not require_name:
        allowed.add("version")
    unknown = set(group) - allowed
    if unknown:
        raise PuppetProjectInputError(
            f"unsupported Bolt {address} key(s): " + ", ".join(sorted(map(str, unknown)))
        )
    if require_name and not isinstance(group.get("name"), str):
        raise PuppetProjectInputError(f"Bolt {address} must have a string name")
    for key in ("config", "facts", "vars"):
        if key in group and not isinstance(group[key], dict):
            raise PuppetProjectInputError(f"Bolt {address} {key} must be a mapping")
    if "features" in group and not (
        isinstance(group["features"], list)
        or (
            isinstance(group["features"], dict)
            and isinstance(group["features"].get("_plugin"), str)
        )
    ):
        raise PuppetProjectInputError(f"Bolt {address} features must be a list or plugin mapping")

    groups = group.get("groups", [])
    if isinstance(groups, dict):
        if not isinstance(groups.get("_plugin"), str):
            raise PuppetProjectInputError(f"Bolt {address} groups plugin must name _plugin")
    elif isinstance(groups, list):
        for index, child in enumerate(groups):
            if not isinstance(child, dict):
                raise PuppetProjectInputError(f"Bolt {address} group {index} must be a mapping")
            _validate_bolt_inventory_group(child, f"{address} group {index}", require_name=True)
    else:
        raise PuppetProjectInputError(f"Bolt {address} groups must be a list or plugin mapping")

    targets = group.get("targets", [])
    if isinstance(targets, dict):
        if not isinstance(targets.get("_plugin"), str):
            raise PuppetProjectInputError(f"Bolt {address} targets plugin must name _plugin")
    elif isinstance(targets, list):
        allowed_target = {"alias", "config", "facts", "features", "name", "uri", "vars"}
        for index, target in enumerate(targets):
            if isinstance(target, str):
                continue
            if not isinstance(target, dict):
                raise PuppetProjectInputError(
                    f"Bolt {address} target {index} must be a string or mapping"
                )
            unknown_target = set(target) - allowed_target
            if unknown_target:
                raise PuppetProjectInputError(
                    f"unsupported Bolt {address} target {index} key(s): "
                    + ", ".join(sorted(map(str, unknown_target)))
                )
            if not isinstance(target.get("name") or target.get("uri"), str):
                raise PuppetProjectInputError(
                    f"Bolt {address} target {index} must have a string name or uri"
                )
            for key in ("config", "facts", "vars"):
                if key in target and not isinstance(target[key], dict):
                    raise PuppetProjectInputError(
                        f"Bolt {address} target {index} {key} must be a mapping"
                    )
            if "features" in target and not (
                isinstance(target["features"], list)
                or (
                    isinstance(target["features"], dict)
                    and isinstance(target["features"].get("_plugin"), str)
                )
            ):
                raise PuppetProjectInputError(
                    f"Bolt {address} target {index} features must be a list or plugin mapping"
                )
    else:
        raise PuppetProjectInputError(f"Bolt {address} targets must be a list or plugin mapping")


def _parse_puppet_conf(source: str) -> dict[str, Any]:
    sections: dict[str, dict[str, dict[str, Any]]] = {}
    current_section: str | None = None
    setting_count = 0
    for line_number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("["):
            if line != line.lstrip():
                raise PuppetProjectInputError(
                    f"puppet.conf section on line {line_number} must not be indented"
                )
            section_match = re.fullmatch(r"\[(?P<name>[A-Za-z][A-Za-z0-9_-]*)\]", stripped)
            if section_match is None:
                raise PuppetProjectInputError(
                    f"invalid puppet.conf section declaration on line {line_number}"
                )
            current_section = section_match.group("name").lower()
            if current_section not in _PUPPET_CONFIG_SECTIONS:
                raise PuppetProjectInputError(
                    f"unsupported puppet.conf section {current_section!r} on line {line_number}"
                )
            if current_section in sections:
                raise PuppetProjectInputError(
                    f"duplicate puppet.conf section {current_section!r} on line {line_number}"
                )
            sections[current_section] = {}
            continue
        if current_section is None:
            raise PuppetProjectInputError(
                f"puppet.conf setting on line {line_number} appears before a section"
            )
        setting_match = _PUPPET_CONFIG_SETTING.fullmatch(line)
        if setting_match is None:
            raise PuppetProjectInputError(f"invalid puppet.conf setting on line {line_number}")
        name = setting_match.group("name").lower()
        if name in sections[current_section]:
            raise PuppetProjectInputError(
                f"duplicate puppet.conf setting {name!r} in section {current_section!r}"
            )
        sections[current_section][name] = {
            "value": setting_match.group("value").strip(),
            "line": line_number,
        }
        setting_count += 1
    if not sections or not setting_count:
        raise PuppetProjectInputError("input is not a populated puppet.conf")
    return {"artifact_type": "config", "document": {"sections": sections}}


def _parse_environment_conf(source: str) -> dict[str, Any]:
    settings: dict[str, dict[str, Any]] = {}
    for line_number, original in enumerate(source.splitlines(), start=1):
        cleaned = _strip_comment(original)
        line = cleaned.strip()
        if not line:
            continue
        if line.startswith("["):
            raise PuppetProjectInputError("environment.conf must not contain config sections")
        match = _PUPPET_CONFIG_SETTING.fullmatch(cleaned)
        if match is None:
            raise PuppetProjectInputError(f"invalid environment.conf setting on line {line_number}")
        name = match.group("name").casefold()
        if name not in _ENVIRONMENT_SETTINGS:
            raise PuppetProjectInputError(
                f"unsupported environment.conf setting on line {line_number}"
            )
        if name in settings:
            raise PuppetProjectInputError(
                f"duplicate environment.conf setting on line {line_number}"
            )
        value = match.group("value").strip()
        if not value:
            raise PuppetProjectInputError(f"empty environment.conf setting on line {line_number}")
        settings[name] = {"value": value, "line": line_number}
    if not settings:
        raise PuppetProjectInputError("environment.conf does not contain settings")
    return {"artifact_type": "environment", "document": {"settings": settings}}


def _parse_puppetdb_conf(source: str) -> dict[str, Any]:
    parsed = _parse_puppet_conf(source)
    sections = parsed["document"]["sections"]
    if set(sections) != {"main"}:
        raise PuppetProjectInputError("puppetdb.conf must contain only a main section")
    return {"artifact_type": "puppetdb", "document": parsed["document"]}


def _parse_puppet_server_hocon(source: str, artifact_type: str) -> dict[str, Any]:
    try:
        parsed = parse_puppet_hocon(source)
    except PuppetHoconError as exc:
        raise PuppetProjectInputError(str(exc)) from exc
    return {
        "artifact_type": artifact_type,
        "document": {
            "config": parsed.values,
            "include_count": parsed.include_count,
            "substitution_count": parsed.substitution_count,
        },
    }


def _validate_hiera(document: dict[str, Any]) -> None:
    unknown = set(document) - {"version", "defaults", "hierarchy", "default_hierarchy"}
    if unknown:
        raise PuppetProjectInputError(
            "unsupported top-level Hiera key(s): " + ", ".join(sorted(map(str, unknown)))
        )
    defaults = document.get("defaults", {})
    if not isinstance(defaults, dict):
        raise PuppetProjectInputError("Hiera defaults must be a mapping")
    _validate_hiera_functions(defaults, "defaults")
    if "options" in defaults and not isinstance(defaults["options"], dict):
        raise PuppetProjectInputError("Hiera defaults options must be a mapping")
    for key in ("hierarchy", "default_hierarchy"):
        levels = document.get(key, [])
        if not isinstance(levels, list):
            raise PuppetProjectInputError(f"Hiera {key} must be a list")
        for index, level in enumerate(levels, start=1):
            if not isinstance(level, dict):
                raise PuppetProjectInputError(f"Hiera {key} level {index} must be a mapping")
            _validate_hiera_functions(level, f"{key} level {index}")
            if "options" in level and not isinstance(level["options"], dict):
                raise PuppetProjectInputError(
                    f"Hiera {key} level {index} options must be a mapping"
                )
            for paths_key in ("paths", "globs"):
                if paths_key in level and not isinstance(level[paths_key], list):
                    raise PuppetProjectInputError(
                        f"Hiera {key} level {index} {paths_key} must be a list"
                    )
            if "mapped_paths" in level and (
                not isinstance(level["mapped_paths"], list) or len(level["mapped_paths"]) != 3
            ):
                raise PuppetProjectInputError(
                    f"Hiera {key} level {index} mapped_paths must contain exactly three items"
                )


def _validate_hiera_functions(values: dict[str, Any], address: str) -> None:
    functions = {"data_hash", "lookup_key", "data_dig"} & set(values)
    if len(functions) > 1:
        raise PuppetProjectInputError(
            f"Hiera {address} must select only one lookup function, found: "
            + ", ".join(sorted(functions))
        )


def parse_puppet_project(source: str, *, filename: str = "") -> dict[str, Any]:
    """Parse Puppet, Hiera, Puppet Server, PuppetDB, Bolt, or r10k configuration."""
    if not source.strip():
        raise PuppetProjectInputError("input is empty")
    basename = Path(filename).name.casefold()
    try:
        if is_bolt_yaml_plan(filename):
            parsed = {
                "artifact_type": "bolt_yaml_plan",
                "document": parse_bolt_yaml_plan(source),
            }
        elif is_bolt_task_metadata(filename):
            parsed = {
                "artifact_type": "bolt_task_metadata",
                "document": parse_bolt_task_metadata(source),
            }
        elif basename in {"r10k.yaml", "r10k.yml"}:
            parsed = _parse_r10k_yaml(source)
        elif basename == "environment.conf":
            parsed = _parse_environment_conf(source)
        elif basename == "puppetdb.conf":
            parsed = _parse_puppetdb_conf(source)
        elif basename in _PUPPET_SERVER_HOCON_FILES:
            parsed = _parse_puppet_server_hocon(source, _PUPPET_SERVER_HOCON_FILES[basename])
        elif basename == "bolt-project.yaml":
            parsed = _parse_bolt_yaml(source, "bolt_project")
        elif basename in {"inventory.yaml", "inventory.yml"}:
            parsed = _parse_bolt_yaml(source, "bolt_inventory")
        else:
            parsed = _parse_json(source)
    except BoltContentInputError as exc:
        raise PuppetProjectInputError(str(exc)) from exc
    if parsed is None:
        first = next(
            (
                line.strip()
                for line in source.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ),
            "",
        )
        if basename == "puppet.conf" or first.startswith("["):
            parsed = _parse_puppet_conf(source)
        elif first == "---" or re.match(r"^(?:version|defaults|hierarchy):", first):
            parsed = _parse_hiera(source)
        else:
            parsed = _parse_puppetfile(source)
    return {"puppet_project": parsed}


def _embedded_credential(value: str) -> bool:
    candidate = value.removeprefix("git+")
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _source_risks(source: str) -> tuple[str, list[str]]:
    risk = "review"
    reasons: list[str] = []
    if source.lower().startswith(("http://", "git://")):
        risk = "dangerous"
        reasons.append("It uses an unauthenticated plaintext transport.")
    if _embedded_credential(source):
        risk = "dangerous"
        reasons.append("The source URL embeds credentials that can leak in logs or metadata.")
    if source.startswith(("./", "../", "/", "file://", "git+file://")):
        reasons.append("It resolves executable content from the local filesystem.")
    return risk, reasons


def _path_escapes(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        path.is_absolute()
        or ".." in path.parts
        or bool(re.match(r"^[A-Za-z]:/", normalized))
        or bool(urlsplit(normalized).scheme)
    )


def _puppetfile_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for call in document["calls"]:
        name = call["name"]
        values = call["values"]
        options = call["options"]
        address = f"puppetfile.line.{call['line']}"
        if name == "forge":
            endpoint = values[0] if values else "<dynamic>"
            risk, reasons = _source_risks(endpoint)
            if endpoint == "<dynamic>":
                risk = "dangerous"
                reasons.append("The Forge endpoint is dynamic and cannot be resolved statically.")
            changes.append(
                _change(
                    address,
                    "forge_source",
                    risk,
                    f"Puppetfile downloads modules from Forge endpoint {endpoint!r}. "
                    + " ".join(reasons),
                )
            )
        elif name == "moduledir":
            target = values[0] if values else "<dynamic>"
            changes.append(
                _change(
                    address,
                    "module_directory",
                    "dangerous" if target == "<dynamic>" or _path_escapes(target) else "review",
                    f"Puppetfile installs module content under {target!r}; verify deployment "
                    "scope, ownership, and modulepath precedence.",
                )
            )
        elif name == "mod":
            module = values[0] if values else "<dynamic>"
            version = values[1] if len(values) > 1 and not options else ""
            source = options.get("git") or options.get("path") or ""
            revision = next(
                (
                    options[key]
                    for key in ("commit", "ref", "revision", "tag", "branch")
                    if key in options
                ),
                "",
            )
            risk, reasons = _source_risks(source)
            exact_forge = bool(version and _EXACT_VERSION.fullmatch(version))
            exact_git = bool(revision and _COMMIT.fullmatch(revision))
            if not exact_forge and not exact_git:
                risk = "dangerous"
                reasons.append("The module is not pinned to an exact Forge version or full commit.")
            if revision and not exact_git:
                risk = "dangerous"
                reasons.append("The Git revision is a mutable branch, tag, or abbreviated commit.")
            install_path = options.get("install_path", "")
            if install_path and _path_escapes(install_path):
                risk = "dangerous"
                reasons.append("The install_path escapes the environment module directory.")
            changes.append(
                _change(
                    address,
                    "module_dependency",
                    risk,
                    f"Puppet installs executable module/content {module!r}. " + " ".join(reasons),
                )
            )
    changes.extend(_dynamic_changes(document.get("dynamic", [])))
    return changes


def _dynamic_changes(dynamic: list[dict[str, Any]]) -> list[dict[str, str]]:
    if not dynamic:
        return []
    execution = [item for item in dynamic if _RUBY_EXECUTION.search(str(item["source"]))]
    remaining = [item for item in dynamic if item not in execution]
    changes: list[dict[str, str]] = []
    if execution:
        changes.append(
            _change(
                f"puppetfile.line.{execution[0]['line']}",
                "ruby_execution",
                "dangerous",
                "Puppetfile contains Ruby process/code-loading behavior; r10k or Code Manager "
                "executes this file while resolving environment content.",
            )
        )
    if remaining:
        changes.append(
            _change(
                f"puppetfile.line.{remaining[0]['line']}",
                "dynamic_ruby",
                "review",
                f"Puppetfile contains {len(remaining)} unexpanded Ruby expression(s); effective "
                "module resolution may differ at deployment time.",
            )
        )
    return changes


def _bounded_requirement(value: str) -> bool:
    text = value.strip()
    if _EXACT_VERSION.fullmatch(text.lstrip("= ")):
        return True
    lower = bool(re.search(r"(?:^|\s)(?:>=|>)\s*v?\d", text))
    upper = bool(re.search(r"(?:^|\s)(?:<=|<)\s*v?\d", text))
    pessimistic = bool(re.search(r"(?:^|\s)~>\s*v?\d", text))
    return lower and upper or pessimistic


def _metadata_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for key in sorted(_METADATA_REQUIRED - set(document)):
        changes.append(
            _change(
                f"metadata.{key}",
                "missing_metadata_field",
                "dangerous",
                f"Puppet module metadata omits required field {key!r}, weakening package "
                "identity or dependency resolution.",
            )
        )
    source = document.get("source")
    if isinstance(source, str) and source:
        risk, reasons = _source_risks(source)
        if reasons:
            changes.append(
                _change(
                    "metadata.source",
                    "module_source",
                    risk,
                    f"Puppet module publishes source endpoint {source!r}. " + " ".join(reasons),
                )
            )
    for kind in ("dependencies", "requirements"):
        for index, item in enumerate(document.get(kind, []), start=1):
            name = item["name"]
            requirement = str(item.get("version_requirement", "")).strip()
            bounded = _bounded_requirement(requirement)
            changes.append(
                _change(
                    f"metadata.{kind}.{index}.{name}",
                    "module_dependency" if kind == "dependencies" else "runtime_requirement",
                    "review" if bounded else "dangerous",
                    f"Puppet metadata declares {kind[:-1]} {name!r} with version requirement "
                    f"{requirement or '<missing>'!r}. "
                    + (
                        "The requirement is exact or has both compatibility bounds."
                        if bounded
                        else "The requirement is missing or unbounded."
                    ),
                )
            )
    operating_systems = document.get("operatingsystem_support", [])
    if operating_systems:
        changes.append(
            _change(
                "metadata.operatingsystem_support",
                "operating_system_support",
                "review",
                f"Puppet module declares compatibility with {len(operating_systems)} operating "
                "system family entry/entries; verify promoted node coverage.",
            )
        )
    return changes


def _hiera_function(level: dict[str, Any], defaults: dict[str, Any]) -> tuple[str, str]:
    for key in ("lookup_key", "data_hash", "data_dig"):
        if key in level:
            return key, str(level[key])
        if key in defaults:
            return key, str(defaults[key])
    return "data_hash", "yaml_data"


def _walk_secret_paths(value: Any, prefix: str = "") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if (
                _SECRET.search(path)
                and isinstance(child, (str, int, float, bool))
                and not _looks_like_file_reference(child)
            ):
                paths.append(path)
            paths.extend(_walk_secret_paths(child, path))
    elif isinstance(value, list):
        for child in value:
            paths.extend(_walk_secret_paths(child, prefix))
    return paths


def _walk_secret_file_paths(value: Any, prefix: str = "") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if _SECRET.search(path) and _looks_like_file_reference(child):
                paths.append(path)
            paths.extend(_walk_secret_file_paths(child, path))
    elif isinstance(value, list):
        for child in value:
            paths.extend(_walk_secret_file_paths(child, prefix))
    return paths


def _looks_like_file_reference(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return (
        "/" in value
        or "\\" in value
        or lowered.endswith((".key", ".pem", ".pkcs7", ".crt", ".cert"))
    )


def _hiera_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    version = document.get("version")
    if version != 5:
        changes.append(
            _change(
                "hiera.version",
                "legacy_hiera_version",
                "dangerous",
                f"Hiera configuration uses version {version!r}; version 5 is the supported "
                "environment/module configuration contract.",
            )
        )
    defaults = document.get("defaults", {})
    default_datadir = str(defaults.get("datadir", "data"))
    if _path_escapes(default_datadir):
        changes.append(
            _change(
                "hiera.defaults.datadir",
                "data_path_escape",
                "dangerous",
                f"Hiera default datadir {default_datadir!r} escapes the configuration directory.",
            )
        )
    default_options = defaults.get("options", {})
    default_secrets = _walk_secret_paths(default_options)
    default_secret_files = _walk_secret_file_paths(default_options)
    if default_secrets:
        changes.append(
            _change(
                "hiera.defaults.options",
                "backend_secret",
                "dangerous",
                "Hiera default backend options contain literal secret-like field(s): "
                + ", ".join(default_secrets[:3]),
            )
        )
    if default_secret_files:
        changes.append(
            _change(
                "hiera.defaults.options",
                "backend_credential_file",
                "review",
                "Hiera default backend options reference credential/key file(s): "
                + ", ".join(default_secret_files[:3])
                + ". Verify permissions and keep private material outside source control.",
            )
        )
    all_levels = [
        *document.get("hierarchy", []),
        *document.get("default_hierarchy", []),
    ]
    if not all_levels and ({"lookup_key", "data_hash", "data_dig"} & set(defaults)):
        function_kind, function = _hiera_function({}, defaults)
        builtin = (
            function in _BUILTIN_DATA_HASHES
            if function_kind == "data_hash"
            else function in _BUILTIN_LOOKUP_KEYS
        )
        changes.append(
            _change(
                f"hiera.defaults.{function_kind}",
                "data_backend",
                "review" if builtin else "dangerous",
                (
                    f"Hiera defaults select built-in {function_kind} {function!r}."
                    if builtin
                    else f"Hiera defaults execute custom {function_kind} {function!r} during "
                    "catalog data lookup."
                ),
            )
        )
    for hierarchy_kind in ("hierarchy", "default_hierarchy"):
        levels = document.get(hierarchy_kind, [])
        if levels and hierarchy_kind == "default_hierarchy":
            changes.append(
                _change(
                    "hiera.default_hierarchy",
                    "default_data_fallback",
                    "review",
                    "Hiera adds a module default hierarchy consulted after global, environment, "
                    "and normal module data sources do not return a value.",
                )
            )
        for index, level in enumerate(levels, start=1):
            address = f"hiera.{hierarchy_kind}.{index}"
            function_kind, function = _hiera_function(level, defaults)
            builtin = (
                function in _BUILTIN_DATA_HASHES
                if function_kind == "data_hash"
                else function in _BUILTIN_LOOKUP_KEYS
            )
            changes.append(
                _change(
                    f"{address}.{function_kind}",
                    "data_backend",
                    "review" if builtin else "dangerous",
                    (
                        f"Hiera hierarchy level uses built-in {function_kind} {function!r}."
                        if builtin
                        else f"Hiera hierarchy level executes custom {function_kind} {function!r} "
                        "during catalog data lookup."
                    ),
                )
            )
            paths: list[str] = []
            for key in ("path", "glob", "datadir"):
                if key in level:
                    paths.append(str(level[key]))
            for key in ("paths", "globs"):
                paths.extend(str(item) for item in level.get(key, []))
            if "mapped_paths" in level:
                mapped = level["mapped_paths"]
                if isinstance(mapped, list):
                    paths.extend(str(item) for item in mapped[1:])
            if not str(level.get("name", "")).strip():
                changes.append(
                    _change(
                        f"{address}.name",
                        "missing_hierarchy_name",
                        "dangerous",
                        "Hiera hierarchy level has no static name, weakening lookup traceability.",
                    )
                )
            if function_kind == "data_hash" and not paths:
                changes.append(
                    _change(
                        f"{address}.paths",
                        "missing_data_path",
                        "dangerous",
                        "File-backed Hiera hierarchy level has no path, paths, glob, globs, or "
                        "mapped_paths source.",
                    )
                )
            if any(_path_escapes(path) for path in paths):
                changes.append(
                    _change(
                        f"{address}.paths",
                        "data_path_escape",
                        "dangerous",
                        "Hiera hierarchy path escapes its configured data directory.",
                    )
                )
            elif paths:
                changes.append(
                    _change(
                        f"{address}.paths",
                        "data_source",
                        "review",
                        f"Hiera hierarchy level selects {len(paths)} ordered data path/glob "
                        "source(s); higher-priority values override later sources.",
                    )
                )
            options = level.get("options", {})
            if isinstance(options, dict):
                secrets = _walk_secret_paths(options)
                secret_files = _walk_secret_file_paths(options)
                if secrets:
                    changes.append(
                        _change(
                            f"{address}.options",
                            "backend_secret",
                            "dangerous",
                            "Hiera backend options contain literal secret-like field(s): "
                            + ", ".join(secrets[:3]),
                        )
                    )
                if secret_files:
                    changes.append(
                        _change(
                            f"{address}.options",
                            "backend_credential_file",
                            "review",
                            "Hiera backend options reference credential/key file(s): "
                            + ", ".join(secret_files[:3])
                            + ". Verify permissions and keep private material outside source "
                            "control.",
                        )
                    )
    return changes


def _puppet_config_enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "on", "true", "yes"}


def _puppet_config_disabled(value: str) -> bool:
    return value.strip().lower() in {"0", "false", "no", "none", "off"}


def _puppet_config_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    sections = document["sections"]
    for section, settings in sections.items():
        for name, setting in settings.items():
            value = str(setting["value"])
            lowered = value.strip().lower()
            address = f"puppet_conf.{section}.{name}"

            if name in _PUPPET_SECRET_SETTINGS and lowered not in {"", "none"}:
                indirect = value.lstrip().startswith("$")
                changes.append(
                    _change(
                        address,
                        "credential",
                        "review" if indirect else "dangerous",
                        (
                            "Puppet configuration references a credential through setting "
                            f"{name!r}; verify the referenced value is supplied outside source "
                            "control and protected from logs."
                            if indirect
                            else "Puppet configuration stores a literal credential in setting "
                            f"{name!r}; move it to a protected external secret source."
                        ),
                    )
                )
                continue

            if name == "autosign":
                if _puppet_config_disabled(value):
                    risk = "safe"
                    explanation = "Puppet CA certificate autosigning is explicitly disabled."
                elif _puppet_config_enabled(value):
                    risk = "dangerous"
                    explanation = (
                        "Puppet CA autosigns every certificate request, allowing unreviewed "
                        "nodes to receive trusted identities."
                    )
                else:
                    risk = "review"
                    explanation = (
                        "Puppet CA delegates certificate autosigning to a policy/configuration "
                        "file; verify its allowlist and permissions because executable files are "
                        "run for every certificate request."
                    )
                changes.append(_change(address, "certificate_autosign", risk, explanation))
                continue

            if name == "certificate_revocation":
                if _puppet_config_disabled(value):
                    risk = "dangerous"
                    explanation = "Puppet disables all certificate revocation checks."
                elif lowered == "leaf":
                    risk = "review"
                    explanation = (
                        "Puppet verifies only leaf certificate revocation and does not verify "
                        "revocation across the complete CA chain."
                    )
                else:
                    risk = "safe"
                    explanation = "Puppet enables certificate revocation checking for its CA chain."
                changes.append(_change(address, "certificate_revocation", risk, explanation))
                continue

            if name == "allow_duplicate_certs" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "duplicate_certificate_request",
                        "review",
                        "Puppet CA permits a new certificate request to replace an existing "
                        "request; retain explicit cleanup and signing approval controls.",
                    )
                )
                continue

            if name == "digest_algorithm":
                strong = lowered in {"sha224", "sha256", "sha384", "sha512"}
                changes.append(
                    _change(
                        address,
                        "content_digest",
                        "safe" if strong else "dangerous",
                        (
                            "Puppet uses a modern SHA-2 digest for managed file integrity."
                            if strong
                            else "Puppet uses a weak or unrecognized digest for managed file "
                            "integrity."
                        ),
                    )
                )
                continue

            if name in _PUPPET_COMMAND_SETTINGS and lowered not in {"", "none"}:
                risk = "review" if name == "diff" and lowered == "diff" else "dangerous"
                changes.append(
                    _change(
                        address,
                        "external_command",
                        risk,
                        f"Puppet setting {name!r} invokes an external command in a privileged "
                        "configuration workflow; review ownership, arguments, and executable "
                        "provenance.",
                    )
                )
                continue

            if name == "code" and value.strip():
                changes.append(
                    _change(
                        address,
                        "inline_code",
                        "dangerous",
                        "Puppet configuration injects inline manifest code directly into the "
                        "runtime instead of loading reviewed environment content.",
                    )
                )
                continue

            if name == "node_terminus" and lowered == "exec":
                changes.append(
                    _change(
                        address,
                        "external_node_classifier",
                        "dangerous",
                        "Puppet delegates node classification to an executable external node "
                        "classifier whose output controls classes, environments, and parameters.",
                    )
                )
                continue

            if name in _PUPPET_TERMINUS_SETTINGS and lowered not in {"", "none"}:
                builtins = {
                    "classifier",
                    "compiler",
                    "json",
                    "msgpack",
                    "plain",
                    "puppetdb",
                    "rest",
                    "yaml",
                }
                custom = lowered not in builtins
                changes.append(
                    _change(
                        address,
                        "runtime_backend",
                        "dangerous" if custom else "review",
                        (
                            f"Puppet setting {name!r} selects a custom runtime backend that can "
                            "load extension code or redirect authoritative data."
                            if custom
                            else f"Puppet setting {name!r} changes the backend responsible for "
                            "authoritative runtime data or cached state."
                        ),
                    )
                )
                continue

            if name == "reports" and value.strip():
                processors = {item.strip().lower() for item in value.split(",") if item.strip()}
                custom = processors - _PUPPET_BUILTIN_REPORTS
                changes.append(
                    _change(
                        address,
                        "report_processors",
                        "dangerous" if custom else "review",
                        (
                            "Puppet loads one or more custom report processors as server-side "
                            "extension code."
                            if custom
                            else "Puppet forwards or persists run reports through configured "
                            "built-in processors; verify destinations and report-data exposure."
                        ),
                    )
                )
                continue

            if name == "reporturl" and value.strip():
                plaintext = lowered.startswith("http://")
                changes.append(
                    _change(
                        address,
                        "report_endpoint",
                        "dangerous" if plaintext else "review",
                        (
                            "Puppet sends report data to a plaintext HTTP endpoint."
                            if plaintext
                            else "Puppet sends report data to an external endpoint; verify TLS, "
                            "authentication, and data handling."
                        ),
                    )
                )
                continue

            if name == "http_debug" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "http_debug_logging",
                        "dangerous",
                        "Puppet logs HTTP requests and responses, which can expose catalog, fact, "
                        "certificate, or credential material.",
                    )
                )
                continue

            if name == "http_extra_headers" and value.strip() not in {"", "[]"}:
                secret_like = bool(_SECRET.search(value))
                changes.append(
                    _change(
                        address,
                        "http_headers",
                        "dangerous" if secret_like else "review",
                        (
                            "Puppet configuration places secret-like material in outbound HTTP "
                            "headers."
                            if secret_like
                            else "Puppet adds custom outbound HTTP headers; verify their trust "
                            "boundary and logging behavior."
                        ),
                    )
                )
                continue

            if name == "show_diff" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "content_diff_logging",
                        "dangerous",
                        "Puppet logs managed file content differences, which can expose secrets "
                        "or other sensitive configuration data.",
                    )
                )
                continue

            if name == "ignore_plugin_errors" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "plugin_error_bypass",
                        "dangerous",
                        "Puppet continues after plugin synchronization errors instead of failing "
                        "the run closed.",
                    )
                )
                continue

            if name == "use_cached_catalog" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "cached_catalog_only",
                        "dangerous",
                        "Puppet applies only its cached catalog without requesting current policy "
                        "or uploading current facts.",
                    )
                )
                continue

            if name == "usecacheonfailure" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "cached_catalog_fallback",
                        "review",
                        "Puppet can apply a previously cached catalog when current catalog "
                        "compilation fails; review stale-policy tolerance.",
                    )
                )
                continue

            if name == "strict_variables" and _puppet_config_disabled(value):
                changes.append(
                    _change(
                        address,
                        "undefined_variable_tolerance",
                        "dangerous",
                        "Puppet permits undefined variables instead of failing catalog evaluation.",
                    )
                )
                continue

            if name == "strict" and lowered == "off":
                changes.append(
                    _change(
                        address,
                        "validation_strictness",
                        "review",
                        "Puppet disables strict validation warnings for potentially unsafe or "
                        "deprecated behavior.",
                    )
                )
                continue

            if name == "preferred_serialization_format" and lowered == "pson":
                changes.append(
                    _change(
                        address,
                        "legacy_serialization",
                        "dangerous",
                        "Puppet prefers legacy PSON serialization, which cannot preserve all rich "
                        "catalog data safely.",
                    )
                )
                continue

            if name == "allow_pson_serialization" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "legacy_serialization",
                        "review",
                        "Puppet permits fallback to legacy PSON serialization when modern formats "
                        "cannot represent catalog data.",
                    )
                )
                continue

            if name in _PUPPET_CODE_PATH_SETTINGS and value.strip():
                changes.append(
                    _change(
                        address,
                        "code_source_path",
                        "review",
                        f"Puppet setting {name!r} changes a manifest, module, fact, plugin, route, "
                        "or data source path that can affect compiled catalogs and runtime code.",
                    )
                )
                continue

            if name in _PUPPET_ENDPOINT_SETTINGS and lowered not in {"", "none"}:
                changes.append(
                    _change(
                        address,
                        "service_endpoint",
                        "review",
                        f"Puppet setting {name!r} changes a server, CA, reporting, or proxy trust "
                        "boundary; verify identity, routing, and TLS expectations.",
                    )
                )
                continue

            if name in _PUPPET_IDENTITY_SETTINGS and value.strip():
                changes.append(
                    _change(
                        address,
                        "runtime_identity",
                        "review",
                        f"Puppet setting {name!r} changes certificate, node, user, or group "
                        "identity used for authorization and privileged execution.",
                    )
                )
                continue

            if name == "environment" and value.strip():
                global_environment = section == "main"
                changes.append(
                    _change(
                        address,
                        "environment_selection",
                        "dangerous" if global_environment else "review",
                        (
                            "Puppet sets environment globally even though agent, server, and user "
                            "contexts can require different code; move it to the intended "
                            "application-specific section."
                            if global_environment
                            else "Puppet pins the code environment for this application context; "
                            "verify environment assignment and promotion controls."
                        ),
                    )
                )
                continue

            if name in {"ca_ttl", "dns_alt_names", "ssl_client_header", "ssl_client_verify_header"}:
                changes.append(
                    _change(
                        address,
                        "certificate_identity",
                        "review",
                        f"Puppet setting {name!r} changes certificate lifetime, trusted names, or "
                        "reverse-proxy identity headers; review the CA and network trust model.",
                    )
                )
                continue

            if name in {"pluginsync", "report", "splay", "storeconfigs"} and _puppet_config_enabled(
                value
            ):
                changes.append(
                    _change(
                        address,
                        "runtime_integration",
                        "review",
                        f"Puppet enables {name!r}, changing plugin delivery, reporting, "
                        "scheduling, or exported-resource state behavior.",
                    )
                )
                continue

            if name == "runinterval" and value.strip():
                changes.append(
                    _change(
                        address,
                        "agent_schedule",
                        "review",
                        "Puppet changes the recurring agent enforcement interval; review rollout "
                        "load, convergence latency, and maintenance windows.",
                    )
                )
                continue

            if name == "noop" and _puppet_config_enabled(value):
                changes.append(
                    _change(
                        address,
                        "dry_run",
                        "safe",
                        "Puppet runs in no-op mode and reports proposed changes without enforcing "
                        "resource state.",
                    )
                )
                continue

            if name in {"tasks", "manage_internal_file_permissions"}:
                unsafe = (name == "tasks" and _puppet_config_enabled(value)) or (
                    name == "manage_internal_file_permissions" and _puppet_config_disabled(value)
                )
                if unsafe:
                    changes.append(
                        _change(
                            address,
                            "runtime_safety_control",
                            "dangerous",
                            f"Puppet setting {name!r} enables experimental execution or disables "
                            "protection of internal files.",
                        )
                    )

    return changes


_BOLT_BUILTIN_PLUGINS = {
    "aws_inventory",
    "azure_inventory",
    "env_var",
    "gcloud_inventory",
    "json",
    "pkcs7",
    "prompt",
    "puppetdb",
    "terraform",
    "vault",
    "yaml",
}
_BOLT_DYNAMIC_INVENTORY_PLUGINS = {
    "aws_inventory",
    "azure_inventory",
    "gcloud_inventory",
    "puppetdb",
    "terraform",
    "yaml",
}
_BOLT_PRIVILEGED_USERS = {"administrator", "root"}


def _bolt_address_segment(value: object) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", str(value))[:80] or "key"


def _bolt_walk(value: Any, address: str = "bolt") -> list[tuple[str, str, Any]]:
    found: list[tuple[str, str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_address = f"{address}.{_bolt_address_segment(key_text)}"
            found.append((child_address, key_text.casefold(), child))
            found.extend(_bolt_walk(child, child_address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_bolt_walk(child, f"{address}.{index}"))
    return found


def _bolt_plugin_changes(document: dict[str, Any], *, inventory: bool) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for address, key, value in _bolt_walk(document):
        if key != "_plugin" or not isinstance(value, str):
            continue
        plugin = value.casefold()
        if (
            inventory
            and plugin in _BOLT_DYNAMIC_INVENTORY_PLUGINS
            and (".targets._plugin" in address or ".groups._plugin" in address)
        ):
            risk = "dangerous"
            kind = "bolt_dynamic_inventory"
            explanation = (
                "Bolt executes a reference plugin while loading inventory to determine target "
                "scope. Review the query, credentials, returned targets, and plugin provenance."
            )
        elif plugin in _BOLT_BUILTIN_PLUGINS:
            risk = "review"
            kind = "bolt_reference_plugin"
            explanation = (
                "Bolt resolves a built-in reference plugin at runtime; verify its external data "
                "source, secret handling, and effective returned value."
            )
        else:
            risk = "dangerous"
            kind = "bolt_custom_plugin"
            explanation = (
                "Bolt resolves a module-provided or unknown plugin that can execute custom code "
                "on the controller. Verify the installed module and plugin implementation."
            )
        changes.append(_change(address, kind, risk, explanation))
    return changes


def _bolt_literal_secret_changes(document: dict[str, Any], root: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for address, key, value in _bolt_walk(document, root):
        if key == "token" and ".puppetdb" in address:
            continue
        if (not _SECRET.search(key) and key != "key-data") or key in {
            "private-key",
            "token-file",
        }:
            continue
        if isinstance(value, (str, int, float)):
            changes.append(
                _change(
                    address,
                    "bolt_literal_credential",
                    "dangerous",
                    "Bolt configuration contains literal credential material. Replace it with a "
                    "secret reference plugin or a protected credential file.",
                )
            )
    return changes


def _bolt_module_change(module: Any, index: int) -> dict[str, str]:
    address = f"bolt_project.modules.{index}"
    if isinstance(module, str):
        return _change(
            address,
            "bolt_module_dependency",
            "dangerous",
            "Bolt installs a module without an exact version requirement, so future resolution "
            "can change the code executed by tasks and plans.",
        )
    if not isinstance(module, dict):
        return _change(
            address,
            "bolt_module_dependency",
            "dangerous",
            "Bolt module dependency is not a static string or mapping and cannot be verified.",
        )
    source = module.get("git")
    requirement = module.get("version_requirement")
    ref = module.get("ref")
    if isinstance(source, str):
        source_risk, reasons = _source_risks(source)
        immutable = isinstance(ref, str) and bool(_COMMIT.fullmatch(ref))
        risk = "review" if immutable and source_risk == "review" else "dangerous"
        explanation = "Bolt installs a module from Git. " + " ".join(reasons)
        explanation += (
            " The ref is an immutable commit."
            if immutable
            else " The ref is absent or mutable; pin a full commit digest."
        )
        return _change(address, "bolt_module_dependency", risk, explanation)
    exact = isinstance(requirement, str) and bool(_EXACT_VERSION.fullmatch(requirement.strip()))
    return _change(
        address,
        "bolt_module_dependency",
        "review" if exact else "dangerous",
        "Bolt installs a Forge module with an exact version requirement."
        if exact
        else "Bolt installs a Forge module without an exact version requirement.",
    )


def _bolt_project_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes = [
        _bolt_module_change(module, index)
        for index, module in enumerate(document.get("modules", []))
    ]
    changes.extend(_bolt_plugin_changes(document, inventory=False))
    changes.extend(_bolt_literal_secret_changes(document, "bolt_project"))

    plugins = document.get("plugins", {})
    for index, _name in enumerate(plugins):
        changes.append(
            _change(
                f"bolt_project.plugins.{index}",
                "bolt_configured_plugin",
                "dangerous",
                "Bolt configures a plugin supplied by installed executable module content. "
                "Verify the module provenance, plugin hooks, and configuration schema.",
            )
        )

    modulepath = document.get("modulepath", [])
    paths = [modulepath] if isinstance(modulepath, str) else modulepath
    for index, path in enumerate(paths):
        if isinstance(path, str):
            changes.append(
                _change(
                    f"bolt_project.modulepath.{index}",
                    "bolt_module_path",
                    "dangerous" if _path_escapes(path) else "review",
                    "Bolt loads executable task, plan, and plugin content from a module path "
                    + ("outside the project." if _path_escapes(path) else "inside the project."),
                )
            )
    module_install = document.get("module-install", {})
    forge = module_install.get("forge", {}) if isinstance(module_install, dict) else {}
    if isinstance(forge, dict):
        endpoint = forge.get("baseurl")
        if isinstance(endpoint, str):
            changes.append(
                _change(
                    "bolt_project.module-install.forge.baseurl",
                    "bolt_module_endpoint",
                    "dangerous" if endpoint.casefold().startswith("http://") else "review",
                    "Bolt downloads modules from a plaintext Forge endpoint."
                    if endpoint.casefold().startswith("http://")
                    else "Bolt downloads modules from a configured Forge endpoint.",
                )
            )
    for address, key, value in _bolt_walk(document, "bolt_project"):
        if key in {"proxy", "server_urls", "service-url"}:
            urls = value if isinstance(value, list) else [value]
            if any(isinstance(url, str) and url.casefold().startswith("http://") for url in urls):
                changes.append(
                    _change(
                        address,
                        "bolt_plaintext_endpoint",
                        "dangerous",
                        "Bolt connects to a plaintext HTTP endpoint, exposing metadata or "
                        "credentials to interception.",
                    )
                )
            if any(isinstance(url, str) and _embedded_credential(url) for url in urls):
                changes.append(
                    _change(
                        address,
                        "bolt_embedded_credential",
                        "dangerous",
                        "Bolt endpoint or proxy URL embeds credentials that can leak through "
                        "configuration, logs, and process metadata.",
                    )
                )
        if key in {"cacert", "cert", "key", "token"} and ".puppetdb" in address:
            changes.append(
                _change(
                    address,
                    "bolt_credential_file_boundary",
                    "review",
                    "Bolt depends on an external PuppetDB trust or credential file.",
                )
            )
        if key == "trusted-external-command" and isinstance(value, str):
            changes.append(
                _change(
                    address,
                    "bolt_external_command",
                    "dangerous",
                    "Bolt executes an external controller command to produce trusted facts.",
                )
            )
        if key in {"evaltrace", "show_diff", "trace"} and value is True:
            changes.append(
                _change(
                    address,
                    "bolt_sensitive_output",
                    "dangerous",
                    "Bolt enables verbose apply output that can disclose sensitive resource "
                    "values or execution context.",
                )
            )
        if key == "log_level" and str(value).casefold() == "debug":
            changes.append(
                _change(
                    address,
                    "bolt_debug_logging",
                    "dangerous",
                    "Bolt enables debug apply logs that can persist sensitive execution details.",
                )
            )
        if key == "plugin" and ".plugin-hooks." in address and isinstance(value, str):
            run_as = document.get("plugin-hooks", {})
            changes.append(
                _change(
                    address,
                    "bolt_plugin_hook",
                    "dangerous" if "root" in str(run_as).casefold() else "review",
                    "Bolt configures a plugin hook that installs or prepares executable Puppet "
                    "content on targets.",
                )
            )
    return changes


def _bolt_inventory_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes = _bolt_plugin_changes(document, inventory=True)
    changes.extend(_bolt_literal_secret_changes(document, "bolt_inventory"))
    target_count = 0
    for address, key, value in _bolt_walk(document, "bolt_inventory"):
        if key == "targets" and isinstance(value, list):
            target_count += len(value)
            for index, target in enumerate(value):
                if not isinstance(target, str):
                    continue
                target_address = f"{address}.{index}"
                if target.casefold().startswith("http://"):
                    changes.append(
                        _change(
                            target_address,
                            "bolt_plaintext_transport",
                            "dangerous",
                            "Bolt connects to a target over plaintext HTTP.",
                        )
                    )
                if target.casefold().startswith("local://"):
                    changes.append(
                        _change(
                            target_address,
                            "bolt_transport",
                            "dangerous",
                            "Bolt target URI selects local controller execution.",
                        )
                    )
                if _embedded_credential(target):
                    changes.append(
                        _change(
                            target_address,
                            "bolt_embedded_credential",
                            "dangerous",
                            "Bolt target URI embeds credentials that can leak through "
                            "configuration, logs, and process metadata.",
                        )
                    )
        if (
            key in {"uri", "service-url"}
            and isinstance(value, str)
            and value.casefold().startswith("http://")
        ):
            changes.append(
                _change(
                    address,
                    "bolt_plaintext_transport",
                    "dangerous",
                    "Bolt connects to a target or service over plaintext HTTP.",
                )
            )
        if key in {"uri", "service-url"} and isinstance(value, str) and _embedded_credential(value):
            changes.append(
                _change(
                    address,
                    "bolt_embedded_credential",
                    "dangerous",
                    "Bolt target or service URL embeds credentials that can leak through "
                    "configuration, logs, and process metadata.",
                )
            )
        if key in {"host-key-check", "ssl-verify"} and value is False:
            changes.append(
                _change(
                    address,
                    "bolt_transport_verification",
                    "dangerous",
                    "Bolt disables SSH host-key or TLS certificate verification, allowing "
                    "endpoint impersonation.",
                )
            )
        if key == "ssl" and value is False:
            changes.append(
                _change(
                    address,
                    "bolt_plaintext_transport",
                    "dangerous",
                    "Bolt disables HTTPS for WinRM transport.",
                )
            )
        if key == "cleanup" and value is False:
            changes.append(
                _change(
                    address,
                    "bolt_remote_cleanup",
                    "review",
                    "Bolt leaves temporary executable files on targets after commands finish.",
                )
            )
        if (
            key in {"user", "run-as"}
            and isinstance(value, str)
            and value.casefold() in _BOLT_PRIVILEGED_USERS
        ):
            changes.append(
                _change(
                    address,
                    "bolt_privileged_identity",
                    "dangerous",
                    "Bolt logs in or executes commands with a highly privileged identity.",
                )
            )
        if key in {"run-as-command", "shell-command", "sudo-executable", "interpreters"}:
            changes.append(
                _change(
                    address,
                    "bolt_command_execution",
                    "dangerous",
                    "Bolt overrides a command, interpreter, or privilege-escalation executable "
                    "used on targets.",
                )
            )
        if key == "transport" and isinstance(value, str):
            risk = "dangerous" if value.casefold() == "local" else "review"
            changes.append(
                _change(
                    address,
                    "bolt_transport",
                    risk,
                    "Bolt selects local controller execution."
                    if risk == "dangerous"
                    else "Bolt selects a target transport; verify the effective inherited "
                    "connection policy.",
                )
            )
        if key in {"proxyjump", "private-key", "token-file", "cacert", "cert", "key"}:
            changes.append(
                _change(
                    address,
                    "bolt_credential_or_proxy_boundary",
                    "review",
                    "Bolt depends on an external credential, trust file, private key, or proxy "
                    "boundary.",
                )
            )
        if key in {
            "encryption-algorithms",
            "host-key-algorithms",
            "kex-algorithms",
            "mac-algorithms",
        }:
            encoded = " ".join(map(str, value if isinstance(value, list) else [value])).casefold()
            if any(marker in encoded for marker in ("cbc", "dss", "group1", "md5", "sha1")):
                changes.append(
                    _change(
                        address,
                        "bolt_legacy_ssh_algorithm",
                        "dangerous",
                        "Bolt enables legacy SSH algorithms that weaken transport security.",
                    )
                )
    if target_count:
        changes.append(
            _change(
                "bolt_inventory.targets",
                "bolt_target_scope",
                "review",
                f"Bolt inventory statically selects {target_count} target declaration(s); "
                "verify group inheritance and command targeting.",
            )
        )
    return changes


def _r10k_endpoint_risk(value: str) -> tuple[str, list[str]]:
    risk, reasons = _source_risks(value)
    if _R10K_DYNAMIC.search(value):
        risk = "dangerous"
        reasons.append("The endpoint is dynamically interpolated at deployment time.")
    try:
        parsed = urlsplit(value.removeprefix("git+"))
    except ValueError:
        parsed = None
    if parsed and re.search(
        r"(?:^|&)(?:access_?token|api_?key|client_?secret|password|secret|token)=",
        parsed.query,
        re.IGNORECASE,
    ):
        risk = "dangerous"
        reasons.append("The endpoint query contains credential-like parameters.")
    return risk, reasons


def _r10k_endpoint_change(
    address: str,
    kind: str,
    value: str,
    explanation: str,
    *,
    mutable: bool = False,
) -> dict[str, str]:
    risk, reasons = _r10k_endpoint_risk(value)
    if mutable:
        risk = "dangerous"
        reasons.insert(
            0,
            "Branches from this repository can become executable Puppet environments.",
        )
    if not reasons:
        reasons.append("The endpoint uses an authenticated or encrypted transport shape.")
    return _change(address, kind, risk, f"{explanation} {' '.join(reasons)}")


def _r10k_path_is_relative(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return not path.is_absolute() and not bool(re.match(r"^[A-Za-z]:/", normalized))


def _r10k_path_has_traversal(value: str) -> bool:
    normalized = value.replace("\\", "/")
    return ".." in PurePosixPath(normalized).parts or bool(urlsplit(normalized).scheme)


def _r10k_path_contains(parent: str, child: str) -> bool:
    normalized_parent = parent.replace("\\", "/").rstrip("/")
    normalized_child = child.replace("\\", "/").rstrip("/")
    return bool(normalized_parent) and (
        normalized_child == normalized_parent
        or normalized_child.startswith(f"{normalized_parent}/")
    )


def _r10k_sources(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    sources = list(document.get("sources", {}).items())
    if "remote" in document:
        sources.append(
            (
                "legacy",
                {
                    "remote": document["remote"],
                    "basedir": document.get("r10k_basedir", ""),
                    "type": "git",
                    "legacy": True,
                },
            )
        )
    return sources


def _r10k_source_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    sources = _r10k_sources(document)
    basedirs: dict[str, list[dict[str, Any]]] = {}
    for index, (_, source) in enumerate(sources, start=1):
        address = f"r10k.sources.{index}"
        source_type = str(source.get("type", "git")).casefold()
        remote = str(source.get("remote", ""))
        basedir = str(source.get("basedir", ""))
        if source.get("legacy"):
            changes.append(
                _change(
                    f"{address}.legacy",
                    "r10k_legacy_source",
                    "review",
                    "r10k uses the legacy global remote/r10k_basedir source form; migrate to a "
                    "named sources mapping before adding another control repository.",
                )
            )
        if remote:
            changes.append(
                _r10k_endpoint_change(
                    f"{address}.remote",
                    "r10k_environment_source",
                    remote,
                    "r10k fetches a control repository to create Puppet environments.",
                    mutable=True,
                )
            )
        elif source_type == "git":
            changes.append(
                _change(
                    f"{address}.remote",
                    "r10k_environment_source",
                    "dangerous",
                    "The Git environment source has no static remote, so deployed code provenance "
                    "cannot be established.",
                )
            )
        if basedir:
            risk = "dangerous"
            reasons = [
                "r10k fully manages this environment directory and can remove unmanaged content."
            ]
            if _r10k_path_is_relative(basedir) or _r10k_path_has_traversal(basedir):
                reasons.append("The directory is relative or contains parent traversal.")
            if basedir.replace("\\", "/").rstrip("/") in {"", "/", "/etc", "/opt", "/var"}:
                reasons.append("The target is an unusually broad system directory.")
            changes.append(
                _change(
                    f"{address}.basedir",
                    "r10k_environment_target",
                    risk,
                    " ".join(reasons),
                )
            )
            basedirs.setdefault(basedir.replace("\\", "/").rstrip("/").casefold(), []).append(
                source
            )
        else:
            changes.append(
                _change(
                    f"{address}.basedir",
                    "r10k_environment_target",
                    "dangerous",
                    "The environment source has no static basedir; verify the effective Puppet "
                    "environmentpath before deployment.",
                )
            )
        if source_type == "exec" or source.get("command"):
            changes.append(
                _change(
                    f"{address}.command",
                    "r10k_source_command",
                    "dangerous",
                    "The environment source executes an external command to discover deployable "
                    "environments.",
                )
            )
        elif source_type not in {"git", "svn", "yaml", "yamldir"}:
            changes.append(
                _change(
                    f"{address}.type",
                    "r10k_custom_source",
                    "dangerous",
                    "The environment source uses a custom provider whose code and provenance are "
                    "not available in this configuration.",
                )
            )
        if source.get("filter_command"):
            changes.append(
                _change(
                    f"{address}.filter_command",
                    "r10k_branch_filter_command",
                    "dangerous",
                    "r10k executes a shell command for every candidate branch while selecting "
                    "Puppet environments.",
                )
            )
        if source.get("invalid_branches", "correct_and_warn") != "error":
            changes.append(
                _change(
                    f"{address}.invalid_branches",
                    "r10k_branch_normalization",
                    "review",
                    "Invalid Git branch names can be corrected into Puppet environment names; "
                    "review normalization collisions and rejected branches.",
                )
            )
        if source.get("prefix") in {False, None, ""}:
            changes.append(
                _change(
                    f"{address}.prefix",
                    "r10k_environment_namespace",
                    "review",
                    "The source does not namespace generated environment names with a prefix.",
                )
            )
        if source.get("strip_component"):
            changes.append(
                _change(
                    f"{address}.strip_component",
                    "r10k_branch_mapping",
                    "review",
                    "r10k rewrites branch names before mapping them to Puppet environments.",
                )
            )
        if source.get("ignore_branch_prefixes"):
            changes.append(
                _change(
                    f"{address}.ignore_branch_prefixes",
                    "r10k_branch_scope",
                    "review",
                    "The source excludes branch prefixes from environment deployment; verify that "
                    "the filter covers every non-deployable branch class.",
                )
            )
        if source.get("puppetfile_name"):
            changes.append(
                _change(
                    f"{address}.puppetfile_name",
                    "r10k_puppetfile_boundary",
                    "review",
                    "The source selects a non-default Puppetfile whose module graph must be "
                    "reviewed separately.",
                )
            )
        if source.get("overrides"):
            changes.append(
                _change(
                    f"{address}.overrides",
                    "r10k_source_override",
                    "dangerous",
                    "Source-specific overrides can replace effective module or deployment "
                    "settings.",
                )
            )
    for index, grouped in enumerate(basedirs.values(), start=1):
        if len(grouped) < 2:
            continue
        unprefixed = sum(source.get("prefix") in {False, None, ""} for source in grouped)
        if unprefixed > 1:
            changes.append(
                _change(
                    f"r10k.basedir_collisions.{index}",
                    "r10k_environment_collision",
                    "dangerous",
                    "Multiple unprefixed sources manage the same basedir, so identical branch "
                    "names can collide or overwrite environment state.",
                )
            )
    return changes


def _r10k_git_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    git = document.get("git", {})
    if not git:
        return []
    changes: list[dict[str, str]] = []
    if "provider" in git:
        provider = str(git["provider"]).casefold()
        risk = "review" if provider in {"rugged", "shellgit"} else "dangerous"
        explanation = (
            "r10k delegates repository operations to the system Git executable."
            if provider == "shellgit"
            else "r10k selects a Git provider that determines credential, proxy, and transport "
            "behavior."
        )
        changes.append(_change("r10k.git.provider", "r10k_git_provider", risk, explanation))
    if "default_ref" in git:
        default_ref = str(git["default_ref"])
        pinned = bool(_COMMIT.fullmatch(default_ref))
        changes.append(
            _change(
                "r10k.git.default_ref",
                "r10k_default_revision",
                "review" if pinned else "dangerous",
                "The default module revision is pinned to an immutable commit."
                if pinned
                else "Modules without an explicit ref follow a mutable or dynamic default "
                "revision.",
            )
        )
    for key in ("private_key", "oauth_token", "github_app_id", "github_app_key"):
        if key in git:
            changes.append(
                _change(
                    f"r10k.git.{key}",
                    "r10k_git_credential",
                    "review",
                    "r10k reads Git authentication material from an external credential or key "
                    "boundary; verify file ownership, scope, and rotation.",
                )
            )
    if "proxy" in git:
        changes.append(
            _r10k_endpoint_change(
                "r10k.git.proxy",
                "r10k_git_proxy",
                str(git["proxy"]),
                "r10k routes Git HTTP operations through a configured proxy.",
            )
        )
    for index, repository in enumerate(git.get("repositories", []), start=1):
        remote = str(repository["remote"])
        changes.append(
            _r10k_endpoint_change(
                f"r10k.git.repositories.{index}.remote",
                "r10k_repository_override",
                remote,
                "r10k applies repository-specific Git behavior to a remote.",
            )
        )
        if any(
            key in repository
            for key in ("private_key", "oauth_token", "github_app_id", "github_app_key")
        ):
            changes.append(
                _change(
                    f"r10k.git.repositories.{index}.credentials",
                    "r10k_git_credential",
                    "review",
                    "A repository selects dedicated authentication material; verify least "
                    "privilege, file permissions, and rotation.",
                )
            )
        if "proxy" in repository:
            changes.append(
                _r10k_endpoint_change(
                    f"r10k.git.repositories.{index}.proxy",
                    "r10k_git_proxy",
                    str(repository["proxy"]),
                    "A repository overrides the global Git proxy.",
                )
            )
    return changes


def _r10k_forge_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    forge = document.get("forge", {})
    changes: list[dict[str, str]] = []
    if "baseurl" in forge:
        changes.append(
            _r10k_endpoint_change(
                "r10k.forge.baseurl",
                "r10k_forge_endpoint",
                str(forge["baseurl"]),
                "r10k downloads executable Puppet modules from a configured Forge endpoint.",
            )
        )
    if "proxy" in forge:
        changes.append(
            _r10k_endpoint_change(
                "r10k.forge.proxy",
                "r10k_forge_proxy",
                str(forge["proxy"]),
                "r10k routes Forge downloads through a configured proxy.",
            )
        )
    if "authorization_token" in forge:
        changes.append(
            _change(
                "r10k.forge.authorization_token",
                "r10k_literal_credential",
                "dangerous",
                "The r10k file contains a literal Forge authorization token; move it to a "
                "protected external secret boundary and rotate exposed values.",
            )
        )
    if forge.get("allow_puppetfile_override") is True:
        changes.append(
            _change(
                "r10k.forge.allow_puppetfile_override",
                "r10k_forge_override",
                "dangerous",
                "Puppetfiles can override the centrally configured Forge endpoint, expanding the "
                "module supply-chain trust boundary.",
            )
        )
    return changes


def _r10k_deploy_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    deploy = document.get("deploy", {})
    changes: list[dict[str, str]] = []
    if "purgedirs" in document:
        changes.append(
            _change(
                "r10k.purgedirs",
                "r10k_deprecated_purge",
                "dangerous",
                "The deprecated purgedirs setting is no longer respected, creating false "
                "assurance about deletion scope.",
            )
        )
    if "purge_levels" in deploy:
        levels = {str(level).casefold() for level in deploy["purge_levels"]}
        risk = "dangerous" if levels else "review"
        reasons = ["r10k removes unmanaged content at configured deployment levels."]
        if "environment" in levels:
            reasons.append(
                "Environment-level purge can delete unmanaged files inside environments."
            )
        changes.append(
            _change(
                "r10k.deploy.purge_levels",
                "r10k_purge_scope",
                risk,
                " ".join(reasons),
            )
        )
    if "purge_allowlist" in deploy:
        broad = any(str(item).strip() in {"*", "**", "**/*"} for item in deploy["purge_allowlist"])
        changes.append(
            _change(
                "r10k.deploy.purge_allowlist",
                "r10k_purge_exception",
                "dangerous" if broad else "review",
                "The purge allowlist is broad enough to defeat expected cleanup."
                if broad
                else "Purge exceptions preserve unmanaged paths; review patterns against the "
                "effective environment layout.",
            )
        )
    if deploy.get("generate_types") is True:
        changes.append(
            _change(
                "r10k.deploy.generate_types",
                "r10k_type_generation",
                "dangerous",
                "r10k invokes Puppet type generation after deployment, executing code from the "
                "new environment.",
            )
        )
    if "puppet_path" in deploy:
        changes.append(
            _change(
                "r10k.deploy.puppet_path",
                "r10k_executable_path",
                "dangerous",
                "r10k executes a configured Puppet binary during deployment workflows.",
            )
        )
    if "puppet_conf" in deploy:
        changes.append(
            _change(
                "r10k.deploy.puppet_conf",
                "r10k_puppet_config_boundary",
                "review",
                "r10k reads an external puppet.conf whose environmentpath and runtime settings "
                "must match deployment targets.",
            )
        )
    if deploy.get("exclude_spec") is False:
        changes.append(
            _change(
                "r10k.deploy.exclude_spec",
                "r10k_deployment_content",
                "review",
                "r10k deploys module test/spec content into live Puppet environments.",
            )
        )
    if "write_lock" in deploy:
        changes.append(
            _change(
                "r10k.deploy.write_lock",
                "r10k_deployment_lock",
                "review",
                "A deployment write lock is configured; verify orchestration honors the lock "
                "before changing code state.",
            )
        )
    return changes


def _r10k_operational_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    cachedir = str(document.get("cachedir", ""))
    if cachedir:
        reasons = ["r10k stores mirrored Git repositories in a persistent local cache."]
        risk = "review"
        if _r10k_path_is_relative(cachedir) or _r10k_path_has_traversal(cachedir):
            risk = "dangerous"
            reasons.append("The cache path is relative or contains parent traversal.")
        for _, source in _r10k_sources(document):
            basedir = str(source.get("basedir", ""))
            if basedir and (
                _r10k_path_contains(basedir, cachedir) or _r10k_path_contains(cachedir, basedir)
            ):
                risk = "dangerous"
                reasons.append("The cache and managed environment directory overlap.")
                break
        changes.append(
            _change(
                "r10k.cachedir",
                "r10k_repository_cache",
                risk,
                " ".join(reasons),
            )
        )
    if "proxy" in document:
        changes.append(
            _r10k_endpoint_change(
                "r10k.proxy",
                "r10k_global_proxy",
                str(document["proxy"]),
                "r10k routes global HTTP and HTTPS operations through a configured proxy.",
            )
        )
    if "postrun" in document:
        changes.append(
            _change(
                "r10k.postrun",
                "r10k_postrun_command",
                "dangerous",
                "r10k executes a configured command after deploying environments or modules.",
            )
        )
    if "pool_size" in document:
        pool_size = int(document["pool_size"])
        changes.append(
            _change(
                "r10k.pool_size",
                "r10k_deployment_concurrency",
                "dangerous" if pool_size > 16 else "review",
                "High deployment concurrency can amplify repository, filesystem, and Puppet "
                "environment races."
                if pool_size > 16
                else "r10k installs modules concurrently; verify repository and filesystem limits.",
            )
        )
    logging = document.get("logging", {})
    if str(logging.get("level", "")).casefold() in {"debug", "debug1", "debug2"}:
        changes.append(
            _change(
                "r10k.logging.level",
                "r10k_debug_logging",
                "review",
                "Debug logging can expose repository, proxy, branch, command, and filesystem "
                "metadata.",
            )
        )
    if logging.get("outputs"):
        changes.append(
            _change(
                "r10k.logging.outputs",
                "r10k_log_destination",
                "review",
                "r10k sends deployment logs to additional plugin-defined destinations.",
            )
        )
    if logging.get("disable_default_stderr") is True:
        changes.append(
            _change(
                "r10k.logging.disable_default_stderr",
                "r10k_observability",
                "review",
                "r10k disables its default stderr output; ensure failures remain visible to "
                "automation and operators.",
            )
        )
    return changes


def _r10k_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    return [
        *_r10k_source_changes(document),
        *_r10k_git_changes(document),
        *_r10k_forge_changes(document),
        *_r10k_deploy_changes(document),
        *_r10k_operational_changes(document),
    ]


def _setting_value(document: dict[str, Any], name: str) -> str:
    setting = document.get("settings", {}).get(name, {})
    return str(setting.get("value", "")).strip() if isinstance(setting, dict) else ""


def _environment_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    modulepath = _setting_value(document, "modulepath")
    if modulepath:
        paths = [item.strip() for item in re.split(r"[:;]", modulepath) if item.strip()]
        external = sum(
            1
            for item in paths
            if _path_escapes(item) and not item.startswith(("$codedir", "$basemodulepath"))
        )
        changes.append(
            _change(
                "environment.modulepath",
                "environment_module_path",
                "dangerous" if external else "review",
                f"The environment loads executable Puppet modules from {len(paths)} path entry or "
                "entries; "
                + (
                    f"{external} entry or entries escape the environment or standard interpolated "
                    "code roots."
                    if external
                    else "review path precedence and deployed module ownership."
                ),
            )
        )
    manifest = _setting_value(document, "manifest")
    if manifest:
        external = _path_escapes(manifest) and not manifest.startswith("$codedir")
        changes.append(
            _change(
                "environment.manifest",
                "environment_manifest",
                "dangerous" if external else "review",
                "The environment overrides its main manifest with content outside the environment "
                "directory."
                if external
                else "The environment overrides its main manifest; verify the selected Puppet "
                "code and alphabetical directory evaluation order.",
            )
        )
    config_version = _setting_value(document, "config_version")
    if config_version:
        changes.append(
            _change(
                "environment.config_version",
                "environment_config_version_command",
                "dangerous",
                "Puppet Server executes the environment's config-version command during catalog "
                "compilation; verify the executable, arguments, ownership, and output handling.",
            )
        )
    timeout = _setting_value(document, "environment_timeout").casefold()
    if timeout:
        supported = timeout in {"0", "unlimited"} or bool(
            re.fullmatch(r"\d+(?:\.\d+)?(?:ms|s|m|h|d|y)?", timeout)
        )
        if not supported:
            changes.append(
                _change(
                    "environment.environment_timeout",
                    "environment_cache_timeout",
                    "dangerous",
                    "The environment cache timeout is not a static Puppet duration, zero, or "
                    "unlimited value.",
                )
            )
        elif timeout == "unlimited":
            changes.append(
                _change(
                    "environment.environment_timeout",
                    "environment_cache_refresh",
                    "review",
                    "The environment remains cached until an explicit refresh or server restart; "
                    "the deployment workflow must invalidate the cache after code changes.",
                )
            )
        elif timeout == "0":
            changes.append(
                _change(
                    "environment.environment_timeout",
                    "environment_cache_disabled",
                    "review",
                    "Environment caching is disabled, reducing stale-code risk but increasing "
                    "catalog compilation and module-loading pressure.",
                )
            )
    return changes


def _puppetdb_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    settings = document.get("sections", {}).get("main", {})
    changes: list[dict[str, str]] = []

    def value(name: str) -> str:
        entry = settings.get(name, {})
        return str(entry.get("value", "")).strip() if isinstance(entry, dict) else ""

    endpoints: list[str] = []
    for key in ("server_urls", "submit_only_server_urls"):
        raw = value(key)
        if not raw:
            continue
        urls = [item.strip() for item in raw.split(",") if item.strip()]
        endpoints.extend(urls)
        insecure = sum(1 for item in urls if not item.casefold().startswith("https://"))
        credentials = sum(1 for item in urls if _embedded_credential(item))
        changes.append(
            _change(
                f"puppetdb.{key}",
                "puppetdb_endpoint",
                "dangerous" if insecure or credentials else "review",
                f"Puppet Server sends catalog, fact, report, or query data to {len(urls)} PuppetDB "
                "endpoint(s); "
                + (
                    f"{insecure} endpoint(s) are not HTTPS and {credentials} embed credentials."
                    if insecure or credentials
                    else "review certificate trust, data scope, failover order, and ownership."
                ),
            )
        )
    if not endpoints:
        changes.append(
            _change(
                "puppetdb.server_urls",
                "puppetdb_endpoint_boundary",
                "review",
                "PuppetDB endpoints are selected by defaults or another configuration layer; "
                "verify the effective HTTPS destinations and certificate trust.",
            )
        )
    if value("soft_write_failure").casefold() in {"true", "yes", "1"}:
        changes.append(
            _change(
                "puppetdb.soft_write_failure",
                "puppetdb_fail_open",
                "dangerous",
                "Puppet Server continues compiling and serving catalogs when PuppetDB command "
                "submission fails, allowing catalog/report/fact persistence to diverge.",
            )
        )
    if value("command_broadcast").casefold() in {"true", "yes", "1"}:
        changes.append(
            _change(
                "puppetdb.command_broadcast",
                "puppetdb_command_broadcast",
                "review",
                "PuppetDB commands are broadcast to multiple servers; verify every destination's "
                "trust, retention, capacity, and consistency policy.",
            )
        )
    minimum = value("min_successful_submissions")
    if minimum:
        try:
            minimum_count = int(minimum)
        except ValueError:
            minimum_count = 0
        if minimum_count < 1 or (len(endpoints) > 1 and minimum_count < len(endpoints)):
            changes.append(
                _change(
                    "puppetdb.min_successful_submissions",
                    "puppetdb_submission_quorum",
                    "dangerous",
                    "The successful-submission threshold is invalid or lower than the configured "
                    "PuppetDB destination count, permitting partial persistence.",
                )
            )
    timeout = value("server_url_timeout")
    if timeout:
        try:
            timeout_value = float(timeout)
        except ValueError:
            timeout_value = -1
        if timeout_value <= 0:
            changes.append(
                _change(
                    "puppetdb.server_url_timeout",
                    "puppetdb_timeout",
                    "dangerous",
                    "The PuppetDB request timeout is non-positive or dynamic, which can break "
                    "failure detection and endpoint failover.",
                )
            )
    return changes


def _server_config(document: dict[str, Any], section: str) -> dict[str, Any]:
    config = document.get("config", {})
    if not isinstance(config, dict):
        return {}
    selected = config.get(section, config)
    return selected if isinstance(selected, dict) else {}


def _hocon_boundary_changes(document: dict[str, Any], label: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    includes = int(document.get("include_count", 0))
    substitutions = int(document.get("substitution_count", 0))
    if includes:
        changes.append(
            _change(
                f"{label}.includes",
                "server_hocon_include",
                "dangerous",
                f"The Puppet Server configuration imports {includes} external HOCON source(s); "
                "their effective policy is not present in this artifact.",
            )
        )
    if substitutions:
        changes.append(
            _change(
                f"{label}.substitutions",
                "server_hocon_substitution",
                "review",
                f"The Puppet Server configuration resolves {substitutions} HOCON substitution(s) "
                "from environment or merged configuration at startup.",
            )
        )
    return changes


def _contains_wildcard(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip() == "*" or value.startswith("/.*")
    if isinstance(value, list):
        return any(_contains_wildcard(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_wildcard(item) for item in value.values())
    return False


def _server_auth_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    auth = _server_config(document, "authorization")
    changes = _hocon_boundary_changes(document, "server_auth")
    if auth.get("version") != 1:
        changes.append(
            _change(
                "server_auth.version",
                "server_auth_version",
                "dangerous",
                "Puppet Server authorization must declare static HOCON policy version 1.",
            )
        )
    if auth.get("allow-header-cert-info") is True:
        changes.append(
            _change(
                "server_auth.allow_header_cert_info",
                "server_header_identity",
                "dangerous",
                "Puppet Server ignores presented client certificates and trusts X-Client headers "
                "for identity; network and proxy spoofing controls become security-critical.",
            )
        )
    rules = auth.get("rules")
    if not isinstance(rules, list):
        changes.append(
            _change(
                "server_auth.rules",
                "server_auth_rules",
                "dangerous",
                "Puppet Server authorization does not declare a static rules array.",
            )
        )
        return changes
    for index, rule in enumerate(rules, start=1):
        address = f"server_auth.rules.{index}"
        if not isinstance(rule, dict):
            changes.append(
                _change(
                    address,
                    "server_auth_rule",
                    "dangerous",
                    "An authorization rule is not a static mapping.",
                )
            )
            continue
        match = rule.get("match-request", {})
        if not isinstance(match, dict) or not match.get("path") or not match.get("type"):
            changes.append(
                _change(
                    f"{address}.match",
                    "server_auth_match",
                    "dangerous",
                    "An authorization rule lacks a static request path or match type.",
                )
            )
            match = {}
        path = str(match.get("path", ""))
        broad_path = path in {"/", ".*", "^/.*", "^/.*$"} or path.startswith(".*")
        methods = match.get("method")
        method_values = methods if isinstance(methods, list) else [methods] if methods else []
        mutating = any(
            str(method).casefold() in {"delete", "post", "put"} for method in method_values
        )
        if rule.get("allow-unauthenticated") is True:
            changes.append(
                _change(
                    f"{address}.unauthenticated",
                    "server_unauthenticated_access",
                    "dangerous",
                    "An authorization rule permits unauthenticated requests to a Puppet Server "
                    "API surface.",
                )
            )
        if _contains_wildcard(rule.get("allow")):
            changes.append(
                _change(
                    f"{address}.allow",
                    "server_wildcard_identity",
                    "dangerous",
                    "An authorization rule allows a wildcard or match-all client identity.",
                )
            )
        if broad_path or not method_values:
            changes.append(
                _change(
                    f"{address}.scope",
                    "server_broad_authorization",
                    "dangerous",
                    "An authorization rule matches a broad path or every HTTP method, expanding "
                    "access beyond a narrowly scoped API operation.",
                )
            )
        if mutating and any(marker in path for marker in ("admin", "certificate", "environment")):
            changes.append(
                _change(
                    f"{address}.mutation",
                    "server_privileged_api",
                    "dangerous",
                    "An authorization rule grants mutating access to an administrative, "
                    "certificate, or environment-cache API.",
                )
            )
        order = rule.get("sort-order")
        if isinstance(order, (int, float)) and 1 <= order <= 399:
            changes.append(
                _change(
                    f"{address}.sort_order",
                    "server_auth_precedence",
                    "dangerous",
                    "An authorization rule is evaluated before Puppet's default rules and can "
                    "override their effective protection.",
                )
            )
        if not rule.get("name") or order is None:
            changes.append(
                _change(
                    f"{address}.required",
                    "server_auth_rule_metadata",
                    "dangerous",
                    "An authorization rule omits its required static name or sort order.",
                )
            )
    return changes


def _server_web_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    web = _server_config(document, "webserver")
    changes = _hocon_boundary_changes(document, "server_web")
    client_auth = str(web.get("client-auth", "")).casefold()
    if client_auth and client_auth != "need":
        changes.append(
            _change(
                "server_web.client_auth",
                "server_client_authentication",
                "dangerous",
                "The HTTPS listener does not require a valid client certificate for every "
                "connection.",
            )
        )
    if any(key in web for key in ("host", "port")) or web.get("ssl-enabled") is False:
        changes.append(
            _change(
                "server_web.plaintext",
                "server_plaintext_listener",
                "dangerous",
                "Puppet Server declares a plaintext HTTP listener or disables its HTTPS listener.",
            )
        )
    ssl_host = str(web.get("ssl-host", ""))
    if ssl_host in {"0.0.0.0", "::", "*"}:
        changes.append(
            _change(
                "server_web.ssl_host",
                "server_network_exposure",
                "review",
                "The Puppet Server HTTPS listener binds all interfaces; verify firewall, load "
                "balancer, and administrative API reachability.",
            )
        )
    protocols = web.get("ssl-protocols", [])
    protocol_values = protocols if isinstance(protocols, list) else [protocols]
    if any(
        str(item).casefold() in {"sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"} for item in protocol_values
    ):
        changes.append(
            _change(
                "server_web.ssl_protocols",
                "server_legacy_tls",
                "dangerous",
                "The Puppet Server listener enables a legacy SSL/TLS protocol.",
            )
        )
    if web.get("ssl-renegotiation-allowed") is True:
        changes.append(
            _change(
                "server_web.ssl_renegotiation",
                "server_tls_renegotiation",
                "dangerous",
                "The Puppet Server listener permits TLS renegotiation, increasing "
                "denial-of-service and legacy protocol risk.",
            )
        )
    custom_tls = any(key in web for key in ("ssl-cert", "ssl-key", "ssl-ca-cert"))
    if custom_tls and not all(
        key in web for key in ("ssl-cert", "ssl-key", "ssl-ca-cert", "ssl-crl-path")
    ):
        changes.append(
            _change(
                "server_web.tls_material",
                "server_tls_material",
                "dangerous",
                "Custom TLS material is incomplete or omits a CRL path; verify certificate, key, "
                "CA chain, revocation, ownership, and file permissions.",
            )
        )
    if not web.get("access-log-config"):
        changes.append(
            _change(
                "server_web.access_log",
                "server_access_logging",
                "review",
                "The file does not configure HTTP access logging; verify effective request audit "
                "coverage and sensitive-field redaction.",
            )
        )
    return changes


def _server_ca_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    ca = _server_config(document, "certificate-authority")
    changes = _hocon_boundary_changes(document, "server_ca")
    if ca.get("allow-subject-alt-names") is True:
        changes.append(
            _change(
                "server_ca.subject_alt_names",
                "server_ca_subject_alt_names",
                "dangerous",
                "The CA can sign requested subject alternative names, allowing a compromised or "
                "misreviewed CSR to impersonate other nodes.",
            )
        )
    if ca.get("allow-authorization-extensions") is True:
        changes.append(
            _change(
                "server_ca.authorization_extensions",
                "server_ca_authorization_extensions",
                "dangerous",
                "The CA can sign authorization extensions that may grant privileged Puppet Server "
                "API identities.",
            )
        )
    if ca.get("enable-infra-crl") is False:
        changes.append(
            _change(
                "server_ca.infrastructure_crl",
                "server_ca_revocation_scope",
                "review",
                "The separate infrastructure-node CRL is explicitly disabled; verify revocation "
                "distribution and blast radius for agent and server certificates.",
            )
        )
    return changes


def _walk_mapping(value: Any) -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            found.append((str(key), item))
            found.extend(_walk_mapping(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_walk_mapping(item))
    return found


def _server_runtime_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    runtime = _server_config(document, "jruby-puppet")
    changes = _hocon_boundary_changes(document, "server_runtime")
    if "compat-version" in runtime:
        changes.append(
            _change(
                "server_runtime.compat_version",
                "server_removed_setting",
                "dangerous",
                "The removed JRuby compatibility setting prevents supported Puppet Server "
                "versions from starting.",
            )
        )
    for key in ("ruby-load-path", "gem-home", "gem-path"):
        if key in runtime:
            changes.append(
                _change(
                    f"server_runtime.{key.replace('-', '_')}",
                    "server_ruby_code_path",
                    "dangerous",
                    "Puppet Server loads Ruby or gem code from customized filesystem paths; verify "
                    "ownership, write permissions, package provenance, and path precedence.",
                )
            )
    environment = runtime.get("environment-vars", {})
    environment_secret_count = 0
    if isinstance(environment, dict) and environment:
        environment_secret_count = sum(
            1
            for key, value in environment.items()
            if _SECRET.search(str(key))
            and not isinstance(value, (dict, list))
            and value not in (None, "", "<unresolved-hocon-substitution>")
        )
        protected = sum(
            1 for key in environment if str(key).upper() in {"GEM_HOME", "HOME", "PATH"}
        )
        changes.append(
            _change(
                "server_runtime.environment_vars",
                "server_jruby_environment",
                "dangerous" if environment_secret_count or protected else "review",
                f"Puppet Server injects {len(environment)} environment variable(s) into JRuby; "
                f"{environment_secret_count} contain literal secret-like values and {protected} "
                "override protected runtime paths or homes.",
            )
        )
    active = runtime.get("max-active-instances")
    if isinstance(active, (int, float)) and active > 12:
        changes.append(
            _change(
                "server_runtime.max_active_instances",
                "server_jruby_concurrency",
                "review",
                "The configured JRuby concurrency exceeds twelve instances and can amplify memory, "
                "code-cache, PuppetDB, and compile-primary pressure.",
            )
        )
    if runtime.get("max-requests-per-instance") == 0:
        changes.append(
            _change(
                "server_runtime.max_requests_per_instance",
                "server_jruby_recycling",
                "review",
                "JRuby instances are never recycled by request count, so extension memory/state "
                "growth persists until another lifecycle event or restart.",
            )
        )
    if runtime.get("multithreaded") is True:
        changes.append(
            _change(
                "server_runtime.multithreaded",
                "server_jruby_multithreading",
                "review",
                "Puppet Server shares one multithreaded JRuby runtime; verify custom functions, "
                "providers, and extensions are thread-safe.",
            )
        )
    literal_secrets = max(
        0,
        sum(
            1
            for key, value in _walk_mapping(runtime)
            if _SECRET.search(key)
            and not isinstance(value, (dict, list))
            and value not in (None, "", "<unresolved-hocon-substitution>")
        )
        - environment_secret_count,
    )
    if literal_secrets:
        changes.append(
            _change(
                "server_runtime.literal_secrets",
                "server_literal_secret",
                "dangerous",
                f"Puppet Server runtime configuration contains {literal_secrets} literal "
                "secret-like value(s).",
            )
        )
    return changes


def _server_routes_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    routes = _server_config(document, "web-router-service")
    changes = _hocon_boundary_changes(document, "server_routes")
    if routes:
        expected_routes = {
            "certificate-authority-service": "/puppet-ca",
            "master-service": "/puppet",
            "metrics-service": "/metrics",
            "puppet-admin-service": "/puppet-admin-api",
            "status-service": "/status",
        }
        admin = sum(
            1
            for key in routes
            if any(marker in key.casefold() for marker in ("admin", "metrics", "status", "ca."))
        )
        changed = 0
        for key, value in routes.items():
            expected = next(
                (route for marker, route in expected_routes.items() if marker in key.casefold()),
                None,
            )
            if expected is None or value != expected:
                changed += 1
        changes.append(
            _change(
                "server_routes.mounts",
                "server_api_routes",
                "dangerous" if changed else "review",
                f"Puppet Server customizes {len(routes)} web application mount(s), including "
                f"{admin} administrative, CA, metrics, or status service(s); authorization rules "
                f"and clients must match the effective routes. {changed} mount(s) differ from "
                "recognized defaults or target unrecognized services.",
            )
        )
    return changes


class PuppetProjectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "puppet-project"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        project = input_data.get("puppet_project")
        return (
            isinstance(project, dict)
            and project.get("artifact_type")
            in {
                "puppetfile",
                "metadata",
                "hiera",
                "config",
                "bolt_project",
                "bolt_inventory",
                "bolt_task_metadata",
                "bolt_yaml_plan",
                "environment",
                "puppetdb",
                "r10k",
                "server_auth",
                "server_ca",
                "server_routes",
                "server_runtime",
                "server_web",
            }
            and isinstance(project.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        project = input_data["puppet_project"]
        artifact_type = project["artifact_type"]
        changes = {
            "puppetfile": _puppetfile_changes,
            "metadata": _metadata_changes,
            "hiera": _hiera_changes,
            "config": _puppet_config_changes,
            "bolt_project": _bolt_project_changes,
            "bolt_inventory": _bolt_inventory_changes,
            "bolt_task_metadata": bolt_task_metadata_changes,
            "bolt_yaml_plan": bolt_yaml_plan_changes,
            "environment": _environment_changes,
            "puppetdb": _puppetdb_changes,
            "r10k": _r10k_changes,
            "server_auth": _server_auth_changes,
            "server_ca": _server_ca_changes,
            "server_routes": _server_routes_changes,
            "server_runtime": _server_runtime_changes,
            "server_web": _server_web_changes,
        }[artifact_type](project["document"])
        if artifact_type.startswith("bolt_"):
            boundary = (
                "Effective Bolt behavior also depends on configuration precedence, command-line "
                "options, installed modules and plugins, resolved inventory data, target facts "
                "and variables, credential files, environment values, and the tasks, plans, "
                "commands, scripts, and Puppet code selected at runtime."
            )
            address = "bolt.effective_project"
        elif artifact_type == "r10k":
            boundary = (
                "Effective r10k and Code Manager deployment also depends on command-line and "
                "environment overrides, enumerated remote branches, Git and Forge client trust, "
                "credential file contents, Puppetfiles and module locks, filesystem ownership, "
                "the effective Puppet environmentpath, deployment orchestration, hooks, and live "
                "server state; readtheplan does not fetch repositories or execute deployments."
            )
            address = "r10k.effective_deployment"
        elif artifact_type.startswith("server_"):
            boundary = (
                "Effective Puppet Server behavior also depends on merged conf.d files, HOCON "
                "includes and substitutions, command-line and service overrides, reverse proxy "
                "trust, filesystem permissions, certificates and CRLs, installed Ruby/Clojure "
                "extensions, network policy, and the live server version and state."
            )
            address = "puppet_server.effective_policy"
        elif artifact_type == "environment":
            boundary = (
                "Effective environment behavior also depends on global Puppet settings, deployed "
                "manifests and modules, Hiera data, path interpolation, environment-cache flushes, "
                "filesystem ownership, and the code deployment workflow."
            )
            address = "puppet_environment.effective_policy"
        elif artifact_type == "puppetdb":
            boundary = (
                "Effective PuppetDB behavior also depends on Puppet terminus routing, server and "
                "client certificates, DNS, load balancers, PuppetDB retention and authorization, "
                "command queues, endpoint health, and runtime overrides."
            )
            address = "puppetdb.effective_connection"
        else:
            boundary = (
                "Effective Puppet behavior also depends on deployed module contents, transitive "
                "dependencies, environment/modulepath precedence, Hiera data files, eyaml keys, "
                "Puppet Server configuration, PuppetDB, facts, compiler-side extensions, and any "
                "r10k or Code Manager configuration analyzed separately."
            )
            address = "puppet.effective_project"
        changes.append(_change(address, "project_boundary", "review", boundary))
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"puppet_project_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_puppet_project(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = PuppetProjectAdapter().analyze(data, tool_name="Puppet project")
    summary = PlanSummary(
        path=Path("puppet-project://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Puppet project")
    gate["adapter"] = "puppet-project"
    gate["artifact_type"] = data["puppet_project"]["artifact_type"]
    if data["puppet_project"]["artifact_type"] == "r10k":
        gate["source_count"] = len(_r10k_sources(data["puppet_project"]["document"]))
    if data["puppet_project"]["artifact_type"] == "server_auth":
        auth = _server_config(data["puppet_project"]["document"], "authorization")
        rules = auth.get("rules", [])
        gate["rule_count"] = len(rules) if isinstance(rules, list) else 0
    if data["puppet_project"]["artifact_type"] in {
        "bolt_task_metadata",
        "bolt_yaml_plan",
    }:
        gate.update(
            bolt_content_metadata(
                data["puppet_project"]["artifact_type"],
                data["puppet_project"]["document"],
            )
        )
    gate["total_changes"] = len(changes)
    return gate
