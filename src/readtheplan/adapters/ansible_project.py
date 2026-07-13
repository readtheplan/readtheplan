from __future__ import annotations

import configparser
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class AnsibleProjectInputError(ValueError):
    """Raised when input is not recognizable Ansible project configuration."""


_CONFIG_SECTIONS = {
    "defaults",
    "diff",
    "galaxy",
    "inventory",
    "paramiko_connection",
    "persistent_connection",
    "privilege_escalation",
    "selinux",
    "ssh_connection",
}
_PLUGIN_PATH_OPTIONS = {
    "action_plugins",
    "become_plugins",
    "cache_plugins",
    "callback_plugins",
    "cliconf_plugins",
    "connection_plugins",
    "filter_plugins",
    "httpapi_plugins",
    "inventory_plugins",
    "library",
    "lookup_plugins",
    "module_utils",
    "netconf_plugins",
    "shell_plugins",
    "strategy_plugins",
    "terminal_plugins",
    "test_plugins",
    "vars_plugins",
}
_SECRET_OPTIONS = re.compile(
    r"(?:password|passwd|token|secret|private.?key|client.?secret|api.?key|access.?key|auth.?key)",
    re.IGNORECASE,
)
_EXACT_VERSION = re.compile(r"(?:==)?(?:v)?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?$")
_COMMIT = re.compile(r"[0-9a-f]{40,64}$", re.IGNORECASE)
_MUTABLE_VERSIONS = {"", "*", "devel", "head", "latest", "main", "master", "trunk"}
_INVENTORY_GROUP_KEYS = {"children", "hosts", "vars"}
_INVENTORY_SCOPE_KEYS = {
    "exclude_filters",
    "filters",
    "include_filters",
    "locations",
    "projects",
    "regions",
    "resource_groups",
    "scopes",
    "services",
    "subscriptions",
    "zones",
}
_INVENTORY_SECRET_FILE_KEYS = {
    "ansible_private_key_file",
    "ansible_ssh_private_key_file",
    "private_key_file",
}
_INVENTORY_IDENTITY_KEYS = {
    "ansible_user",
    "ansible_ssh_user",
    "remote_user",
}
_INVENTORY_PRIVILEGED_USERS = {"administrator", "root"}
_INVENTORY_INTERPRETER = re.compile(
    r"^ansible_(?:.*_)?(?:interpreter|executable)$", re.IGNORECASE
)
_INVENTORY_TEMPLATE = re.compile(r"(?:\{[{%]|\b(?:lookup|query)\s*\()", re.IGNORECASE)
_INVENTORY_FILENAME = re.compile(
    r"(?:^|[._-])(?:inventory|hosts)(?:[._-]|$)|"
    r"[.](?:aws_ec2|azure_rm|gcp_compute|openstack|constructed)[.](?:ya?ml)$",
    re.IGNORECASE,
)


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


class _VaultValue(str):
    """Opaque marker for an encrypted Ansible Vault scalar."""


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
            raise AnsibleProjectInputError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise AnsibleProjectInputError(f"duplicate YAML key: {key}")
        explicit_keys.add(key)
    loader.flatten_mapping(node)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _construct_vault(loader: _UniqueKeyLoader, node: yaml.ScalarNode) -> _VaultValue:
    loader.construct_scalar(node)
    return _VaultValue("<encrypted-vault-value>")


_UniqueKeyLoader.add_constructor("!vault", _construct_vault)


def _enabled(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def _disabled(value: Any) -> bool:
    return value is False or str(value).strip().lower() in {"0", "false", "no", "off"}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _parse_config(source: str) -> dict[str, Any] | None:
    first = next(
        (
            line.strip()
            for line in source.splitlines()
            if line.strip() and not line.lstrip().startswith(("#", ";"))
        ),
        "",
    )
    if not first.startswith("["):
        return None
    declared_sections = {
        match.group("section").strip().lower()
        for match in re.finditer(r"(?m)^\s*\[(?P<section>[^]]+)]\s*(?:[#;].*)?$", source)
    }
    if not (
        declared_sections & _CONFIG_SECTIONS
        or any(section.startswith("galaxy_server.") for section in declared_sections)
    ):
        return None
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str.lower
    try:
        parser.read_string(source)
    except configparser.Error as exc:
        raise AnsibleProjectInputError(str(exc)) from exc
    return {
        section.lower(): {key.lower(): value for key, value in parser.items(section)}
        for section in parser.sections()
    }


def _valid_dependency(item: Any) -> bool:
    if isinstance(item, str):
        return bool(item.strip())
    if not isinstance(item, dict):
        return False
    return bool({"include", "name", "src", "source"} & {str(key).lower() for key in item})


def _parse_requirements(source: str) -> dict[str, list[Any]]:
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except AnsibleProjectInputError:
        raise
    except yaml.YAMLError as exc:
        raise AnsibleProjectInputError(str(exc)) from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1:
        raise AnsibleProjectInputError("requirements input must contain exactly one YAML document")
    document = documents[0]
    if isinstance(document, list):
        if not document or not all(_valid_dependency(item) for item in document):
            raise AnsibleProjectInputError("input is not an Ansible Galaxy requirements list")
        return {"roles": document, "collections": []}
    if not isinstance(document, dict):
        raise AnsibleProjectInputError("requirements input must be a YAML mapping or list")
    unknown = set(document) - {"collections", "roles"}
    if unknown or not ({"collections", "roles"} & set(document)):
        raise AnsibleProjectInputError(
            "requirements mapping must contain only roles and/or collections"
        )
    roles = document.get("roles", [])
    collections = document.get("collections", [])
    if not isinstance(roles, list) or not isinstance(collections, list):
        raise AnsibleProjectInputError("roles and collections must be YAML lists")
    if not all(_valid_dependency(item) for item in [*roles, *collections]):
        raise AnsibleProjectInputError("invalid role or collection requirement entry")
    return {"roles": roles, "collections": collections}


def _inventory_filename(filename: str | None) -> bool:
    if not filename:
        return False
    normalized = PurePosixPath(filename.replace("\\", "/"))
    name = normalized.name
    return bool(
        _INVENTORY_FILENAME.search(name)
        or any(part.lower() in {"inventories", "inventory"} for part in normalized.parts[:-1])
    )


def _parse_inventory_ini(source: str) -> dict[str, Any]:
    groups: dict[str, dict[str, Any]] = {}
    ungrouped: list[dict[str, Any]] = []
    current_group: str | None = None
    current_mode = "hosts"
    saw_inventory = False

    for line_number, original in enumerate(source.splitlines(), start=1):
        line = original.strip()
        if not line or line.startswith(("#", ";")):
            continue
        section = re.fullmatch(r"\[([^]]+)]\s*(?:[#;].*)?", line)
        if section:
            raw_section = section.group(1).strip()
            if not raw_section:
                raise AnsibleProjectInputError(f"empty inventory group on line {line_number}")
            group, separator, modifier = raw_section.rpartition(":")
            if separator and modifier.lower() in {"children", "vars"}:
                current_group = group.strip()
                current_mode = modifier.lower()
            else:
                current_group = raw_section
                current_mode = "hosts"
            if not current_group:
                raise AnsibleProjectInputError(f"empty inventory group on line {line_number}")
            groups.setdefault(current_group, {"children": [], "hosts": [], "vars": {}})
            saw_inventory = True
            continue

        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise AnsibleProjectInputError(
                f"invalid INI inventory quoting on line {line_number}: {exc}"
            ) from exc
        if not tokens:
            continue
        if current_mode == "vars":
            if current_group is None or "=" not in line:
                raise AnsibleProjectInputError(
                    f"inventory group variable must use key=value on line {line_number}"
                )
            key, value = line.split("=", 1)
            key = key.strip()
            if not key:
                raise AnsibleProjectInputError(
                    f"inventory group variable has an empty key on line {line_number}"
                )
            variables = groups[current_group]["vars"]
            if key in variables:
                raise AnsibleProjectInputError(
                    f"duplicate inventory variable {key!r} on line {line_number}"
                )
            variables[key] = value.strip()
            saw_inventory = True
            continue
        if current_mode == "children":
            if current_group is None or len(tokens) != 1:
                raise AnsibleProjectInputError(
                    f"inventory child group must be one name on line {line_number}"
                )
            groups[current_group]["children"].append(tokens[0])
            saw_inventory = True
            continue

        if len(tokens) > 1 and tokens[1] == "=":
            raise AnsibleProjectInputError(
                f"inventory host variables must be attached as key=value on line {line_number}"
            )
        variables: dict[str, str] = {}
        for token in tokens[1:]:
            if "=" not in token:
                raise AnsibleProjectInputError(
                    f"inventory host variable must use key=value on line {line_number}"
                )
            key, value = token.split("=", 1)
            if not key or key in variables:
                raise AnsibleProjectInputError(
                    f"invalid or duplicate inventory host variable on line {line_number}"
                )
            variables[key] = value
        host = {"name": tokens[0], "vars": variables}
        if current_group is None:
            ungrouped.append(host)
        else:
            groups[current_group]["hosts"].append(host)
        saw_inventory = True

    if not saw_inventory:
        raise AnsibleProjectInputError("input is not a recognized INI inventory")
    return {"groups": groups, "ungrouped": ungrouped}


def _validate_inventory_group(
    name: str,
    body: Any,
    *,
    path: str,
    seen: set[int],
) -> None:
    if body is None:
        return
    if not isinstance(body, dict):
        raise AnsibleProjectInputError(f"inventory group {path} must be a YAML mapping")
    object_id = id(body)
    if object_id in seen:
        raise AnsibleProjectInputError(f"inventory group {path} contains a recursive YAML alias")
    seen.add(object_id)
    unknown = set(body) - _INVENTORY_GROUP_KEYS
    if unknown:
        fields = ", ".join(sorted(str(item) for item in unknown))
        raise AnsibleProjectInputError(f"inventory group {path} has unknown field(s): {fields}")
    hosts = body.get("hosts", {})
    if hosts is not None and not isinstance(hosts, dict):
        raise AnsibleProjectInputError(f"inventory hosts in {path} must be a YAML mapping")
    for host, variables in (hosts or {}).items():
        if variables is not None and not isinstance(variables, dict):
            raise AnsibleProjectInputError(
                f"inventory host variables for {host!r} in {path} must be a YAML mapping"
            )
    variables = body.get("vars", {})
    if variables is not None and not isinstance(variables, dict):
        raise AnsibleProjectInputError(f"inventory vars in {path} must be a YAML mapping")
    children = body.get("children", {})
    if children is not None and not isinstance(children, dict):
        raise AnsibleProjectInputError(f"inventory children in {path} must be a YAML mapping")
    for child, child_body in (children or {}).items():
        _validate_inventory_group(
            str(child), child_body, path=f"{path}.children.{child}", seen=seen
        )
    seen.remove(object_id)


def _parse_inventory_yaml(document: Any) -> dict[str, Any] | None:
    if not isinstance(document, dict) or not document or "plugin" in document:
        return None
    if not all(
        body is None
        or (
            isinstance(body, dict)
            and bool(set(body) & _INVENTORY_GROUP_KEYS)
            and not (set(body) - _INVENTORY_GROUP_KEYS)
        )
        for body in document.values()
    ):
        return None
    for group, body in document.items():
        _validate_inventory_group(str(group), body, path=str(group), seen=set())
    return document


def _load_inventory_yaml(source: str) -> Any:
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except AnsibleProjectInputError:
        raise
    except yaml.YAMLError as exc:
        raise AnsibleProjectInputError(str(exc)) from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1:
        raise AnsibleProjectInputError("inventory input must contain exactly one YAML document")
    return documents[0]


def parse_ansible_project(source: str, filename: str | None = None) -> dict[str, Any]:
    """Parse Ansible project configuration, dependencies, or inventory without execution."""
    if not source.strip():
        raise AnsibleProjectInputError("input is empty")
    filename_suffix = (
        PurePosixPath(filename.replace("\\", "/")).suffix.lower() if filename else ""
    )
    if _inventory_filename(filename) and filename_suffix == ".ini":
        inventory = _parse_inventory_ini(source)
        return {"ansible_project": {"artifact_type": "inventory_ini", "document": inventory}}
    config = _parse_config(source)
    if config is not None:
        return {"ansible_project": {"artifact_type": "config", "document": config}}

    try:
        document = _load_inventory_yaml(source)
    except AnsibleProjectInputError:
        if _inventory_filename(filename) or source.lstrip().startswith("["):
            inventory = _parse_inventory_ini(source)
            return {
                "ansible_project": {"artifact_type": "inventory_ini", "document": inventory}
            }
        raise
    if isinstance(document, dict) and isinstance(document.get("plugin"), str):
        if not document["plugin"].strip():
            raise AnsibleProjectInputError("inventory plugin name must not be empty")
        return {
            "ansible_project": {"artifact_type": "inventory_plugin", "document": document}
        }
    inventory_yaml = _parse_inventory_yaml(document)
    if inventory_yaml is not None:
        return {
            "ansible_project": {"artifact_type": "inventory_yaml", "document": inventory_yaml}
        }
    if _inventory_filename(filename) and filename_suffix not in {".json", ".yaml", ".yml"}:
        inventory = _parse_inventory_ini(source)
        return {"ansible_project": {"artifact_type": "inventory_ini", "document": inventory}}
    requirements = _parse_requirements(source)
    return {"ansible_project": {"artifact_type": "requirements", "document": requirements}}


def _config_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    defaults = document.get("defaults", {})
    privilege = document.get("privilege_escalation", {})
    ssh = document.get("ssh_connection", {})
    inventory = document.get("inventory", {})

    if _disabled(defaults.get("host_key_checking")):
        changes.append(
            _change(
                "defaults.host_key_checking",
                "host_key_checking",
                "dangerous",
                "ansible.cfg disables SSH host-key checking, allowing machine-in-the-middle "
                "impersonation of managed hosts.",
            )
        )
    ssh_args = " ".join(
        str(ssh.get(key, ""))
        for key in ("ssh_args", "ssh_common_args", "ssh_extra_args", "scp_extra_args")
    )
    lowered_ssh_args = ssh_args.lower()
    if (
        "stricthostkeychecking=no" in lowered_ssh_args
        or "userknownhostsfile=/dev/null" in lowered_ssh_args
    ):
        changes.append(
            _change(
                "ssh_connection.ssh_args",
                "ssh_host_verification",
                "dangerous",
                "Ansible SSH arguments bypass host-key verification or known-host persistence.",
            )
        )
    if "proxycommand" in lowered_ssh_args:
        changes.append(
            _change(
                "ssh_connection.ssh_args",
                "ssh_proxy_command",
                "dangerous",
                "Ansible executes an SSH ProxyCommand on the controller and reroutes managed-host "
                "traffic through an external command boundary.",
            )
        )

    become = privilege.get("become", defaults.get("become"))
    become_user = str(privilege.get("become_user", defaults.get("become_user", "root")))
    if _enabled(become):
        changes.append(
            _change(
                "privilege_escalation.become",
                "global_privilege_escalation",
                "dangerous",
                f"ansible.cfg enables privilege escalation globally as {become_user!r}.",
            )
        )
    remote_user = str(defaults.get("remote_user", "")).strip().lower()
    if remote_user in {"root", "administrator"}:
        changes.append(
            _change(
                "defaults.remote_user",
                "privileged_remote_user",
                "dangerous",
                f"Ansible connects to managed hosts directly as privileged user {remote_user!r}.",
            )
        )
    if _enabled(defaults.get("allow_world_readable_tmpfiles")):
        changes.append(
            _change(
                "defaults.allow_world_readable_tmpfiles",
                "world_readable_tempfiles",
                "dangerous",
                "Ansible may make controller-transferred module files world-readable on managed "
                "hosts.",
            )
        )
    if _enabled(defaults.get("allow_broken_conditionals")):
        changes.append(
            _change(
                "defaults.allow_broken_conditionals",
                "broken_conditionals",
                "dangerous",
                "Ansible accepts non-boolean broken conditionals, which can execute tasks under "
                "unexpected truthiness rules.",
            )
        )
    if _enabled(defaults.get("display_args_to_stdout")):
        changes.append(
            _change(
                "defaults.display_args_to_stdout",
                "argument_logging",
                "dangerous",
                "Ansible displays task arguments in stdout, which can expose secret-bearing module "
                "inputs in CI logs.",
            )
        )
    if str(defaults.get("log_path", "")).strip():
        changes.append(
            _change(
                "defaults.log_path",
                "controller_logging",
                "review",
                "Ansible writes controller logs to disk; verify permissions, retention, redaction, "
                "and collection scope.",
            )
        )

    secret_files = [
        f"{section}.{key}"
        for section, values in document.items()
        for key, value in values.items()
        if key in {"become_password_file", "private_key_file", "vault_password_file"}
        and str(value).strip()
    ]
    if secret_files:
        changes.append(
            _change(
                secret_files[0],
                "secret_file",
                "review",
                f"ansible.cfg references {len(secret_files)} password/private-key file(s); verify "
                "filesystem permissions and keep content outside source control.",
            )
        )

    plugin_paths = [
        f"{section}.{key}"
        for section, values in document.items()
        for key, value in values.items()
        if key in _PLUGIN_PATH_OPTIONS and str(value).strip()
    ]
    if plugin_paths:
        changes.append(
            _change(
                plugin_paths[0],
                "controller_plugin_path",
                "dangerous",
                f"ansible.cfg adds {len(plugin_paths)} controller plugin/module path(s); Python "
                "from those locations can execute during inventory, templating, connection, or "
                "task processing.",
            )
        )
    content_paths = [
        f"defaults.{key}"
        for key in ("collections_path", "collections_paths", "roles_path")
        if str(defaults.get(key, "")).strip()
    ]
    if content_paths:
        changes.append(
            _change(
                content_paths[0],
                "content_path",
                "review",
                "ansible.cfg changes role/collection discovery paths; review executable content "
                "provenance and write permissions.",
            )
        )
    callbacks = [
        f"defaults.{key}"
        for key in ("callbacks_enabled", "callback_plugins", "stdout_callback")
        if str(defaults.get(key, "")).strip()
    ]
    if callbacks:
        changes.append(
            _change(
                callbacks[0],
                "callback_execution",
                "dangerous",
                "Ansible enables callback code that receives task results and may export "
                "inventory, arguments, facts, or secrets.",
            )
        )
    enable_plugins = str(inventory.get("enable_plugins", ""))
    enabled_inventory = {item.strip() for item in enable_plugins.split(",") if item.strip()}
    if enabled_inventory & {"auto", "script"}:
        changes.append(
            _change(
                "inventory.enable_plugins",
                "inventory_plugin_execution",
                "dangerous",
                "Ansible enables auto/script inventory loading, which can execute accessible "
                "inventory plugin or script code on the controller.",
            )
        )
    if str(defaults.get("inventory", "")).strip():
        changes.append(
            _change(
                "defaults.inventory",
                "inventory_source",
                "review",
                "ansible.cfg selects external inventory sources; verify plugin type, credentials, "
                "host scope, and generated variables.",
            )
        )

    galaxy_sections = {
        section: values
        for section, values in document.items()
        if section == "galaxy" or section.startswith("galaxy_server.")
    }
    insecure_servers: list[str] = []
    disabled_verification: list[str] = []
    inline_secrets: list[str] = []
    for section, values in galaxy_sections.items():
        for key, value in values.items():
            text = str(value).strip()
            if key in {"server", "url"} and text.lower().startswith("http://"):
                insecure_servers.append(f"{section}.{key}")
            if key in {"ignore_certs", "validate_certs"} and (
                _enabled(value) if key == "ignore_certs" else _disabled(value)
            ):
                disabled_verification.append(f"{section}.{key}")
            if _SECRET_OPTIONS.search(key) and text and not text.startswith("${"):
                inline_secrets.append(f"{section}.{key}")
    if insecure_servers:
        changes.append(
            _change(
                insecure_servers[0],
                "plaintext_galaxy_server",
                "dangerous",
                "Ansible Galaxy/Automation Hub content is downloaded over plaintext HTTP.",
            )
        )
    if disabled_verification:
        changes.append(
            _change(
                disabled_verification[0],
                "galaxy_tls_verification",
                "dangerous",
                "ansible.cfg disables certificate verification for a Galaxy/Automation Hub server.",
            )
        )
    if inline_secrets:
        changes.append(
            _change(
                inline_secrets[0],
                "inline_galaxy_credential",
                "dangerous",
                "ansible.cfg contains a literal Galaxy/Automation Hub credential.",
            )
        )
    if galaxy_sections:
        changes.append(
            _change(
                "galaxy",
                "galaxy_configuration",
                "review",
                "ansible.cfg changes Galaxy/Automation Hub sources; verify server trust, token "
                "scope, signatures, and content approval policy.",
            )
        )
    return changes


def _dependency_fields(item: Any) -> dict[str, Any]:
    if isinstance(item, str):
        return {"name": item}
    return {str(key).lower(): value for key, value in item.items()}


def _embedded_url_credential(value: str) -> bool:
    candidate = value.removeprefix("git+")
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    return bool(parsed.username or parsed.password)


def _dependency_change(kind: str, item: Any, index: int) -> dict[str, str]:
    fields = _dependency_fields(item)
    if "include" in fields:
        return _change(
            f"{kind}.{index}.include",
            "requirements_include",
            "review",
            f"Ansible requirements include {fields['include']!r}; the referenced dependency file "
            "is not expanded.",
        )
    name = str(fields.get("name") or fields.get("src") or "<unnamed>")
    source = str(fields.get("src") or fields.get("source") or name).strip()
    version = str(fields.get("version", "")).strip()
    risk = "review"
    reasons = [
        f"Ansible installs {kind[:-1]} dependency {name!r}; downloaded content can execute on "
        "the controller or managed hosts."
    ]
    mutable = (
        version.lower() in _MUTABLE_VERSIONS
        or any(operator in version for operator in (">", "<", "!", ","))
        or (version and not (_EXACT_VERSION.fullmatch(version) or _COMMIT.fullmatch(version)))
    )
    if mutable:
        risk = "dangerous"
        reasons.append("The dependency version is mutable, ranged, implicit, or not immutable.")
    if source.lower().startswith(("http://", "git://")):
        risk = "dangerous"
        reasons.append("The dependency uses an unauthenticated plaintext transport.")
    if _embedded_url_credential(source):
        risk = "dangerous"
        reasons.append("The source URL embeds credentials that can leak through logs or metadata.")
    if source.startswith(("file://", "git+file://", "./", "../", "/")):
        reasons.append("The dependency resolves local filesystem content outside this artifact.")
    if fields.get("signatures"):
        reasons.append("Supplemental collection signatures are declared for upstream verification.")
    return _change(
        f"{kind}.{index}.{name}",
        f"{kind[:-1]}_dependency",
        risk,
        " ".join(reasons),
    )


def _requirements_changes(document: dict[str, list[Any]]) -> list[dict[str, str]]:
    changes = [
        _change(
            "requirements.effective_content",
            "requirements_boundary",
            "review",
            "Ansible Galaxy requirements install executable roles, modules, plugins, and "
            "playbooks; transitive dependencies, server policy, signatures, and installed content "
            "are outside this file.",
        )
    ]
    for kind in ("roles", "collections"):
        for index, item in enumerate(document.get(kind, []), start=1):
            changes.append(_dependency_change(kind, item, index))
    return changes


def _walk_key_values(
    value: Any,
    *,
    seen: set[int] | None = None,
) -> list[tuple[str, Any]]:
    if seen is None:
        seen = set()
    if not isinstance(value, (dict, list)):
        return []
    object_id = id(value)
    if object_id in seen:
        return []
    seen.add(object_id)
    found: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            found.append((str(key).lower(), item))
            found.extend(_walk_key_values(item, seen=seen))
    else:
        for item in value:
            found.extend(_walk_key_values(item, seen=seen))
    seen.remove(object_id)
    return found


def _external_or_encrypted_value(value: Any) -> bool:
    if isinstance(value, _VaultValue):
        return True
    if not isinstance(value, str):
        return False
    text = value.strip()
    return bool(
        text.startswith("$ANSIBLE_VAULT;")
        or re.fullmatch(r"\$\{[^}]+}", text)
        or re.fullmatch(r"\{\{.*}}", text, re.DOTALL)
        or text.startswith("ENC[")
    )


def _literal_secret(key: str, value: Any) -> bool:
    if key in _INVENTORY_SECRET_FILE_KEYS or not _SECRET_OPTIONS.search(key):
        return False
    if isinstance(value, (dict, list, _VaultValue)) or value in (None, "", False):
        return False
    return not _external_or_encrypted_value(value)


def _scalar_text(value: Any) -> str:
    if isinstance(value, (str, int, float, bool)) and not isinstance(value, _VaultValue):
        return str(value)
    return ""


def _inventory_static_context(
    document: dict[str, Any], artifact_type: str
) -> tuple[int, int, list[dict[str, Any]], bool]:
    host_names: set[str] = set()
    variable_sets: list[dict[str, Any]] = []
    group_count = 0
    all_group_order_issue = False

    if artifact_type == "inventory_ini":
        groups = document.get("groups", {})
        group_count = len(groups)
        for group in groups.values():
            variables = group.get("vars", {})
            if variables:
                variable_sets.append(variables)
            for host in group.get("hosts", []):
                host_names.add(str(host.get("name", "")))
                if host.get("vars"):
                    variable_sets.append(host["vars"])
        for host in document.get("ungrouped", []):
            host_names.add(str(host.get("name", "")))
            if host.get("vars"):
                variable_sets.append(host["vars"])
        return len(host_names - {""}), group_count, variable_sets, False

    seen: set[int] = set()

    def visit_group(body: Any) -> None:
        nonlocal group_count
        if not isinstance(body, dict) or id(body) in seen:
            return
        seen.add(id(body))
        group_count += 1
        variables = body.get("vars")
        if isinstance(variables, dict) and variables:
            variable_sets.append(variables)
        hosts = body.get("hosts")
        if isinstance(hosts, dict):
            for host_name, host_variables in hosts.items():
                host_names.add(str(host_name))
                if isinstance(host_variables, dict) and host_variables:
                    variable_sets.append(host_variables)
        children = body.get("children")
        if isinstance(children, dict):
            for child in children.values():
                visit_group(child)
        seen.remove(id(body))

    for body in document.values():
        visit_group(body)
    if "all" in document and next(iter(document)) != "all":
        all_body = document.get("all")
        all_group_order_issue = isinstance(all_body, dict) and bool(all_body.get("vars"))
    return len(host_names), group_count, variable_sets, all_group_order_issue


def _inventory_variable_findings(variable_sets: list[dict[str, Any]]) -> dict[str, bool]:
    findings = {
        "become": False,
        "external_secret": False,
        "host_key_bypass": False,
        "identity": False,
        "interpreter": False,
        "literal_private_key": False,
        "literal_secret": False,
        "local_connection": False,
        "private_key_file": False,
        "privileged_identity": False,
        "proxy_command": False,
        "template": False,
    }
    for variables in variable_sets:
        for key, value in _walk_key_values(variables):
            text = _scalar_text(value).strip()
            lowered = text.lower()
            if _literal_secret(key, value):
                findings["literal_secret"] = True
            if _SECRET_OPTIONS.search(key) and _external_or_encrypted_value(value):
                findings["external_secret"] = True
            if "-----begin " in lowered and " private key-----" in lowered:
                findings["literal_private_key"] = True
            if key in _INVENTORY_SECRET_FILE_KEYS and text:
                findings["private_key_file"] = True
            if key in _INVENTORY_IDENTITY_KEYS and text:
                findings["identity"] = True
                if lowered in _INVENTORY_PRIVILEGED_USERS:
                    findings["privileged_identity"] = True
            if key in {"ansible_become", "become"} and _enabled(value):
                findings["become"] = True
            if key == "ansible_become_user" and lowered in _INVENTORY_PRIVILEGED_USERS:
                findings["become"] = True
            if key == "ansible_connection" and lowered == "local":
                findings["local_connection"] = True
            if _INVENTORY_INTERPRETER.match(key) and text:
                findings["interpreter"] = True
            if key in {
                "ansible_ssh_args",
                "ansible_ssh_common_args",
                "ansible_ssh_extra_args",
            }:
                compact = re.sub(r"\s+", "", lowered)
                if (
                    "stricthostkeychecking=no" in compact
                    or "userknownhostsfile=/dev/null" in compact
                ):
                    findings["host_key_bypass"] = True
                if "proxycommand" in lowered:
                    findings["proxy_command"] = True
            if text and _INVENTORY_TEMPLATE.search(text):
                findings["template"] = True
    return findings


def _static_inventory_changes(
    document: dict[str, Any], artifact_type: str
) -> list[dict[str, str]]:
    host_count, group_count, variable_sets, order_issue = _inventory_static_context(
        document, artifact_type
    )
    findings = _inventory_variable_findings(variable_sets)
    changes = [
        _change(
            "inventory.scope",
            "inventory_scope",
            "review",
            f"Ansible inventory defines {host_count} unique managed host(s) across "
            f"{group_count} group(s). Review target ownership, environment separation, group "
            "inheritance, aliases, ports, and the play patterns that consume this scope.",
        )
    ]
    if order_issue:
        changes.append(
            _change(
                "inventory.all.order",
                "inventory_group_order",
                "review",
                "YAML inventory defines variables for the all group without placing all first; "
                "review whether the inventory plugin applies those variables as intended.",
            )
        )
    if findings["literal_secret"] or findings["literal_private_key"]:
        changes.append(
            _change(
                "inventory.variables.credentials",
                "inventory_literal_credential",
                "dangerous",
                "Ansible inventory contains a literal connection, privilege-escalation, cloud, "
                "or private-key credential. Move it to Vault or an external secret source and "
                "rotate any exposed credential.",
            )
        )
    if findings["external_secret"]:
        changes.append(
            _change(
                "inventory.variables.secret_references",
                "inventory_secret_boundary",
                "review",
                "Ansible inventory references encrypted or externally resolved secret material; "
                "verify Vault identity, secret-source authorization, rotation, and log redaction.",
            )
        )
    if findings["privileged_identity"] or findings["become"]:
        changes.append(
            _change(
                "inventory.variables.privilege",
                "inventory_privileged_identity",
                "dangerous",
                "Ansible inventory selects a root/Administrator connection identity or enables "
                "privilege escalation. Review least privilege, sudo policy, credential scope, "
                "and the full host-group inheritance path.",
            )
        )
    elif findings["identity"]:
        changes.append(
            _change(
                "inventory.variables.identity",
                "inventory_connection_identity",
                "review",
                "Ansible inventory selects connection identities. Review account ownership, "
                "authentication method, privilege, reuse, and group-variable inheritance.",
            )
        )
    if findings["host_key_bypass"]:
        changes.append(
            _change(
                "inventory.variables.ssh_verification",
                "inventory_ssh_host_verification",
                "dangerous",
                "Ansible inventory SSH arguments disable host-key verification or known-host "
                "persistence, allowing managed-host impersonation.",
            )
        )
    if findings["proxy_command"]:
        changes.append(
            _change(
                "inventory.variables.ssh_proxy",
                "inventory_ssh_proxy_command",
                "dangerous",
                "Ansible inventory configures an SSH ProxyCommand that executes on the controller "
                "and reroutes managed-host traffic through an external command boundary.",
            )
        )
    if findings["local_connection"]:
        changes.append(
            _change(
                "inventory.variables.local_connection",
                "inventory_local_execution",
                "dangerous",
                "Ansible inventory selects the local connection plugin, so matching playbook "
                "tasks execute on the controller instead of a remote managed host.",
            )
        )
    if findings["interpreter"]:
        changes.append(
            _change(
                "inventory.variables.interpreter",
                "inventory_interpreter_override",
                "dangerous",
                "Ansible inventory overrides a language interpreter or shell executable used to "
                "run modules. Verify binary provenance, path ownership, and host scope.",
            )
        )
    if findings["private_key_file"]:
        changes.append(
            _change(
                "inventory.variables.private_key_file",
                "inventory_private_key_file",
                "review",
                "Ansible inventory selects a private-key file outside this artifact. Verify file "
                "permissions, secret storage, identity scope, rotation, and CI availability.",
            )
        )
    if findings["template"]:
        changes.append(
            _change(
                "inventory.variables.templates",
                "inventory_variable_evaluation",
                "dangerous",
                "Ansible inventory variables contain Jinja lookup/query expressions that can "
                "read controller data or invoke plugins when consumed. Review every expression "
                "and plugin trust boundary.",
            )
        )
    return changes


def _plugin_inventory_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    pairs = _walk_key_values(document)
    changes = [
        _change(
            "inventory.plugin",
            "inventory_plugin_execution",
            "dangerous",
            "Ansible loads an inventory plugin on the controller and lets it query an external "
            "source to construct managed hosts and variables. Verify the collection and plugin "
            "version, controller dependencies, source authorization, and returned host scope.",
        )
    ]
    scope_values = [value for key, value in pairs if key in _INVENTORY_SCOPE_KEYS]
    if not scope_values or not any(value not in (None, "", [], {}) for value in scope_values):
        changes.append(
            _change(
                "inventory.plugin.scope",
                "inventory_plugin_broad_scope",
                "dangerous",
                "Dynamic inventory has no statically visible region, project, subscription, "
                "resource-group, service, or filter scope. It may discover every host accessible "
                "to the controller identity.",
            )
        )
    if any(_literal_secret(key, value) for key, value in pairs):
        changes.append(
            _change(
                "inventory.plugin.credentials",
                "inventory_plugin_literal_credential",
                "dangerous",
                "Dynamic inventory configuration contains a literal cloud/API credential. Use "
                "an external identity or secret source and rotate any exposed credential.",
            )
        )
    if any(
        _SECRET_OPTIONS.search(key) and _external_or_encrypted_value(value)
        for key, value in pairs
    ):
        changes.append(
            _change(
                "inventory.plugin.secret_references",
                "inventory_plugin_secret_boundary",
                "review",
                "Dynamic inventory resolves encrypted or external credential material; verify "
                "controller identity, secret-source authorization, rotation, and log redaction.",
            )
        )
    endpoint_values = [
        _scalar_text(value).strip().lower()
        for key, value in pairs
        if key in {"api_endpoint", "endpoint", "endpoint_url", "server", "url"}
    ]
    if any(value.startswith("http://") for value in endpoint_values):
        changes.append(
            _change(
                "inventory.plugin.endpoint",
                "inventory_plugin_plaintext_endpoint",
                "dangerous",
                "Dynamic inventory contacts a plaintext HTTP endpoint, exposing credentials, "
                "inventory data, or host-selection responses to interception.",
            )
        )
    if any(
        key in {"validate_certs", "verify_ssl", "verify_tls"} and _disabled(value)
        for key, value in pairs
    ):
        changes.append(
            _change(
                "inventory.plugin.tls",
                "inventory_plugin_tls_verification",
                "dangerous",
                "Dynamic inventory disables certificate verification for its external API.",
            )
        )
    if any(key in {"strict_permissions"} and _disabled(value) for key, value in pairs):
        changes.append(
            _change(
                "inventory.plugin.failure_policy",
                "inventory_plugin_fail_open",
                "dangerous",
                "Dynamic inventory ignores authorization failures and can return a partial or "
                "unexpected host set instead of failing closed.",
            )
        )
    constructed = any(key in {"compose", "groups", "hostnames", "keyed_groups"} for key, _ in pairs)
    templated = any(
        _INVENTORY_TEMPLATE.search(_scalar_text(value))
        for _key, value in pairs
        if _scalar_text(value)
    )
    if constructed or templated:
        changes.append(
            _change(
                "inventory.plugin.construction",
                "inventory_plugin_construction",
                "dangerous" if templated else "review",
                "Dynamic inventory constructs hostnames, groups, or variables from external "
                "facts and expressions. Review expression/plugin capabilities, collisions, "
                "sanitization, sensitive returned fields, and resulting play targets.",
            )
        )
    if any(key == "use_extra_vars" and _enabled(value) for key, value in pairs):
        changes.append(
            _change(
                "inventory.plugin.extra_vars",
                "inventory_plugin_extra_vars",
                "dangerous",
                "Dynamic inventory imports command-line extra vars into inventory construction, "
                "allowing invocation-time data to alter discovered hosts, groups, or variables.",
            )
        )
    if any(key == "cache" and _enabled(value) for key, value in pairs):
        changes.append(
            _change(
                "inventory.plugin.cache",
                "inventory_plugin_cache",
                "review",
                "Dynamic inventory caching can persist host metadata and serve stale target "
                "membership. Review cache backend access, encryption, TTL, invalidation, and CI "
                "isolation.",
            )
        )
    if any(
        key in {"assume_role_arn", "iam_role_arn", "profile", "service_account_file"}
        and value not in (None, "")
        for key, value in pairs
    ):
        changes.append(
            _change(
                "inventory.plugin.identity",
                "inventory_plugin_identity",
                "review",
                "Dynamic inventory selects a cloud profile, role, or service account. Review "
                "least privilege, cross-account trust, credential source, and discoverable scope.",
            )
        )
    return changes


class AnsibleProjectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "ansible-project"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("ansible_project")
        return (
            isinstance(config, dict)
            and config.get("artifact_type")
            in {
                "config",
                "inventory_ini",
                "inventory_plugin",
                "inventory_yaml",
                "requirements",
            }
            and isinstance(config.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        config = input_data["ansible_project"]
        document = config["document"]
        artifact_type = config["artifact_type"]
        if artifact_type == "config":
            changes = _config_changes(document)
        elif artifact_type == "requirements":
            changes = _requirements_changes(document)
        elif artifact_type == "inventory_plugin":
            changes = _plugin_inventory_changes(document)
        else:
            changes = _static_inventory_changes(document, artifact_type)
        boundary = (
            "Effective Ansible inventory also depends on all combined inventory sources, "
            "group_vars/host_vars, variable precedence, Vault/secret resolution, installed "
            "inventory plugins, command-line limits, and the play patterns that consume it."
            if artifact_type.startswith("inventory_")
            else "Effective Ansible behavior also depends on environment variables, command-line "
            "options, inventory, variables, vault/secret files, installed collections, roles, "
            "and controller plugin code."
        )
        changes.append(
            _change(
                "ansible.effective_project",
                "project_boundary",
                "review",
                boundary,
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"ansible_project_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_ansible_project(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = AnsibleProjectAdapter().analyze(data, tool_name="Ansible project")
    summary = PlanSummary(
        path=Path("ansible-project://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Ansible project")
    gate["adapter"] = "ansible-project"
    gate["artifact_type"] = data["ansible_project"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
