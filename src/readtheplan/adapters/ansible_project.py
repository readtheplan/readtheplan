from __future__ import annotations

import configparser
import re
from pathlib import Path
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
    r"(?:password|passwd|token|secret|private.?key|client.?secret|api.?key)",
    re.IGNORECASE,
)
_EXACT_VERSION = re.compile(r"(?:==)?(?:v)?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?$")
_COMMIT = re.compile(r"[0-9a-f]{40,64}$", re.IGNORECASE)
_MUTABLE_VERSIONS = {"", "*", "devel", "head", "latest", "main", "master", "trunk"}


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
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str.lower
    try:
        parser.read_string(source)
    except configparser.Error as exc:
        raise AnsibleProjectInputError(str(exc)) from exc
    sections = {section.lower() for section in parser.sections()}
    if not (
        sections & _CONFIG_SECTIONS
        or any(section.startswith("galaxy_server.") for section in sections)
    ):
        raise AnsibleProjectInputError("input does not contain recognized ansible.cfg sections")
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


def parse_ansible_project(source: str) -> dict[str, Any]:
    """Parse ansible.cfg or Galaxy requirements.yml without loading project code."""
    if not source.strip():
        raise AnsibleProjectInputError("input is empty")
    config = _parse_config(source)
    if config is not None:
        return {"ansible_project": {"artifact_type": "config", "document": config}}
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


class AnsibleProjectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "ansible-project"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("ansible_project")
        return (
            isinstance(config, dict)
            and config.get("artifact_type") in {"config", "requirements"}
            and isinstance(config.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        config = input_data["ansible_project"]
        document = config["document"]
        changes = (
            _config_changes(document)
            if config["artifact_type"] == "config"
            else _requirements_changes(document)
        )
        changes.append(
            _change(
                "ansible.effective_project",
                "project_boundary",
                "review",
                "Effective Ansible behavior also depends on environment variables, command-line "
                "options, inventory, variables, vault/secret files, installed collections, roles, "
                "and controller plugin code.",
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
