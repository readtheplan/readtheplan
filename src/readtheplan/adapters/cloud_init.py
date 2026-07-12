from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class CloudInitInputError(ValueError):
    """Raised when input is not recognizable cloud-init user-data."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise CloudInitInputError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)

_COMMAND_KEYS = {"bootcmd", "runcmd"}
_STORAGE_KEYS = {"disk_setup", "fs_setup", "growpart", "resize_rootfs"}
_PACKAGE_KEYS = {
    "apt",
    "apt_pipelining",
    "package_reboot_if_required",
    "package_update",
    "package_upgrade",
    "packages",
    "snap",
    "yum_repos",
}
_CONFIG_MANAGERS = {"ansible", "chef", "puppet", "salt_minion"}
_KNOWN_KEYS = (
    _COMMAND_KEYS
    | _STORAGE_KEYS
    | _PACKAGE_KEYS
    | _CONFIG_MANAGERS
    | {
        "chpasswd",
        "disable_root",
        "final_message",
        "groups",
        "hostname",
        "locale",
        "manage_etc_hosts",
        "mounts",
        "phone_home",
        "power_state",
        "reporting",
        "ssh_authorized_keys",
        "ssh_deletekeys",
        "ssh_genkeytypes",
        "ssh_keys",
        "ssh_pwauth",
        "swap",
        "timezone",
        "users",
        "write_files",
    }
)
_SENSITIVE_PATHS = (
    "/etc/shadow",
    "/etc/ssh/",
    "/etc/sudoers",
    "/etc/systemd/",
    "/root/.ssh/",
)
_SECRET_TOKENS = ("password", "passwd", "private_key", "secret", "token")


def _change(kind: str, name: str, value: Any, address: str) -> dict[str, Any]:
    return {"Kind": kind, "Name": name, "Value": value, "Address": address}


def _parse_cloud_config(source: str) -> dict[str, Any]:
    try:
        document = yaml.load(source, Loader=_UniqueKeyLoader)
    except CloudInitInputError:
        raise
    except yaml.YAMLError as exc:
        raise CloudInitInputError(f"invalid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise CloudInitInputError("cloud-config input must be a YAML object")

    changes: list[dict[str, Any]] = []
    for key, value in document.items():
        name = str(key)
        if name == "write_files" and isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    path = str(item.get("path") or f"file-{index}")
                    changes.append(_change("write_file", path, item, f"write_files[{index}]"))
            continue
        if name == "users" and isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, str):
                    username = item
                elif isinstance(item, dict):
                    username = item.get("name", f"user-{index}")
                else:
                    username = f"user-{index}"
                changes.append(_change("user", str(username), item, f"users[{index}]"))
            continue
        if name in _COMMAND_KEYS and isinstance(value, list):
            for index, command in enumerate(value):
                changes.append(_change(name, str(index), command, f"{name}[{index}]"))
            continue
        if name in _KNOWN_KEYS:
            changes.append(_change(name, name, value, name))
        else:
            changes.append(_change("unknown_module", name, value, name))

    changes.append(
        _change(
            "merge_boundary",
            "combined cloud configuration",
            None,
            "cloud_init.merge_boundary",
        )
    )
    if "{{" in source or "{%" in source or source.startswith("## template: jinja"):
        changes.append(_change("jinja", "instance-data template", None, "cloud_init.jinja"))
    return {"cloud_init": {"format": "cloud-config", "changes": changes}}


def parse_cloud_init(source: str) -> dict[str, Any]:
    """Parse common cloud-init user-data without executing any guest code."""
    if not source.strip():
        raise CloudInitInputError("input is empty")
    first_nonempty = next(line.strip() for line in source.splitlines() if line.strip())
    if first_nonempty == "## template: jinja":
        headers = [line.strip() for line in source.splitlines() if line.strip()]
        if len(headers) > 1 and headers[1] == "#cloud-config":
            return _parse_cloud_config(source)
    if first_nonempty == "#cloud-config":
        return _parse_cloud_config(source)
    if first_nonempty.startswith("#!"):
        return {
            "cloud_init": {
                "format": "script",
                "changes": [_change("script", first_nonempty, source, "cloud_init.script")],
            }
        }
    if first_nonempty == "#cloud-boothook":
        return {
            "cloud_init": {
                "format": "boothook",
                "changes": [
                    _change("boothook", "early boot script", source, "cloud_init.boothook")
                ],
            }
        }
    if first_nonempty == "#include":
        urls = [
            line.strip()
            for line in source.splitlines()[1:]
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if not urls:
            raise CloudInitInputError("include user-data contains no URLs")
        return {
            "cloud_init": {
                "format": "include",
                "changes": [
                    _change("include", url, None, f"cloud_init.include[{index}]")
                    for index, url in enumerate(urls)
                ],
            }
        }
    if first_nonempty.startswith("Content-Type: multipart/"):
        return {
            "cloud_init": {
                "format": "mime",
                "changes": [
                    _change("multipart", "MIME user-data", None, "cloud_init.multipart")
                ],
            }
        }
    if first_nonempty == "#cloud-config-archive":
        return {
            "cloud_init": {
                "format": "archive",
                "changes": [
                    _change(
                        "archive",
                        "cloud-config archive",
                        None,
                        "cloud_init.archive",
                    )
                ],
            }
        }
    if first_nonempty == "#part-handler":
        return {
            "cloud_init": {
                "format": "part-handler",
                "changes": [
                    _change(
                        "part_handler",
                        "Python part handler",
                        source,
                        "cloud_init.part_handler",
                    )
                ],
            }
        }
    raise CloudInitInputError("unsupported or missing cloud-init user-data header")


def _contains_secret(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            any(token in str(key).lower() for token in _SECRET_TOKENS)
            or _contains_secret(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    if isinstance(value, str):
        text = value.lower()
        return any(
            marker in text
            for marker in ("password:", "passwd:", "private_key:", "secret:", "token:")
        )
    return False


class CloudInitAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "cloud-init"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        document = input_data.get("cloud_init")
        return isinstance(document, dict) and isinstance(document.get("changes"), list)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        return list(input_data["cloud_init"]["changes"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        kind = str(raw.get("Kind") or "unknown")
        name = str(raw.get("Name") or "unknown")
        value = raw.get("Value")
        risk = "review"
        explanation = f"cloud-init module '{kind}' changes first-boot system state."

        if kind in {"script", "boothook", "bootcmd", "runcmd"}:
            risk = "dangerous"
            explanation = f"cloud-init {kind} executes arbitrary guest commands."
        elif kind == "include":
            risk = "dangerous"
            explanation = "cloud-init downloads and processes external user-data at boot."
        elif kind in {"multipart", "archive"}:
            risk = "dangerous"
            explanation = (
                "Container user-data can contain scripts, boothooks, handlers, and "
                "cloud-config parts; inspect each decoded part before launch."
            )
        elif kind == "part_handler":
            risk = "dangerous"
            explanation = "cloud-init part handlers execute custom Python code during boot."
        elif kind in _CONFIG_MANAGERS:
            risk = "dangerous"
            explanation = f"cloud-init delegates guest configuration to {kind}."
        elif kind in _STORAGE_KEYS or kind == "power_state":
            risk = "dangerous"
            explanation = f"cloud-init '{kind}' can alter storage layout or instance availability."
        elif kind in {"ssh_authorized_keys", "ssh_keys"}:
            risk = "dangerous"
            explanation = "cloud-init installs SSH trust or host key material."
        elif kind == "ssh_pwauth" and bool(value):
            risk = "dangerous"
            explanation = "cloud-init enables SSH password authentication."
        elif kind == "disable_root" and value is False:
            risk = "dangerous"
            explanation = "cloud-init enables direct root login behavior."
        elif kind in {"chpasswd", "user"}:
            text = str(value).lower()
            elevated = "nopasswd" in text or "lock_passwd': false" in text
            risk = "dangerous" if elevated or _contains_secret(value) else "review"
            explanation = (
                "cloud-init creates or modifies a local user, credentials, SSH "
                "trust, or sudo access."
            )
        elif kind == "write_file":
            item = value if isinstance(value, dict) else {}
            permissions = str(item.get("permissions") or "")
            sensitive = any(name.startswith(path) for path in _SENSITIVE_PATHS)
            world_writable = permissions.endswith(("2", "3", "6", "7"))
            risky_file = sensitive or world_writable or _contains_secret(item)
            risk = "dangerous" if risky_file else "review"
            explanation = (
                f"cloud-init writes guest file '{name}'; verify path, owner, "
                "permissions, and content sensitivity."
            )
        elif kind in _PACKAGE_KEYS:
            explanation = f"cloud-init '{kind}' changes package sources or installed software."
        elif kind in {"phone_home", "reporting"}:
            explanation = f"cloud-init '{kind}' can transmit boot or provisioning data externally."
        elif kind == "final_message":
            risk = "safe"
            explanation = "cloud-init final_message only formats a completion message."
        elif kind == "jinja":
            explanation = (
                "cloud-init renders instance-data into user-data; review the resolved "
                "configuration."
            )
        elif kind == "merge_boundary":
            explanation = (
                "cloud-init combines user-data with vendor, image, datasource, and "
                "system configuration; review the resolved merged config."
            )
        elif kind == "unknown_module":
            explanation = (
                f"Unknown cloud-init key '{name}' may be version-specific or ignored; "
                "validate with cloud-init schema."
            )

        if _contains_secret(value) and risk != "dangerous":
            risk = "dangerous"
            explanation += " Credential-like fields are embedded in user-data."

        return ResourceChange(
            address=str(raw.get("Address") or name),
            resource_type=f"cloud_init_{kind}",
            actions=("execute",),
            risk=risk,
            explanation=explanation,
        )


def analyze_cloud_init(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = CloudInitAdapter().analyze(data, tool_name="cloud-init")
    summary = PlanSummary(
        path=Path("cloud-init://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="cloud-init")
    gate["adapter"] = "cloud-init"
    gate["total_changes"] = len(changes)
    return gate
