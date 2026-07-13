from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import hcl2
from hcl2.utils import SerializationOptions


class NomadJobInputError(ValueError):
    """Raised when input is not a recognizable Nomad HCL/JSON jobspec."""


_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)", re.I
)
_TEMPLATE_REMOTE = re.compile(
    r"\b(?:secret|key|keyOrDefault|ls|tree|service|services|nomadService|nomadServices|"
    r"nomadVar|nomadVarExists)\s+",
    re.I,
)
_TEMPLATE_EXEC = re.compile(r"\b(?:plugin|executeTemplate|writeToFile)\s+", re.I)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NomadJobInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strip_internal(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_internal(child) for key, child in value.items() if key != "__is_block__"
        }
    if isinstance(value, list):
        return [_strip_internal(child) for child in value]
    return value


def parse_nomad_job(source: str) -> dict[str, Any]:
    """Parse Nomad HCL or JSON job source without evaluating or canonicalizing it."""
    if not source.strip():
        raise NomadJobInputError("input is empty")
    try:
        document: Any = json.loads(source, object_pairs_hook=_unique_object)
    except NomadJobInputError:
        raise
    except json.JSONDecodeError:
        try:
            document = hcl2.loads(
                source,
                serialization_options=SerializationOptions(
                    explicit_blocks=False,
                    strip_string_quotes=True,
                ),
            )
        except Exception as exc:
            raise NomadJobInputError(f"invalid Nomad HCL/JSON jobspec: {exc}") from exc
    document = _strip_internal(document)
    if not isinstance(document, dict):
        raise NomadJobInputError("Nomad jobspec must be an HCL or JSON object")
    if "Job" in document and isinstance(document["Job"], dict):
        jobs = [
            (
                str(document["Job"].get("Name") or document["Job"].get("ID") or "job"),
                document["Job"],
            )
        ]
        representation = "json"
    elif "job" in document:
        jobs = _labeled_blocks(document, "job")
        representation = "hcl"
    elif any(key in document for key in ("TaskGroups", "Datacenters", "Type")):
        jobs = [(str(document.get("Name") or document.get("ID") or "job"), document)]
        representation = "json"
    else:
        raise NomadJobInputError("input is not recognized as a Nomad jobspec")
    if len(jobs) != 1:
        raise NomadJobInputError("Nomad jobspec must contain exactly one job")
    name, job = jobs[0]
    if not isinstance(job, dict):
        raise NomadJobInputError("Nomad job block must be an object")
    return {
        "nomad_job": {
            "representation": representation,
            "name": name,
            "document": job,
        }
    }


def _labeled_blocks(document: dict[str, Any], name: str) -> list[tuple[str, dict[str, Any]]]:
    raw = document.get(name, [])
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise NomadJobInputError(f"Nomad {name} must contain blocks")
    result: list[tuple[str, dict[str, Any]]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise NomadJobInputError(f"Nomad {name} block must be an object")
        if len(item) == 1 and isinstance(next(iter(item.values())), dict):
            label, block = next(iter(item.items()))
            result.append((str(label), block))
        else:
            label = str(item.get("Name") or item.get("name") or index)
            result.append((label, item))
    return result


def _blocks(document: dict[str, Any], *names: str) -> list[tuple[str, dict[str, Any]]]:
    for name in names:
        if name in document:
            return _labeled_blocks(document, name)
    return []


def _value(document: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in document:
            return document[name]
    return default


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _digest_pinned(image: str) -> bool:
    return bool(re.search(r"@sha256:[0-9a-f]{64}$", image, re.I))


def _absolute_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    return PurePosixPath(normalized).is_absolute() or bool(re.match(r"^[A-Za-z]:/", normalized))


def _embedded_credential(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _literal_secret_changes(value: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            address = f"{prefix}.{key}"
            if _SECRET.search(str(key)) and child not in (None, "", False, [], {}):
                text = str(child)
                reference = bool(re.search(r"\$\{|\{\{|NOMAD_|VAULT_|CONSUL_", text, re.I))
                changes.append(
                    _change(
                        address,
                        "secret_reference" if reference else "literal_secret",
                        "review" if reference else "dangerous",
                        "Nomad jobspec references externally supplied credential-like data."
                        if reference
                        else "Nomad jobspec embeds credential-like material directly; the "
                        "value is omitted from analysis output.",
                    )
                )
            changes.extend(_literal_secret_changes(child, address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            changes.extend(_literal_secret_changes(child, f"{prefix}[{index}]"))
    return changes


def _task_changes(task_name: str, task: dict[str, Any], prefix: str) -> list[dict[str, str]]:
    address = f"{prefix}.task.{task_name}"
    changes: list[dict[str, str]] = []
    driver = str(_value(task, "driver", "Driver", default="")).lower()
    if not driver:
        changes.append(
            _change(
                f"{address}.driver",
                "missing_driver",
                "dangerous",
                "Nomad task has no explicit driver.",
            )
        )
    else:
        dangerous = driver in {"raw_exec", "exec", "qemu", "java"}
        changes.append(
            _change(
                f"{address}.driver",
                "task_driver",
                "dangerous" if dangerous else "review",
                f"Nomad task uses {driver!r} driver; review isolation, host access, plugin "
                "provenance, and client capabilities.",
            )
        )
    user = str(_value(task, "user", "User", default=""))
    if not user or user.lower() in {"root", "administrator", "system"}:
        changes.append(
            _change(
                f"{address}.user",
                "privileged_identity",
                "dangerous",
                "Nomad task may run as the driver or host default privileged identity.",
            )
        )

    configs = _items(_value(task, "config", "Config", default=[]))
    for index, config in enumerate(configs):
        if not isinstance(config, dict):
            continue
        config_address = f"{address}.config[{index}]"
        image = str(_value(config, "image", "Image", default=""))
        if image:
            changes.append(
                _change(
                    f"{config_address}.image",
                    "image",
                    "review" if _digest_pinned(image) else "dangerous",
                    "Nomad task uses an immutable image digest."
                    if _digest_pinned(image)
                    else "Nomad task image is not pinned to a full sha256 digest.",
                )
            )
        for key in ("command", "args", "entrypoint", "Command", "Args", "Entrypoint"):
            if config.get(key):
                changes.append(
                    _change(
                        f"{config_address}.{key.lower()}",
                        "command",
                        "dangerous",
                        "Nomad driver command or arguments define executable workload behavior.",
                    )
                )
        risky = {
            "privileged": "privileged container execution",
            "pid_mode": "host or shared process namespace",
            "ipc_mode": "host or shared IPC namespace",
            "network_mode": "driver network namespace override",
            "devices": "host device access",
            "volumes": "host or allocation volume mounts",
            "mounts": "host or allocation volume mounts",
            "cap_add": "additional Linux capabilities",
        }
        for key, reason in risky.items():
            value = config.get(key)
            enabled = value is True or value not in (None, "", False, [], {})
            if enabled:
                changes.append(
                    _change(
                        f"{config_address}.{key}",
                        key,
                        "dangerous",
                        f"Nomad task requests {reason}.",
                    )
                )
        changes.extend(_literal_secret_changes(config, config_address))

    for index, artifact in enumerate(_items(_value(task, "artifact", "Artifacts", default=[]))):
        if not isinstance(artifact, dict):
            continue
        source = str(_value(artifact, "source", "GetterSource", default=""))
        options = _value(artifact, "options", "GetterOptions", default={})
        checksum = options.get("checksum") if isinstance(options, dict) else None
        dangerous = (
            source.lower().startswith(("http://", "git://"))
            or _embedded_credential(source)
            or not checksum
        )
        changes.append(
            _change(
                f"{address}.artifact[{index}]",
                "artifact",
                "dangerous" if dangerous else "review",
                "Nomad downloads a task artifact; review transport, immutable origin, checksum, "
                "archive extraction, destination, ownership, and credentials.",
            )
        )

    for index, template in enumerate(_items(_value(task, "template", "Templates", default=[]))):
        if not isinstance(template, dict):
            continue
        template_address = f"{address}.template[{index}]"
        data = str(_value(template, "data", "EmbeddedTmpl", default=""))
        source = str(_value(template, "source", "SourcePath", default=""))
        destination = str(_value(template, "destination", "DestPath", default=""))
        if source:
            changes.append(
                _change(
                    f"{template_address}.source",
                    "template_source",
                    "review",
                    "Nomad loads template content from a task-relative source path.",
                )
            )
        if _TEMPLATE_REMOTE.search(data):
            changes.append(
                _change(
                    f"{template_address}.remote_data",
                    "template_remote_data",
                    "dangerous",
                    "Nomad template reads Vault, Consul, Nomad Variables, or service data into "
                    "the allocation.",
                )
            )
        if _TEMPLATE_EXEC.search(data):
            changes.append(
                _change(
                    f"{template_address}.function",
                    "template_execution",
                    "dangerous",
                    "Nomad template uses a high-risk plugin, nested-template, or file-writing "
                    "function.",
                )
            )
        if destination and _absolute_path(destination):
            changes.append(
                _change(
                    f"{template_address}.destination",
                    "absolute_template_destination",
                    "dangerous",
                    "Nomad template targets an absolute path; exec-like drivers may write "
                    "outside the allocation directory.",
                )
            )
        if bool(_value(template, "env", "Envvars", default=False)):
            changes.append(
                _change(
                    f"{template_address}.env",
                    "template_environment",
                    "dangerous",
                    "Nomad parses rendered template content into task environment variables, "
                    "which may expose secrets.",
                )
            )
        change_mode = str(_value(template, "change_mode", "ChangeMode", default="")).lower()
        if change_mode in {"script", "restart"}:
            changes.append(
                _change(
                    f"{template_address}.change_mode",
                    "template_change_action",
                    "dangerous",
                    f"Nomad template changes trigger {change_mode!r} task behavior.",
                )
            )

    vaults = _items(_value(task, "vault", "Vault", default=[]))
    if vaults:
        changes.append(
            _change(
                f"{address}.vault",
                "vault_access",
                "dangerous",
                "Nomad task requests Vault policies or workload identity; review least "
                "privilege, namespace, token exposure, renewal, and outage behavior.",
            )
        )
    consuls = _items(_value(task, "consul", "Consul", default=[]))
    if consuls:
        changes.append(
            _change(
                f"{address}.consul",
                "consul_access",
                "review",
                "Nomad task requests Consul integration and may receive a token or query "
                "service/KV data.",
            )
        )
    for index, identity in enumerate(_items(_value(task, "identity", "Identities", default=[]))):
        if isinstance(identity, dict):
            exposed = bool(_value(identity, "env", "Env", default=False)) or bool(
                _value(identity, "file", "File", default=False)
            )
            ttl = _value(identity, "ttl", "TTL", default="")
            changes.append(
                _change(
                    f"{address}.identity[{index}]",
                    "workload_identity",
                    "dangerous" if exposed or not ttl else "review",
                    "Nomad exposes or mints workload identity; review audience, TTL, "
                    "file/environment exposure, renewal, and downstream trust.",
                )
            )
    for index, lifecycle in enumerate(_items(_value(task, "lifecycle", "Lifecycle", default=[]))):
        if isinstance(lifecycle, dict):
            changes.append(
                _change(
                    f"{address}.lifecycle[{index}]",
                    "lifecycle_task",
                    "review",
                    "Nomad lifecycle hook changes task ordering, sidecar behavior, and failure "
                    "propagation.",
                )
            )
    changes.extend(
        _literal_secret_changes(_value(task, "env", "Env", default={}), f"{address}.env")
    )
    changes.extend(_literal_secret_changes(task, address))
    return changes


def _group_changes(group_name: str, group: dict[str, Any], prefix: str) -> list[dict[str, str]]:
    address = f"{prefix}.group.{group_name}"
    changes: list[dict[str, str]] = []
    for index, network in enumerate(_items(_value(group, "network", "Networks", default=[]))):
        if not isinstance(network, dict):
            continue
        mode = str(_value(network, "mode", "Mode", default="")).lower()
        if mode in {"host", "raw_exec"}:
            changes.append(
                _change(
                    f"{address}.network[{index}].mode",
                    "host_network",
                    "dangerous",
                    "Nomad task group shares the host network namespace.",
                )
            )
        ports = _blocks(network, "port", "DynamicPorts", "ReservedPorts")
        for port_name, port in ports:
            if _value(port, "static", "Value", default=0):
                changes.append(
                    _change(
                        f"{address}.network[{index}].port.{port_name}",
                        "static_port",
                        "review",
                        "Nomad reserves a static host port; review exposure, collision, firewall, "
                        "and scheduling constraints.",
                    )
                )
    for volume_name, volume in _blocks(group, "volume", "Volumes"):
        volume_type = str(_value(volume, "type", "Type", default="")).lower()
        source = str(_value(volume, "source", "Source", default=""))
        dangerous = volume_type == "host" or _absolute_path(source)
        changes.append(
            _change(
                f"{address}.volume.{volume_name}",
                "host_volume" if dangerous else "volume",
                "dangerous" if dangerous else "review",
                "Nomad mounts persistent or host storage; review source identity, access mode, "
                "attachment, permissions, encryption, snapshots, and deletion behavior.",
            )
        )
    services = _items(_value(group, "service", "Services", default=[]))
    for index, service in enumerate(services):
        if isinstance(service, dict):
            connect = bool(_value(service, "connect", "Connect", default=[]))
            provider = str(_value(service, "provider", "Provider", default="consul"))
            changes.append(
                _change(
                    f"{address}.service[{index}]",
                    "service_mesh" if connect else "service_registration",
                    "review",
                    f"Nomad registers a {provider} service; review checks, tags, address/port "
                    "exposure, identity, and mesh upstreams.",
                )
            )
    if _value(group, "update", "Update", default=None):
        changes.append(
            _change(
                f"{address}.update",
                "rollout_strategy",
                "review",
                "Nomad update strategy controls canaries, parallelism, health deadlines, "
                "auto-revert, and promotion.",
            )
        )
    for task_name, task in _blocks(group, "task", "Tasks"):
        changes.extend(_task_changes(task_name, task, address))
    changes.extend(_literal_secret_changes(group, address))
    return changes


def nomad_job_changes(payload: dict[str, Any]) -> list[dict[str, str]]:
    job = payload["document"]
    job_name = str(payload["name"])
    address = f"job.{job_name}"
    changes: list[dict[str, str]] = []
    job_type = str(_value(job, "type", "Type", default="service")).lower()
    if job_type in {"system", "sysbatch"}:
        changes.append(
            _change(
                f"{address}.type",
                "cluster_wide_job",
                "dangerous",
                f"Nomad {job_type!r} job can run on every eligible client node.",
            )
        )
    datacenters = _items(_value(job, "datacenters", "Datacenters", default=[]))
    if "*" in datacenters:
        changes.append(
            _change(
                f"{address}.datacenters",
                "global_placement",
                "dangerous",
                "Nomad job targets every datacenter.",
            )
        )
    namespace = str(_value(job, "namespace", "Namespace", default="default"))
    if namespace in {"*", ""}:
        changes.append(
            _change(
                f"{address}.namespace",
                "broad_namespace",
                "dangerous",
                "Nomad job has broad or unresolved namespace scope.",
            )
        )
    if _value(job, "periodic", "Periodic", default=None) or _value(
        job, "parameterized", "ParameterizedJob", default=None
    ):
        changes.append(
            _change(
                f"{address}.dispatch",
                "unattended_execution",
                "review",
                "Nomad periodic or parameterized job can create unattended or externally "
                "dispatched executions.",
            )
        )
    for group_name, group in _blocks(job, "group", "TaskGroups"):
        changes.extend(_group_changes(group_name, group, address))
    if not _blocks(job, "group", "TaskGroups"):
        changes.append(
            _change(
                f"{address}.groups",
                "missing_task_groups",
                "dangerous",
                "Nomad jobspec contains no recognized task groups.",
            )
        )
    changes.extend(_literal_secret_changes(job, address))
    changes.append(
        _change(
            "nomad.effective_jobspec",
            "source_boundary",
            "review",
            "Static analysis does not run Nomad HCL2 functions, resolve variables or locals, "
            "download artifacts, render templates, query Vault/Consul/Nomad Variables, inspect "
            "driver plugins, plan scheduling, or register the job.",
        )
    )
    return changes
