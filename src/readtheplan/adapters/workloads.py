from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class WorkloadInputError(ValueError):
    """Raised when a Compose or Nomad artifact is invalid."""


def parse_docker_compose(source: str) -> dict[str, Any]:
    """Parse a Docker Compose YAML document without resolving external files."""
    if not source.strip():
        raise WorkloadInputError("input is empty")
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise WorkloadInputError(f"invalid YAML: {exc}") from exc
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("services"), dict)
        or not document["services"]
    ):
        raise WorkloadInputError("Compose input must contain a non-empty services object")
    return {"docker_compose": document}


def parse_nomad_plan(source: str) -> dict[str, Any]:
    """Parse a Nomad ``/v1/job/:id/plan`` JSON response."""
    if not source.strip():
        raise WorkloadInputError("input is empty")
    try:
        document = json.loads(source)
    except json.JSONDecodeError as exc:
        raise WorkloadInputError(f"invalid JSON: {exc}") from exc
    if not isinstance(document, dict) or not any(
        key in document for key in ("Diff", "Annotations", "FailedTGAllocs")
    ):
        raise WorkloadInputError("Nomad input must be a job plan API response")
    return {"nomad_plan": document}


def parse_nomad(source: str) -> dict[str, Any]:
    """Parse a Nomad plan API response or HCL/JSON jobspec source."""
    try:
        return parse_nomad_plan(source)
    except WorkloadInputError as plan_error:
        from readtheplan.adapters.nomad_job import NomadJobInputError, parse_nomad_job

        try:
            return parse_nomad_job(source)
        except NomadJobInputError as job_error:
            raise WorkloadInputError(
                f"input is neither a Nomad plan response nor jobspec: {job_error}"
            ) from plan_error


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {
        "Address": address,
        "Kind": kind,
        "Risk": risk,
        "Explanation": explanation,
    }


def _is_digest_pinned(reference: Any) -> bool:
    return "@sha256:" in str(reference).lower()


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _mount_source(mount: Any) -> tuple[str, bool]:
    if isinstance(mount, dict):
        source = str(mount.get("source", ""))
        read_only = bool(mount.get("read_only"))
        return source, read_only
    text = str(mount)
    parts = text.split(":")
    windows_source = (
        len(parts) > 2
        and len(parts[0]) == 1
        and parts[0].isalpha()
        and parts[1].startswith(("/", "\\"))
    )
    source = f"{parts[0]}:{parts[1]}" if windows_source else parts[0] if len(parts) > 1 else ""
    option_start = 3 if windows_source else 2
    read_only = any(part == "ro" or "ro" in part.split(",") for part in parts[option_start:])
    return source, read_only


def _is_host_bind(source: str) -> bool:
    normalized = source.replace("\\", "/")
    return normalized.startswith(("/", "./", "../", "~/")) or (
        len(normalized) > 2 and normalized[1:3] == ":/"
    )


def _is_sensitive_bind(source: str) -> bool:
    normalized = source.replace("\\", "/").lower().rstrip("/")
    return normalized in {"/", "/etc", "/proc", "/sys", "/var/run"} or any(
        token in normalized for token in ("docker.sock", "podman.sock", "/.ssh", "/.aws", "/.kube")
    )


def _has_sensitive_environment(value: Any) -> bool:
    sensitive_tokens = ("password", "passwd", "secret", "token", "api_key", "private_key")
    if isinstance(value, dict):
        return any(any(token in str(key).lower() for token in sensitive_tokens) for key in value)
    for item in _as_list(value):
        name = str(item).split("=", 1)[0].lower()
        if any(token in name for token in sensitive_tokens):
            return True
    return False


class _WorkloadAdapter(BaseAdapter):
    wrapper_key = ""
    tool_name = "Workload"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        return isinstance(input_data.get(self.wrapper_key), dict)

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"{self.adapter_name.replace('-', '_')}_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


class DockerComposeAdapter(_WorkloadAdapter):
    wrapper_key = "docker_compose"
    tool_name = "Docker Compose"

    @property
    def adapter_name(self) -> str:
        return "docker-compose"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        compose = input_data[self.wrapper_key]
        changes: list[dict[str, Any]] = []

        for service_name, service in compose.get("services", {}).items():
            address = f"services.{service_name}"
            service_change_start = len(changes)
            if not isinstance(service, dict):
                changes.append(
                    _change(
                        address,
                        "unresolved",
                        "review",
                        "Compose service is not an object and requires manual review.",
                    )
                )
                continue

            image = service.get("image")
            if image is not None:
                pinned = _is_digest_pinned(image)
                changes.append(
                    _change(
                        f"{address}.image",
                        "image",
                        "review" if pinned else "dangerous",
                        "Compose image executes workload code; verify provenance and pin "
                        "production images to an immutable digest.",
                    )
                )
            if "build" in service:
                changes.append(
                    _change(
                        f"{address}.build",
                        "build",
                        "dangerous",
                        "Compose build executes a Dockerfile and build context; review "
                        "instructions, secrets, entitlements, and source boundaries.",
                    )
                )

            for key in ("command", "entrypoint", "post_start", "pre_stop"):
                if key in service:
                    changes.append(
                        _change(
                            f"{address}.{key}",
                            "command",
                            "dangerous",
                            f"Compose {key} can execute arbitrary commands in the container.",
                        )
                    )

            if service.get("privileged") is True:
                changes.append(
                    _change(
                        f"{address}.privileged",
                        "privileged",
                        "dangerous",
                        "Compose service requests privileged container access to the host.",
                    )
                )

            for namespace_key in (
                "network_mode",
                "pid",
                "ipc",
                "userns_mode",
                "uts",
                "cgroup",
            ):
                value = str(service.get(namespace_key, "")).lower()
                if value == "host" or value.startswith("container:"):
                    changes.append(
                        _change(
                            f"{address}.{namespace_key}",
                            "host_namespace",
                            "dangerous",
                            f"Compose {namespace_key} shares a host or container namespace.",
                        )
                    )

            if service.get("use_api_socket") is True:
                changes.append(
                    _change(
                        f"{address}.use_api_socket",
                        "container_api",
                        "dangerous",
                        "Compose service receives the container engine API socket and credentials.",
                    )
                )

            capabilities = {str(item).upper() for item in _as_list(service.get("cap_add"))}
            if capabilities:
                high_risk = bool(capabilities & {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"})
                changes.append(
                    _change(
                        f"{address}.cap_add",
                        "capability",
                        "dangerous" if high_risk else "review",
                        "Compose service adds Linux capabilities; verify each capability "
                        "is required and constrained.",
                    )
                )
            dropped = {str(item).upper() for item in _as_list(service.get("cap_drop"))}
            if "ALL" in dropped:
                changes.append(
                    _change(
                        f"{address}.cap_drop",
                        "hardening",
                        "safe",
                        "Compose service drops all Linux capabilities by default.",
                    )
                )
            if service.get("read_only") is True:
                changes.append(
                    _change(
                        f"{address}.read_only",
                        "hardening",
                        "safe",
                        "Compose service uses a read-only root filesystem.",
                    )
                )

            for index, mount in enumerate(_as_list(service.get("volumes"))):
                source, read_only = _mount_source(mount)
                if not source:
                    continue
                host_bind = _is_host_bind(source)
                sensitive = host_bind and _is_sensitive_bind(source)
                risk = "dangerous" if sensitive else "review"
                access = "read-only" if read_only else "read-write"
                changes.append(
                    _change(
                        f"{address}.volumes[{index}]",
                        "mount",
                        risk,
                        f"Compose mounts {source!r} with {access} access; verify host "
                        "exposure, persistence, and data mutation scope.",
                    )
                )

            for key in ("devices", "device_cgroup_rules"):
                if service.get(key):
                    changes.append(
                        _change(
                            f"{address}.{key}",
                            "device",
                            "dangerous",
                            "Compose service receives host device access.",
                        )
                    )

            if service.get("secrets"):
                changes.append(
                    _change(
                        f"{address}.secrets",
                        "secret_input",
                        "dangerous",
                        "Compose service receives secret material; verify source, target, "
                        "permissions, and log handling.",
                    )
                )
            if _has_sensitive_environment(service.get("environment")):
                changes.append(
                    _change(
                        f"{address}.environment",
                        "secret_input",
                        "dangerous",
                        "Compose environment declares credential-like variables; verify "
                        "secret sourcing and prevent plaintext or log exposure.",
                    )
                )
            for key in ("env_file", "extends"):
                if key in service:
                    changes.append(
                        _change(
                            f"{address}.{key}",
                            "external_file",
                            "review",
                            f"Compose {key} reads configuration outside this service; "
                            "review the resolved file content.",
                        )
                    )

            for index, port in enumerate(_as_list(service.get("ports"))):
                published = self._published_port(port)
                if published:
                    host_ip = published[0]
                    public = not host_ip or host_ip in {"0.0.0.0", "::"}
                    changes.append(
                        _change(
                            f"{address}.ports[{index}]",
                            "published_port",
                            "dangerous" if public else "review",
                            "Compose publishes a container port to all host interfaces."
                            if public
                            else "Compose publishes a container port to a specific host address.",
                        )
                    )

            security_options = " ".join(
                str(item).lower() for item in _as_list(service.get("security_opt"))
            )
            if (
                "seccomp=unconfined" in security_options
                or "apparmor=unconfined" in security_options
            ):
                changes.append(
                    _change(
                        f"{address}.security_opt",
                        "security_boundary",
                        "dangerous",
                        "Compose disables a container security profile.",
                    )
                )

            if len(changes) == service_change_start:
                changes.append(
                    _change(
                        address,
                        "service",
                        "review",
                        "Compose service has no recognized image or runtime boundary; "
                        "review its resolved configuration.",
                    )
                )

        for key in ("include", "secrets", "configs"):
            if compose.get(key):
                risk = "dangerous" if key == "secrets" else "review"
                changes.append(
                    _change(
                        f"compose.{key}",
                        "external_input",
                        risk,
                        f"Compose top-level {key} can load external content or expose data; "
                        "review the resolved source.",
                    )
                )
        return changes

    @staticmethod
    def _published_port(port: Any) -> tuple[str, str] | None:
        if isinstance(port, dict):
            published = port.get("published")
            return (str(port.get("host_ip", "")), str(published)) if published else None
        text = str(port).strip()
        if not text:
            return None
        text = text.rsplit("/", 1)[0]
        if text.startswith("[") and "]" in text:
            host, _, rest = text.partition("]:")
            pieces = rest.split(":")
            return (host[1:], pieces[0]) if len(pieces) >= 2 else None
        pieces = text.split(":")
        if len(pieces) == 2:
            return "", pieces[0]
        if len(pieces) >= 3:
            return pieces[0], pieces[-2]
        return None


class NomadPlanAdapter(_WorkloadAdapter):
    wrapper_key = "nomad_plan"
    tool_name = "Nomad"

    @property
    def adapter_name(self) -> str:
        return "nomad"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        return isinstance(input_data.get("nomad_plan"), dict) or isinstance(
            input_data.get("nomad_job"), dict
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        if "nomad_job" in input_data:
            from readtheplan.adapters.nomad_job import nomad_job_changes

            return nomad_job_changes(input_data["nomad_job"])
        plan = input_data[self.wrapper_key]
        changes: list[dict[str, Any]] = []

        warnings = str(plan.get("Warnings") or "").strip()
        if warnings:
            changes.append(
                _change(
                    "plan.warnings",
                    "scheduler_warning",
                    "dangerous",
                    "Nomad scheduler returned warnings that require resolution before run.",
                )
            )

        failed = plan.get("FailedTGAllocs")
        if isinstance(failed, dict) and failed:
            for group_name in failed:
                changes.append(
                    _change(
                        f"failed_allocations.{group_name}",
                        "placement_failure",
                        "dangerous",
                        "Nomad cannot place every planned allocation for this task group.",
                    )
                )

        desired = (plan.get("Annotations") or {}).get("DesiredTGUpdates", {})
        if isinstance(desired, dict):
            for group_name, updates in desired.items():
                if not isinstance(updates, dict):
                    continue
                destructive = int(updates.get("DestructiveUpdate") or 0)
                stopped = int(updates.get("Stop") or 0)
                migrated = int(updates.get("Migrate") or 0)
                placed = int(updates.get("Place") or 0)
                in_place = int(updates.get("InPlaceUpdate") or 0)
                if destructive:
                    changes.append(
                        _change(
                            f"task_groups.{group_name}.destructive_update",
                            "destructive_update",
                            "dangerous",
                            f"Nomad will replace {destructive} allocation(s) in this task group.",
                        )
                    )
                if stopped:
                    changes.append(
                        _change(
                            f"task_groups.{group_name}.stop",
                            "stop",
                            "dangerous",
                            f"Nomad will stop {stopped} allocation(s) in this task group.",
                        )
                    )
                if migrated:
                    changes.append(
                        _change(
                            f"task_groups.{group_name}.migrate",
                            "migration",
                            "review",
                            f"Nomad will migrate {migrated} allocation(s) in this task group.",
                        )
                    )
                if placed or in_place:
                    changes.append(
                        _change(
                            f"task_groups.{group_name}.rollout",
                            "rollout",
                            "review",
                            "Nomad will place or update allocations; verify capacity, health "
                            "checks, canaries, and update strategy.",
                        )
                    )

        diff = plan.get("Diff")
        if isinstance(diff, dict):
            self._walk_diff(diff, "job", changes)
        if not changes:
            changes.append(
                _change(
                    "plan",
                    "no_change",
                    "safe",
                    "Nomad plan reports no scheduler or job-specification changes.",
                )
            )
        return changes

    def _walk_diff(
        self,
        node: dict[str, Any],
        address: str,
        changes: list[dict[str, Any]],
    ) -> None:
        node_type = str(node.get("Type") or "").lower()
        name = str(node.get("Name") or node.get("ID") or "").strip()
        current = f"{address}.{name}" if name else address
        if node_type in {"deleted", "removed"}:
            changes.append(
                _change(
                    current,
                    "delete",
                    "dangerous",
                    "Nomad plan removes a job, task group, task, or nested runtime object.",
                )
            )
        elif node_type in {"added", "edited", "updated"}:
            changes.append(
                _change(
                    current,
                    "job_change",
                    "review",
                    f"Nomad plan {node_type} this job specification object.",
                )
            )

        fields = node.get("Fields") or []
        if isinstance(fields, list):
            for index, field in enumerate(fields):
                if not isinstance(field, dict):
                    continue
                self._field_change(field, f"{current}.fields[{index}]", changes)

        for collection_name in ("TaskGroups", "Tasks", "Objects"):
            children = node.get(collection_name) or []
            if isinstance(children, list):
                for index, child in enumerate(children):
                    if isinstance(child, dict):
                        self._walk_diff(
                            child,
                            f"{current}.{collection_name.lower()}[{index}]",
                            changes,
                        )

    def _field_change(
        self,
        field: dict[str, Any],
        address: str,
        changes: list[dict[str, Any]],
    ) -> None:
        name = str(field.get("Name") or "field")
        old = str(field.get("Old") or "")
        new = str(field.get("New") or "")
        combined = f"{name} {old} {new}".lower()
        risk = "review"
        kind = "field"
        explanation = f"Nomad changes {name!r} from {old!r} to {new!r}."

        if "driver" in name.lower() and new.lower() in {"raw_exec", "exec"}:
            risk = "dangerous"
            kind = "task_driver"
            explanation = "Nomad task uses a host command execution driver."
        elif "privileged" in combined and new.lower() in {"true", "1"}:
            risk = "dangerous"
            kind = "privileged"
            explanation = "Nomad task enables privileged container execution."
        elif any(token in combined for token in ("vault", "secret", "token")):
            risk = "dangerous"
            kind = "secret_input"
            explanation = "Nomad change handles Vault, token, or secret material."
        elif "image" in name.lower() and new:
            risk = "review" if _is_digest_pinned(new) else "dangerous"
            kind = "image"
            explanation = "Nomad task image changes; verify provenance and use an immutable digest."
        elif any(token in name.lower() for token in ("command", "args", "entrypoint")):
            risk = "dangerous"
            kind = "command"
            explanation = "Nomad task command or arguments change executable behavior."

        changes.append(_change(f"{address}.{name}", kind, risk, explanation))


def analyze_workload(
    adapter: _WorkloadAdapter,
    data: dict[str, Any],
    *,
    catalog=None,
) -> dict[str, Any]:
    changes = adapter.analyze(data, tool_name=adapter.tool_name)
    summary = PlanSummary(
        path=Path(f"{adapter.adapter_name}://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name=adapter.tool_name)
    gate["adapter"] = adapter.adapter_name
    if adapter.adapter_name == "nomad":
        gate["artifact_type"] = "jobspec" if "nomad_job" in data else "plan"
    gate["total_changes"] = len(changes)
    return gate


def analyze_docker_compose(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_workload(DockerComposeAdapter(), data, catalog=catalog)


def analyze_nomad_plan(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_workload(NomadPlanAdapter(), data, catalog=catalog)
