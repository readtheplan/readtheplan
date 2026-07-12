from __future__ import annotations

import errno
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.controls import (
    CatalogSchemaError,
    ControlCatalog,
    FrameworkNotFoundError,
    load_catalog,
)
from readtheplan.evolution import EvolutionEngine
from readtheplan.plan import PlanError, PlanSummary, analyze_plan_file
from readtheplan.summary import summary_to_dict


class MissingMCPDependencyError(RuntimeError):
    """Raised when the optional MCP SDK is not installed."""


@dataclass(frozen=True)
class MCPToolInputError(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


def _working_root() -> Path | None:
    """Return the allowed working root from MCP_ROOT env var, or None.

    When set, all plan_path arguments are validated to be within this
    directory tree.  Symlink traversal is resolved before comparison.
    """
    root = os.environ.get("MCP_ROOT", "").strip()
    if not root:
        return None
    return Path(root).resolve()


def _validate_path(plan_path: str) -> Path:
    """Resolve *plan_path* and reject paths outside the allowed working root.

    Raises :class:`MCPToolInputError` with code ``PATH_TRAVERSAL`` when
    ``MCP_ROOT`` is set and the resolved path falls outside it.
    """
    resolved = Path(plan_path).resolve()
    root = _working_root()
    if root is not None:
        try:
            resolved.relative_to(root)
        except ValueError:
            raise MCPToolInputError(
                code="PATH_TRAVERSAL",
                message=(
                    f"plan_path {plan_path!r} resolves outside the allowed working root {root}"
                ),
            ) from None
    return resolved


def _resolve_path(plan_path: str) -> str:
    """Validate *plan_path* against the working root and return the resolved
    absolute path as a string."""
    return str(_validate_path(plan_path))


def _final_path_from_descriptor(descriptor: int) -> Path | None:
    """Return the filesystem path actually opened by *descriptor*.

    ``MCP_ROOT`` is a security boundary, so checking a pathname before a
    separate open is insufficient: the path can be swapped to a symlink in
    between.  Linux exposes the opened path through ``/proc``; Windows exposes
    it through ``GetFinalPathNameByHandleW``.  Callers fail closed when neither
    mechanism is available and confinement is enabled.
    """
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        get_final_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
        get_final_path.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        get_final_path.restype = wintypes.DWORD
        handle = msvcrt.get_osfhandle(descriptor)
        size = get_final_path(handle, None, 0, 0)
        if size == 0:
            return None
        buffer = ctypes.create_unicode_buffer(size + 1)
        written = get_final_path(handle, buffer, len(buffer), 0)
        if written == 0 or written >= len(buffer):
            return None
        final_path = buffer.value
        if final_path.startswith("\\\\?\\UNC\\"):
            final_path = "\\\\" + final_path[8:]
        elif final_path.startswith("\\\\?\\"):
            final_path = final_path[4:]
        return Path(final_path).resolve()

    descriptor_link = Path("/proc/self/fd") / str(descriptor)
    try:
        return descriptor_link.resolve(strict=True)
    except OSError:
        return None


def _read_confined_bytes(path: str) -> bytes:
    """Open *path* once and verify the opened object remains inside MCP_ROOT."""
    resolved = _resolve_path(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP and _working_root() is not None:
            raise MCPToolInputError(
                code="PATH_TRAVERSAL",
                message=f"input path {path!r} changed to a symlink during validation",
            ) from None
        raise

    try:
        root = _working_root()
        if root is not None:
            opened_path = _final_path_from_descriptor(descriptor)
            if opened_path is None:
                raise MCPToolInputError(
                    code="PATH_TRAVERSAL",
                    message=f"cannot verify the opened path for {path!r}",
                )
            try:
                opened_path.relative_to(root)
            except ValueError:
                raise MCPToolInputError(
                    code="PATH_TRAVERSAL",
                    message=(f"input path {path!r} opened outside the allowed working root {root}"),
                ) from None
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def analyze_plan(
    plan_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Analyze a local Terraform plan JSON file for the MCP tool.

    Args:
        plan_path: Local path to ``terraform show -json`` output.
        framework: Optional compliance framework name (e.g. ``soc2``,
            ``hipaa``, ``iso27001``).  When set, each resource change in
            the summary is annotated with the matching control IDs,
            titles, and rationales from the framework catalog.

    Returns:
        The CLI JSON summary.  When *framework* is provided the payload
        includes a top-level ``framework`` key and per-change ``controls``
        lists.
    """
    _check_non_empty(plan_path)
    plan_path = _resolve_path(plan_path)
    catalog = _load_catalog_for_tool(framework)
    summary = _summary_for_tool(plan_path)
    return summary_to_dict(summary, catalog)


def agent_gate(
    plan_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the local coding-agent gate decision for a Terraform plan JSON file.

    Args:
        plan_path: Local path to ``terraform show -json`` output.
        framework: Optional compliance framework name.  When set, the
            required-checks list includes per-resource control identifiers
            (``rtp.control.<framework>.<id>``) and the evidence checklist
            references the framework.
    """
    _check_non_empty(plan_path)
    plan_path = _resolve_path(plan_path)
    catalog = _load_catalog_for_tool(framework)
    summary = _summary_for_tool(plan_path)
    return agent_gate_to_dict(summary, catalog)


def agent_gate_cloudformation(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the agent-gate decision for a CloudFormation Change Set / template diff."""
    from readtheplan.adapters.cloudformation import analyze_cloudformation

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )

    try:
        import json

        input_path = _resolve_path(input_path)
        data = json.loads(_read_confined_bytes(input_path).decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read {input_path}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise MCPToolInputError(code="INVALID_INPUT", message="Input must be a JSON object")

    catalog = _load_catalog_for_tool(framework)
    return analyze_cloudformation(data, catalog=catalog)


def agent_gate_azure(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the agent-gate decision for Azure Bicep/ARM What-If JSON."""
    import json

    from readtheplan.adapters.azure import AzureWhatIfAdapter, analyze_azure_whatif

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        data = json.loads(_read_confined_bytes(input_path).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR",
            message=f"Cannot read Azure What-If input {input_path}: {exc}",
        ) from exc
    if not isinstance(data, dict) or not AzureWhatIfAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Azure deployment What-If output",
        )

    catalog = _load_catalog_for_tool(framework)
    return analyze_azure_whatif(data, catalog=catalog)


def agent_gate_kubernetes(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the agent-gate decision for a Kubernetes manifest diff.

    Accepts JSON or YAML with any of:
      - {"old_manifests": [...], "new_manifests": [...]} — diff format
      - {"resources": [...]} — single manifest format
      - one manifest, ``kind: List``, or multi-document YAML
    """
    from readtheplan.adapters.kubernetes import (
        KubernetesInputError,
        analyze_kubernetes,
        parse_kubernetes_input,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )

    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except FileNotFoundError:
        raise MCPToolInputError(
            code="FILE_NOT_FOUND",
            message=f"File not found: {input_path}",
        )
    except UnicodeDecodeError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT", message=f"Input is not UTF-8: {input_path}"
        ) from exc
    try:
        data = parse_kubernetes_input(source)
    except KubernetesInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Kubernetes input in {input_path}: {exc}",
        ) from exc

    catalog = _load_catalog_for_tool(framework)
    return analyze_kubernetes(data, catalog=catalog)


def agent_gate_pulumi(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the agent-gate decision for Pulumi preview JSON or JSON events."""
    from readtheplan.adapters.pulumi import (
        PulumiAdapter,
        PulumiPreviewError,
        analyze_pulumi,
        parse_pulumi_preview,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )

    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read {input_path}: {exc}"
        ) from exc

    try:
        data = parse_pulumi_preview(source)
    except PulumiPreviewError as exc:
        raise MCPToolInputError(
            code="INVALID_JSON",
            message=f"Invalid Pulumi preview JSON in {input_path}: {exc}",
        ) from exc
    if not isinstance(data, dict) or not PulumiAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Pulumi preview output",
        )

    catalog = _load_catalog_for_tool(framework)
    return analyze_pulumi(data, catalog=catalog)


def agent_gate_pipeline(
    input_path: str,
    ecosystem: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for supported CI pipeline YAML."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.pipelines import (
        PipelineInputError,
        analyze_pipeline,
        parse_pipeline_yaml,
    )

    if ecosystem not in {
        "github-actions",
        "gitlab-ci",
        "circleci",
        "azure-pipelines",
        "bitbucket-pipelines",
        "buildkite",
    }:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=(
                "ecosystem must be github-actions, gitlab-ci, circleci, "
                "azure-pipelines, bitbucket-pipelines, or buildkite"
            ),
        )
    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read {ecosystem} input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_pipeline_yaml(source, ecosystem)
    except PipelineInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid {ecosystem} pipeline YAML in {input_path}: {exc}",
        ) from exc

    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != ecosystem:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Input is not recognized as {ecosystem} configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_pipeline(adapter, data, catalog=catalog)  # type: ignore[arg-type]


def agent_gate_atlantis(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Atlantis repo-level or server-side YAML."""
    from readtheplan.adapters.atlantis import (
        AtlantisAdapter,
        AtlantisInputError,
        analyze_atlantis,
        parse_atlantis_config,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Atlantis input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_atlantis_config(source)
    except AtlantisInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Atlantis configuration in {input_path}: {exc}",
        ) from exc
    if not AtlantisAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input is not recognized as Atlantis configuration"
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_atlantis(data, catalog=catalog)


def agent_gate_workload(
    input_path: str,
    ecosystem: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for Docker Compose or a Nomad plan response."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.workloads import (
        WorkloadInputError,
        analyze_workload,
        parse_docker_compose,
        parse_nomad_plan,
    )

    parsers = {
        "docker-compose": parse_docker_compose,
        "nomad": parse_nomad_plan,
    }
    if ecosystem not in parsers:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="ecosystem must be docker-compose or nomad",
        )
    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read {ecosystem} input {input_path}: {exc}"
        ) from exc
    try:
        data = parsers[ecosystem](source)
    except WorkloadInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid {ecosystem} input in {input_path}: {exc}",
        ) from exc

    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != ecosystem:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Input is not recognized as {ecosystem} configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_workload(adapter, data, catalog=catalog)  # type: ignore[arg-type]


def agent_gate_packer(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for local Packer inspect output."""
    from readtheplan.adapters.packer import (
        PackerInspectAdapter,
        PackerInspectError,
        analyze_packer,
        parse_packer_inspect,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Packer input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_packer_inspect(source)
    except PackerInspectError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Packer inspect output in {input_path}: {exc}",
        ) from exc
    if not PackerInspectAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Packer inspect output",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_packer(data, catalog=catalog)


def agent_gate_salt(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for a local Salt SLS file."""
    from readtheplan.adapters.salt import SaltAdapter, SaltInputError, analyze_salt, parse_salt_sls

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Salt input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_salt_sls(source)
    except SaltInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Salt SLS in {input_path}: {exc}",
        ) from exc
    if not SaltAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as a Salt SLS state",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_salt(data, catalog=catalog)


def agent_gate_vagrant(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for a local Vagrantfile."""
    from readtheplan.adapters.vagrant import (
        VagrantAdapter,
        VagrantInputError,
        analyze_vagrant,
        parse_vagrantfile,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Vagrant input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_vagrantfile(source)
    except VagrantInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Vagrantfile in {input_path}: {exc}",
        ) from exc
    if not VagrantAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as a Vagrantfile",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_vagrant(data, catalog=catalog)


def agent_gate_cloud_init(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for local cloud-init user-data."""
    from readtheplan.adapters.cloud_init import (
        CloudInitAdapter,
        CloudInitInputError,
        analyze_cloud_init,
        parse_cloud_init,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR",
            message=f"Cannot read cloud-init input {input_path}: {exc}",
        ) from exc
    try:
        data = parse_cloud_init(source)
    except CloudInitInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid cloud-init user-data in {input_path}: {exc}",
        ) from exc
    if not CloudInitAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as cloud-init user-data",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_cloud_init(data, catalog=catalog)


def agent_gate_systemd(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for a local systemd unit file."""
    from readtheplan.adapters.systemd import (
        SystemdUnitAdapter,
        SystemdUnitInputError,
        analyze_systemd,
        parse_systemd_unit,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read systemd input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_systemd_unit(source)
    except SystemdUnitInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid systemd unit in {input_path}: {exc}",
        ) from exc
    if not SystemdUnitAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as a systemd unit",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_systemd(data, catalog=catalog)


def agent_gate_otel_collector(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for OpenTelemetry Collector YAML."""
    from readtheplan.adapters.otel_collector import (
        OTelCollectorAdapter,
        OTelCollectorInputError,
        analyze_otel_collector,
        parse_otel_collector_config,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Collector input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_otel_collector_config(source)
    except OTelCollectorInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Collector configuration in {input_path}: {exc}",
        ) from exc
    if not OTelCollectorAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input is not recognized as Collector configuration"
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_otel_collector(data, catalog=catalog)


def agent_gate_monitoring(
    input_path: str,
    ecosystem: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Prometheus or Alertmanager YAML."""
    from readtheplan.adapters.monitoring import (
        AlertmanagerAdapter,
        MonitoringInputError,
        PrometheusAdapter,
        analyze_monitoring,
        parse_monitoring_config,
    )

    if ecosystem not in {"prometheus", "alertmanager"}:
        raise MCPToolInputError(
            code="INVALID_INPUT", message="ecosystem must be prometheus or alertmanager"
        )
    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read {ecosystem} input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_monitoring_config(source, ecosystem)
    except MonitoringInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid {ecosystem} configuration in {input_path}: {exc}",
        ) from exc
    adapter = PrometheusAdapter() if ecosystem == "prometheus" else AlertmanagerAdapter()
    if not adapter.can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message=f"Input is not recognized as {ecosystem} configuration"
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_monitoring(data, catalog=catalog)


def agent_gate_envoy(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Envoy bootstrap or config_dump data."""
    from readtheplan.adapters.envoy import (
        EnvoyAdapter,
        EnvoyInputError,
        analyze_envoy,
        parse_envoy_config,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Envoy input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_envoy_config(source)
    except EnvoyInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT", message=f"Invalid Envoy input in {input_path}: {exc}"
        ) from exc
    if not EnvoyAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input is not recognized as Envoy configuration"
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_envoy(data, catalog=catalog)


def agent_gate_proxy_config(
    input_path: str,
    ecosystem: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for local NGINX or HAProxy configuration."""
    from readtheplan.adapters.proxy_configs import (
        HAProxyAdapter,
        NginxAdapter,
        ProxyConfigInputError,
        analyze_proxy_config,
        parse_haproxy_config,
        parse_nginx_config,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    if ecosystem not in {"nginx", "haproxy"}:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="ecosystem must be one of: nginx, haproxy",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read {ecosystem} input {input_path}: {exc}"
        ) from exc
    parser = parse_nginx_config if ecosystem == "nginx" else parse_haproxy_config
    adapter = NginxAdapter() if ecosystem == "nginx" else HAProxyAdapter()
    try:
        data = parser(source)
    except ProxyConfigInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid {ecosystem} configuration in {input_path}: {exc}",
        ) from exc
    if not adapter.can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Input is not recognized as {ecosystem} configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_proxy_config(data, catalog=catalog)


def agent_gate_dockerfile(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for a local Dockerfile/Containerfile."""
    from readtheplan.adapters.dockerfile import (
        DockerfileAdapter,
        DockerfileInputError,
        analyze_dockerfile,
        parse_dockerfile,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR",
            message=f"Cannot read Dockerfile input {input_path}: {exc}",
        ) from exc
    try:
        data = parse_dockerfile(source)
    except DockerfileInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Dockerfile in {input_path}: {exc}",
        ) from exc
    if not DockerfileAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as a Dockerfile",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_dockerfile(data, catalog=catalog)


def _load_catalog_for_tool(framework: str | None) -> ControlCatalog | None:
    """Load a compliance framework catalog, or return ``None``."""
    if not framework:
        return None
    try:
        return load_catalog(framework)
    except FrameworkNotFoundError as exc:
        raise MCPToolInputError(code="FRAMEWORK_NOT_FOUND", message=str(exc)) from exc
    except CatalogSchemaError as exc:
        raise MCPToolInputError(code="CATALOG_ERROR", message=str(exc)) from exc


def _check_non_empty(plan_path: str) -> None:
    """Reject empty or whitespace-only plan paths early."""
    if not isinstance(plan_path, str) or not plan_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="plan_path must be a non-empty string",
        )


def _summary_for_tool(plan_path: str) -> PlanSummary:
    import json

    plan_file = Path(plan_path)
    try:
        try:
            raw = _read_confined_bytes(plan_path).decode("utf-8")
        except FileNotFoundError as exc:
            raise PlanError(f"plan file does not exist: {plan_file}") from exc
        except IsADirectoryError as exc:
            raise PlanError(f"plan path is a directory, not a file: {plan_file}") from exc
        except PermissionError as exc:
            if plan_file.is_dir():
                raise PlanError(f"plan path is a directory, not a file: {plan_file}") from exc
            raise PlanError(f"cannot read plan file {plan_file}: {exc}") from exc
        except OSError as exc:
            raise PlanError(f"cannot read plan file {plan_file}: {exc}") from exc

        if not raw.strip():
            raise PlanError(f"plan file is empty: {plan_file}")
        try:
            plan_data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PlanError(
                f"invalid JSON in {plan_file}: line {exc.lineno}, column {exc.colno}: {exc.msg}"
            ) from exc
        if not isinstance(plan_data, dict):
            raise PlanError(f"Terraform plan JSON must be an object: {plan_file}")

        summary = analyze_plan_file(
            plan_data,
            use_rules=True,
            _original_path=plan_file,
        )
    except PlanError as exc:
        raise MCPToolInputError(code="PLAN_ERROR", message=str(exc)) from exc

    return summary


def create_server() -> Any:
    FastMCP = _load_fastmcp()
    mcp = FastMCP("readtheplan")

    analyze_plan_handler = analyze_plan
    agent_gate_handler = agent_gate
    agent_gate_cfn_handler = agent_gate_cloudformation
    agent_gate_azure_handler = agent_gate_azure
    agent_gate_k8s_handler = agent_gate_kubernetes
    agent_gate_pulumi_handler = agent_gate_pulumi
    agent_gate_pipeline_handler = agent_gate_pipeline
    agent_gate_atlantis_handler = agent_gate_atlantis
    agent_gate_workload_handler = agent_gate_workload
    agent_gate_packer_handler = agent_gate_packer
    agent_gate_salt_handler = agent_gate_salt
    agent_gate_vagrant_handler = agent_gate_vagrant
    agent_gate_cloud_init_handler = agent_gate_cloud_init
    agent_gate_systemd_handler = agent_gate_systemd
    agent_gate_envoy_handler = agent_gate_envoy
    agent_gate_monitoring_handler = agent_gate_monitoring
    agent_gate_otel_collector_handler = agent_gate_otel_collector
    agent_gate_proxy_config_handler = agent_gate_proxy_config
    agent_gate_dockerfile_handler = agent_gate_dockerfile

    @mcp.tool(name="analyze_plan")
    def _analyze_plan_tool(
        plan_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Analyze a local Terraform plan JSON file and return the CLI JSON summary.

        Args:
            plan_path: Local path to terraform show -json output.
            framework: Optional compliance framework (e.g. soc2, hipaa, iso27001).
                When set, returns per-change control annotations.
        """
        return analyze_plan_handler(plan_path, framework=framework)

    @mcp.tool(name="agent_gate")
    def _agent_gate_tool(
        plan_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return proceed, warn, or block instructions for a local Terraform plan.

        Args:
            plan_path: Local path to terraform show -json output.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_handler(plan_path, framework=framework)

    @mcp.tool(name="agent_gate_cloudformation")
    def _agent_gate_cfn_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return the gate decision for a CloudFormation Change Set / template diff."""
        return agent_gate_cfn_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_azure")
    def _agent_gate_azure_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return the gate decision for Azure Bicep/ARM What-If JSON."""
        return agent_gate_azure_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_kubernetes")
    def _agent_gate_k8s_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return the agent-gate decision for a Kubernetes manifest diff.

        Args:
            input_path: Path to a JSON or YAML file. Supports:
                - {"old_manifests": [...], "new_manifests": [...]} — diff format
                - {"resources": [...]} — single manifest format
                - one manifest, kind: List, or multi-document YAML
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_k8s_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_pulumi")
    def _agent_gate_pulumi_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return the agent-gate decision for local Pulumi preview output.

        Args:
            input_path: Path to preview digest JSON or streaming JSON events.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_pulumi_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_pipeline")
    def _agent_gate_pipeline_tool(
        input_path: str,
        ecosystem: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for supported GitHub, GitLab, CircleCI, Azure, or Bitbucket YAML.

        Args:
            input_path: Local path to the pipeline YAML file.
            ecosystem: github-actions, gitlab-ci, circleci, azure-pipelines,
                bitbucket-pipelines, or buildkite.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_pipeline_handler(
            input_path,
            ecosystem,
            framework=framework,
        )

    @mcp.tool(name="agent_gate_atlantis")
    def _agent_gate_atlantis_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Atlantis repo-level or server-side configuration.

        Args:
            input_path: Local path to atlantis.yaml or server repos.yaml.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_atlantis_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_workload")
    def _agent_gate_workload_tool(
        input_path: str,
        ecosystem: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Docker Compose or a Nomad job plan response.

        Args:
            input_path: Local path to Compose YAML or Nomad plan response JSON.
            ecosystem: docker-compose or nomad.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_workload_handler(
            input_path,
            ecosystem,
            framework=framework,
        )

    @mcp.tool(name="agent_gate_packer")
    def _agent_gate_packer_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for human or machine-readable Packer inspect output.

        Args:
            input_path: Local path to saved `packer inspect` output.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_packer_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_salt")
    def _agent_gate_salt_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for a Salt SLS YAML/Jinja state file.

        Args:
            input_path: Local path to an SLS state file.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_salt_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_vagrant")
    def _agent_gate_vagrant_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for a Vagrantfile without evaluating its Ruby code.

        Args:
            input_path: Local path to a Vagrantfile.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_vagrant_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_cloud_init")
    def _agent_gate_cloud_init_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for cloud-init user-data without executing guest code.

        Args:
            input_path: Local path to cloud-init user-data.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_cloud_init_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_systemd")
    def _agent_gate_systemd_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for a systemd unit without invoking systemd.

        Args:
            input_path: Local path to a systemd unit file.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_systemd_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_otel_collector")
    def _agent_gate_otel_collector_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for OpenTelemetry Collector YAML.

        Args:
            input_path: Local path to Collector configuration YAML.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_otel_collector_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_monitoring")
    def _agent_gate_monitoring_tool(
        input_path: str,
        ecosystem: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Prometheus or Alertmanager configuration.

        Args:
            input_path: Local path to prometheus.yml or alertmanager.yml.
            ecosystem: prometheus or alertmanager.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_monitoring_handler(input_path, ecosystem, framework=framework)

    @mcp.tool(name="agent_gate_envoy")
    def _agent_gate_envoy_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Envoy bootstrap or admin config_dump data.

        Args:
            input_path: Local path to Envoy YAML/JSON or config_dump JSON.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_envoy_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_proxy_config")
    def _agent_gate_proxy_config_tool(
        input_path: str,
        ecosystem: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for NGINX or HAProxy configuration without starting a proxy.

        Args:
            input_path: Local path to an NGINX or HAProxy configuration file.
            ecosystem: nginx or haproxy.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_proxy_config_handler(input_path, ecosystem, framework=framework)

    @mcp.tool(name="agent_gate_dockerfile")
    def _agent_gate_dockerfile_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for a Dockerfile/Containerfile without building an image.

        Args:
            input_path: Local path to a Dockerfile or Containerfile.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_dockerfile_handler(input_path, framework=framework)

    @mcp.tool(name="evolution_status")
    def _evolution_status_tool() -> dict[str, object]:
        """Return evolution engine statistics and recent run data."""
        return EvolutionEngine().get_stats()

    @mcp.tool(name="evolution_dashboard")
    def _evolution_dashboard_tool() -> dict[str, object]:
        """Generate the HTML evolution dashboard and return its file path."""
        path = EvolutionEngine().generate_html_dashboard()
        return {"dashboard_path": str(path)}

    @mcp.tool(name="evolution_patterns")
    def _evolution_patterns_tool() -> list[dict[str, object]]:
        """Return all detected patterns and their evolution status."""
        return EvolutionEngine().get_all_patterns()

    return mcp


def main() -> None:
    """Entry point for the stdio MCP server.

    Any raw plan JSON is never logged — errors reference file paths only.
    """
    create_server().run(transport="stdio")


def _load_fastmcp() -> Any:
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError as exc:
        if exc.name == "mcp":
            raise MissingMCPDependencyError(
                "MCP preview requires Python 3.10+ and the optional dependency. "
                'Install it with: pip install "readtheplan[mcp]"'
            ) from exc
        raise

    return FastMCP


if __name__ == "__main__":
    main()
