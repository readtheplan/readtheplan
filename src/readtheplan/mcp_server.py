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


def agent_gate_cdk(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for an AWS CDK Cloud Assembly or asset manifest."""
    from readtheplan.adapters.cdk import (
        CdkAdapter,
        CdkInputError,
        analyze_cdk,
        parse_cdk_manifest,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read CDK input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_cdk_manifest(source)
    except CdkInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT", message=f"Invalid AWS CDK manifest {input_path}: {exc}"
        ) from exc
    if not CdkAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input is not recognized as an AWS CDK manifest"
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_cdk(data, catalog=catalog)


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


def agent_gate_bicep(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the agent-gate decision for Azure Bicep source."""
    from readtheplan.adapters.bicep import (
        BicepAdapter,
        BicepInputError,
        analyze_bicep,
        parse_bicep_source,
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
            message=f"Cannot read Bicep source {input_path}: {exc}",
        ) from exc
    try:
        data = parse_bicep_source(source)
    except BicepInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Bicep source in {input_path}: {exc}",
        ) from exc
    if not BicepAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Azure Bicep source",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_bicep(data, catalog=catalog)


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


def agent_gate_pulumi_project(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Pulumi project, stack settings, or policy-pack YAML."""
    from readtheplan.adapters.pulumi_project import (
        PulumiProjectAdapter,
        PulumiProjectInputError,
        analyze_pulumi_project,
        parse_pulumi_project,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except FileNotFoundError as exc:
        raise MCPToolInputError(
            code="FILE_NOT_FOUND",
            message=f"File not found: {input_path}",
        ) from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR",
            message=f"Cannot read {input_path}: {exc}",
        ) from exc
    try:
        data = parse_pulumi_project(source, filename=Path(input_path).name)
    except PulumiProjectInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Pulumi project input in {input_path}: {exc}",
        ) from exc
    if not PulumiProjectAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Pulumi project configuration",
        )

    catalog = _load_catalog_for_tool(framework)
    return analyze_pulumi_project(data, catalog=catalog)


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
    """Return the gate decision for Docker Compose or a Nomad plan/jobspec."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.workloads import (
        WorkloadInputError,
        analyze_workload,
        parse_docker_compose,
        parse_nomad,
    )

    parsers = {
        "docker-compose": parse_docker_compose,
        "nomad": parse_nomad,
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
    """Return the gate decision for local Packer template or inspect output."""
    from readtheplan.adapters.packer import (
        PackerInspectAdapter,
        PackerInspectError,
        analyze_packer,
        parse_packer,
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
        data = parse_packer(source)
    except PackerInspectError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Packer input in {input_path}: {exc}",
        ) from exc
    if not PackerInspectAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Packer template or inspect output",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_packer(data, catalog=catalog)


def agent_gate_skaffold(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for local Skaffold configuration."""
    from readtheplan.adapters.skaffold import (
        SkaffoldAdapter,
        SkaffoldInputError,
        analyze_skaffold,
        parse_skaffold,
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
            code="INPUT_ERROR", message=f"Cannot read Skaffold input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_skaffold(source)
    except SkaffoldInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Skaffold input in {input_path}: {exc}",
        ) from exc
    if not SkaffoldAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Skaffold configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_skaffold(data, catalog=catalog)


def agent_gate_devspace(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for local DevSpace configuration."""
    from readtheplan.adapters.devspace import (
        DevSpaceAdapter,
        DevSpaceInputError,
        analyze_devspace,
        parse_devspace,
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
            code="INPUT_ERROR", message=f"Cannot read DevSpace input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_devspace(source)
    except DevSpaceInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid DevSpace input in {input_path}: {exc}",
        ) from exc
    if not DevSpaceAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as DevSpace configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_devspace(data, catalog=catalog)


def agent_gate_tilt(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for local Tiltfile source."""
    from readtheplan.adapters.tiltfile import (
        TiltfileAdapter,
        TiltfileInputError,
        analyze_tiltfile,
        parse_tiltfile,
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
            code="INPUT_ERROR", message=f"Cannot read Tiltfile input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_tiltfile(source)
    except TiltfileInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Tiltfile input in {input_path}: {exc}",
        ) from exc
    if not TiltfileAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Tiltfile configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_tiltfile(data, catalog=catalog)


def agent_gate_cue(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for local CUE source."""
    from readtheplan.adapters.cue import CueAdapter, CueInputError, analyze_cue, parse_cue

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read CUE input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_cue(source, Path(input_path).name)
    except CueInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid CUE input in {input_path}: {exc}",
        ) from exc
    if not CueAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as CUE configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_cue(data, catalog=catalog)


def agent_gate_jsonnet(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for local Jsonnet or Tanka input."""
    from readtheplan.adapters.jsonnet import (
        JsonnetAdapter,
        JsonnetInputError,
        analyze_jsonnet,
        parse_jsonnet,
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
            code="INPUT_ERROR", message=f"Cannot read Jsonnet/Tanka input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_jsonnet(source, Path(input_path).name)
    except JsonnetInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Jsonnet/Tanka input in {input_path}: {exc}",
        ) from exc
    if not JsonnetAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Jsonnet/Tanka configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_jsonnet(data, catalog=catalog)


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


def agent_gate_nix(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for a local Nix flake, lock, or NixOS module."""
    from readtheplan.adapters.nix import (
        NixInputError,
        NixProjectAdapter,
        analyze_nix_project,
        parse_nix_project,
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
            code="INPUT_ERROR", message=f"Cannot read Nix input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_nix_project(source)
    except NixInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Nix input in {input_path}: {exc}",
        ) from exc
    if not NixProjectAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Nix project data",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_nix_project(data, catalog=catalog)


def agent_gate_dsc(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for a local DSC document or PowerShell source."""
    from readtheplan.adapters.dsc import (
        DscAdapter,
        DscInputError,
        analyze_dsc,
        parse_dsc,
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
            code="INPUT_ERROR", message=f"Cannot read DSC input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_dsc(source)
    except DscInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid DSC input in {input_path}: {exc}",
        ) from exc
    if not DscAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as DSC configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_dsc(data, catalog=catalog)


def agent_gate_cfengine(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for local CFEngine policy or Augments data."""
    from readtheplan.adapters.cfengine import (
        CFEngineAdapter,
        CFEngineInputError,
        analyze_cfengine,
        parse_cfengine,
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
            code="INPUT_ERROR", message=f"Cannot read CFEngine input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_cfengine(source)
    except CFEngineInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid CFEngine input in {input_path}: {exc}",
        ) from exc
    if not CFEngineAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as CFEngine configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_cfengine(data, catalog=catalog)


def agent_gate_opa(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for local Rego, bundle metadata, or Conftest config."""
    from readtheplan.adapters.opa import OPAAdapter, OPAInputError, analyze_opa, parse_opa

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read OPA/Rego input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_opa(source, Path(input_path).name)
    except OPAInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid OPA/Rego input in {input_path}: {exc}",
        ) from exc
    if not OPAAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as OPA/Rego configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_opa(data, catalog=catalog)


def agent_gate_sentinel(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate decision for local Sentinel policy or configuration."""
    from readtheplan.adapters.sentinel import (
        SentinelAdapter,
        SentinelInputError,
        analyze_sentinel,
        parse_sentinel,
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
            code="INPUT_ERROR", message=f"Cannot read Sentinel input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_sentinel(source, Path(input_path).name)
    except SentinelInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Sentinel input in {input_path}: {exc}",
        ) from exc
    if not SentinelAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Sentinel policy or configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_sentinel(data, catalog=catalog)


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


def agent_gate_traefik(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Traefik YAML, JSON, or TOML."""
    from readtheplan.adapters.traefik import (
        TraefikAdapter,
        TraefikInputError,
        analyze_traefik,
        parse_traefik_config,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Traefik input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_traefik_config(source)
    except TraefikInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Traefik configuration in {input_path}: {exc}",
        ) from exc
    if not TraefikAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input is not recognized as Traefik configuration"
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_traefik(data, catalog=catalog)


def agent_gate_grafana(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Grafana INI or provisioning YAML/JSON."""
    from readtheplan.adapters.grafana import (
        GrafanaAdapter,
        GrafanaInputError,
        analyze_grafana,
        parse_grafana_config,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Grafana input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_grafana_config(source)
    except GrafanaInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Grafana configuration in {input_path}: {exc}",
        ) from exc
    if not GrafanaAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input is not recognized as Grafana configuration"
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_grafana(data, catalog=catalog)


def _agent_gate_hashicorp(
    input_path: str,
    ecosystem: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Vault or Consul HCL/JSON configuration."""
    from readtheplan.adapters.hashicorp import (
        ConsulAdapter,
        HashiCorpInputError,
        VaultAdapter,
        analyze_hashicorp,
        parse_hashicorp_config,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR",
            message=f"Cannot read {ecosystem} input {input_path}: {exc}",
        ) from exc
    try:
        data = parse_hashicorp_config(source, ecosystem)
    except HashiCorpInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid {ecosystem} configuration in {input_path}: {exc}",
        ) from exc
    adapter = VaultAdapter() if ecosystem == "vault" else ConsulAdapter()
    if not adapter.can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Input is not recognized as {ecosystem} configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_hashicorp(data, catalog=catalog)


def agent_gate_vault(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Vault server HCL/JSON configuration."""
    return _agent_gate_hashicorp(input_path, "vault", framework)


def agent_gate_consul(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Consul agent HCL/JSON configuration."""
    return _agent_gate_hashicorp(input_path, "consul", framework)


def agent_gate_loki(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Grafana Loki YAML configuration."""
    from readtheplan.adapters.loki import (
        LokiAdapter,
        LokiInputError,
        analyze_loki,
        parse_loki_config,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Loki input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_loki_config(source)
    except LokiInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT", message=f"Invalid Loki configuration in {input_path}: {exc}"
        ) from exc
    if not LokiAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input is not recognized as Loki configuration"
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_loki(data, catalog=catalog)


def agent_gate_caddy(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Caddyfile or native Caddy JSON."""
    from readtheplan.adapters.caddy import (
        CaddyAdapter,
        CaddyInputError,
        analyze_caddy,
        parse_caddy_config,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Caddy input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_caddy_config(source)
    except CaddyInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT", message=f"Invalid Caddy configuration in {input_path}: {exc}"
        ) from exc
    if not CaddyAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input is not recognized as Caddy configuration"
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_caddy(data, catalog=catalog)


def _agent_gate_terraform_source(
    input_path: str,
    ecosystem: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Terraform config or Terragrunt HCL/JSON."""
    from readtheplan.adapters.terraform_config import (
        TerraformConfigAdapter,
        TerraformConfigInputError,
        TerragruntAdapter,
        analyze_terraform_config,
        parse_terraform_config,
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
        data = parse_terraform_config(source, ecosystem)
    except TerraformConfigInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid {ecosystem} configuration in {input_path}: {exc}",
        ) from exc
    adapter = TerraformConfigAdapter() if ecosystem == "terraform-config" else TerragruntAdapter()
    if not adapter.can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Input is not recognized as {ecosystem} configuration",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_terraform_config(data, catalog=catalog)


def agent_gate_terraform_config(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Terraform configuration HCL/JSON."""
    return _agent_gate_terraform_source(input_path, "terraform-config", framework)


def agent_gate_terraform_lock(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for a Terraform/OpenTofu dependency lock."""
    from readtheplan.adapters.terraform_lock import (
        TerraformLockAdapter,
        TerraformLockInputError,
        analyze_terraform_lock,
        parse_terraform_lock,
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
            message=f"Cannot read Terraform/OpenTofu lock input {input_path}: {exc}",
        ) from exc
    try:
        data = parse_terraform_lock(source)
    except TerraformLockInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid dependency lock in {input_path}: {exc}",
        ) from exc
    if not TerraformLockAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as a Terraform/OpenTofu dependency lock",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze_terraform_lock(data, catalog=catalog)


def agent_gate_terraform_state(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for saved Terraform/OpenTofu state JSON."""
    from readtheplan.adapters.terraform_state import (
        TerraformStateAdapter,
        TerraformStateInputError,
        analyze_terraform_state,
        parse_terraform_state,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except FileNotFoundError as exc:
        raise MCPToolInputError(
            code="FILE_NOT_FOUND",
            message=f"File not found: {input_path}",
        ) from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR",
            message=f"Cannot read {input_path}: {exc}",
        ) from exc
    try:
        data = parse_terraform_state(source)
    except TerraformStateInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Invalid Terraform/OpenTofu state in {input_path}: {exc}",
        ) from exc
    if not TerraformStateAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input is not recognized as Terraform/OpenTofu state",
        )

    catalog = _load_catalog_for_tool(framework)
    return analyze_terraform_state(data, catalog=catalog)


def agent_gate_terragrunt(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Terragrunt HCL/JSON configuration."""
    return _agent_gate_terraform_source(input_path, "terragrunt", framework)


def agent_gate_helm(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Helm chart metadata, values, or template source."""
    from readtheplan.adapters.helm import (
        HelmAdapter,
        HelmInputError,
        analyze_helm,
        parse_helm_source,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Helm input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_helm_source(source)
    except HelmInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT", message=f"Invalid Helm source in {input_path}: {exc}"
        ) from exc
    if not HelmAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input is not recognized as Helm source"
        )
    return analyze_helm(data, catalog=_load_catalog_for_tool(framework))


def agent_gate_kustomize(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Kustomize source configuration."""
    from readtheplan.adapters.kustomize import (
        KustomizeAdapter,
        KustomizeInputError,
        analyze_kustomize,
        parse_kustomization,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Kustomize input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_kustomization(source)
    except KustomizeInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT", message=f"Invalid Kustomize source in {input_path}: {exc}"
        ) from exc
    if not KustomizeAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input is not recognized as Kustomize source"
        )
    return analyze_kustomize(data, catalog=_load_catalog_for_tool(framework))


def agent_gate_crossplane(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Crossplane package and resource source."""
    from readtheplan.adapters.crossplane import (
        CrossplaneAdapter,
        CrossplaneInputError,
        analyze_crossplane,
        parse_crossplane_input,
    )

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT", message="input_path must be a non-empty string"
        )
    try:
        source = _read_confined_bytes(input_path).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read Crossplane input {input_path}: {exc}"
        ) from exc
    try:
        data = parse_crossplane_input(source)
    except CrossplaneInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT", message=f"Invalid Crossplane source in {input_path}: {exc}"
        ) from exc
    if not CrossplaneAdapter().can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input is not recognized as Crossplane source"
        )
    return analyze_crossplane(data, catalog=_load_catalog_for_tool(framework))


def _agent_gate_serverless_source(
    input_path: str,
    ecosystem: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Serverless Framework or AWS SAM source."""
    from readtheplan.adapters.serverless import (
        SamTemplateAdapter,
        ServerlessFrameworkAdapter,
        ServerlessInputError,
        analyze_sam,
        analyze_serverless,
        parse_sam_template,
        parse_serverless_source,
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
    if ecosystem == "serverless":
        parser, adapter, analyze = (
            parse_serverless_source,
            ServerlessFrameworkAdapter(),
            analyze_serverless,
        )
    else:
        parser, adapter, analyze = parse_sam_template, SamTemplateAdapter(), analyze_sam
    try:
        data = parser(source)
    except ServerlessInputError as exc:
        raise MCPToolInputError(
            code="INVALID_INPUT", message=f"Invalid {ecosystem} source in {input_path}: {exc}"
        ) from exc
    if not adapter.can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT", message=f"Input is not recognized as {ecosystem} source"
        )
    return analyze(data, catalog=_load_catalog_for_tool(framework))


def agent_gate_serverless(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for Serverless Framework service source."""
    return _agent_gate_serverless_source(input_path, "serverless", framework)


def agent_gate_sam(
    input_path: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return the gate for AWS SAM template source."""
    return _agent_gate_serverless_source(input_path, "sam", framework)


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


def agent_gate_configuration_management(
    input_path: str,
    ecosystem: str,
    framework: str | None = None,
) -> dict[str, object]:
    """Return a gate for major configuration-management source formats."""
    from readtheplan.adapters.ansible import AnsibleAdapter, analyze_ansible
    from readtheplan.adapters.ansible_project import (
        AnsibleProjectAdapter,
        AnsibleProjectInputError,
        analyze_ansible_project,
        parse_ansible_project,
    )
    from readtheplan.adapters.cfengine import (
        CFEngineAdapter,
        CFEngineInputError,
        analyze_cfengine,
        parse_cfengine,
    )
    from readtheplan.adapters.chef import ChefAdapter, analyze_chef
    from readtheplan.adapters.chef_project import (
        ChefProjectAdapter,
        ChefProjectInputError,
        analyze_chef_project,
        parse_chef_project,
    )
    from readtheplan.adapters.dsc import (
        DscAdapter,
        DscInputError,
        analyze_dsc,
        parse_dsc,
    )
    from readtheplan.adapters.jenkins import JenkinsAdapter, analyze_jenkins
    from readtheplan.adapters.jenkins_jcasc import (
        JenkinsJCasCAdapter,
        JenkinsJCasCInputError,
        analyze_jenkins_jcasc,
        parse_jenkins_jcasc,
    )
    from readtheplan.adapters.puppet import PuppetAdapter, analyze_puppet
    from readtheplan.adapters.puppet_project import (
        PuppetProjectAdapter,
        PuppetProjectInputError,
        analyze_puppet_project,
        parse_puppet_project,
    )
    from readtheplan.adapters.salt_project import (
        SaltProjectAdapter,
        SaltProjectInputError,
        analyze_salt_project,
        parse_salt_project,
    )

    supported = {
        "ansible",
        "ansible-project",
        "jenkins",
        "jenkins-jcasc",
        "chef",
        "chef-project",
        "puppet",
        "puppet-project",
        "salt-project",
        "dsc",
        "cfengine",
    }
    if ecosystem not in supported:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=("ecosystem must be one of: " + ", ".join(sorted(supported))),
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
            message=f"Cannot read {ecosystem} input {input_path}: {exc}",
        ) from exc

    if ecosystem == "ansible":
        try:
            import yaml

            documents = list(yaml.safe_load_all(source))
        except yaml.YAMLError as exc:
            raise MCPToolInputError(
                code="INPUT_ERROR",
                message=f"Cannot parse Ansible input {input_path}: {exc}",
            ) from exc
        plays: list[object] = []
        for document in documents:
            if isinstance(document, list):
                plays.extend(document)
            elif isinstance(document, dict):
                plays.append(document)
        data = {"plays": plays}
        adapter = AnsibleAdapter()
        analyze = analyze_ansible
    elif ecosystem == "ansible-project":
        try:
            data = parse_ansible_project(source)
        except AnsibleProjectInputError as exc:
            raise MCPToolInputError(
                code="INVALID_INPUT",
                message=f"Invalid Ansible project input {input_path}: {exc}",
            ) from exc
        adapter = AnsibleProjectAdapter()
        analyze = analyze_ansible_project
    elif ecosystem == "chef-project":
        try:
            data = parse_chef_project(source)
        except ChefProjectInputError as exc:
            raise MCPToolInputError(
                code="INVALID_INPUT",
                message=f"Invalid Chef project input {input_path}: {exc}",
            ) from exc
        adapter = ChefProjectAdapter()
        analyze = analyze_chef_project
    elif ecosystem == "puppet-project":
        try:
            data = parse_puppet_project(source)
        except PuppetProjectInputError as exc:
            raise MCPToolInputError(
                code="INVALID_INPUT",
                message=f"Invalid Puppet project input {input_path}: {exc}",
            ) from exc
        adapter = PuppetProjectAdapter()
        analyze = analyze_puppet_project
    elif ecosystem == "salt-project":
        try:
            data = parse_salt_project(source)
        except SaltProjectInputError as exc:
            raise MCPToolInputError(
                code="INVALID_INPUT",
                message=f"Invalid Salt project input {input_path}: {exc}",
            ) from exc
        adapter = SaltProjectAdapter()
        analyze = analyze_salt_project
    elif ecosystem == "dsc":
        try:
            data = parse_dsc(source)
        except DscInputError as exc:
            raise MCPToolInputError(
                code="INVALID_INPUT",
                message=f"Invalid DSC input {input_path}: {exc}",
            ) from exc
        adapter = DscAdapter()
        analyze = analyze_dsc
    elif ecosystem == "cfengine":
        try:
            data = parse_cfengine(source)
        except CFEngineInputError as exc:
            raise MCPToolInputError(
                code="INVALID_INPUT",
                message=f"Invalid CFEngine input {input_path}: {exc}",
            ) from exc
        adapter = CFEngineAdapter()
        analyze = analyze_cfengine
    elif ecosystem == "jenkins-jcasc":
        try:
            data = parse_jenkins_jcasc(source)
        except JenkinsJCasCInputError as exc:
            raise MCPToolInputError(
                code="INVALID_INPUT",
                message=f"Invalid Jenkins JCasC input {input_path}: {exc}",
            ) from exc
        adapter = JenkinsJCasCAdapter()
        analyze = analyze_jenkins_jcasc
    else:
        key, adapter, analyze = {
            "jenkins": ("jenkinsfile", JenkinsAdapter(), analyze_jenkins),
            "chef": ("chef_recipe", ChefAdapter(), analyze_chef),
            "puppet": ("puppet_manifest", PuppetAdapter(), analyze_puppet),
        }[ecosystem]
        data = {key: source}
    if not adapter.can_handle(data):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message=f"Input is not recognized as {ecosystem} source",
        )
    catalog = _load_catalog_for_tool(framework)
    return analyze(data, catalog=catalog)


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
    agent_gate_cdk_handler = agent_gate_cdk
    agent_gate_azure_handler = agent_gate_azure
    agent_gate_bicep_handler = agent_gate_bicep
    agent_gate_k8s_handler = agent_gate_kubernetes
    agent_gate_pulumi_handler = agent_gate_pulumi
    agent_gate_pulumi_project_handler = agent_gate_pulumi_project
    agent_gate_pipeline_handler = agent_gate_pipeline
    agent_gate_atlantis_handler = agent_gate_atlantis
    agent_gate_workload_handler = agent_gate_workload
    agent_gate_packer_handler = agent_gate_packer
    agent_gate_skaffold_handler = agent_gate_skaffold
    agent_gate_devspace_handler = agent_gate_devspace
    agent_gate_tilt_handler = agent_gate_tilt
    agent_gate_cue_handler = agent_gate_cue
    agent_gate_jsonnet_handler = agent_gate_jsonnet
    agent_gate_salt_handler = agent_gate_salt
    agent_gate_nix_handler = agent_gate_nix
    agent_gate_dsc_handler = agent_gate_dsc
    agent_gate_cfengine_handler = agent_gate_cfengine
    agent_gate_opa_handler = agent_gate_opa
    agent_gate_sentinel_handler = agent_gate_sentinel
    agent_gate_vagrant_handler = agent_gate_vagrant
    agent_gate_cloud_init_handler = agent_gate_cloud_init
    agent_gate_systemd_handler = agent_gate_systemd
    agent_gate_envoy_handler = agent_gate_envoy
    agent_gate_monitoring_handler = agent_gate_monitoring
    agent_gate_otel_collector_handler = agent_gate_otel_collector
    agent_gate_traefik_handler = agent_gate_traefik
    agent_gate_grafana_handler = agent_gate_grafana
    agent_gate_vault_handler = agent_gate_vault
    agent_gate_consul_handler = agent_gate_consul
    agent_gate_loki_handler = agent_gate_loki
    agent_gate_caddy_handler = agent_gate_caddy
    agent_gate_terraform_config_handler = agent_gate_terraform_config
    agent_gate_terraform_lock_handler = agent_gate_terraform_lock
    agent_gate_terraform_state_handler = agent_gate_terraform_state
    agent_gate_terragrunt_handler = agent_gate_terragrunt
    agent_gate_helm_handler = agent_gate_helm
    agent_gate_kustomize_handler = agent_gate_kustomize
    agent_gate_crossplane_handler = agent_gate_crossplane
    agent_gate_serverless_handler = agent_gate_serverless
    agent_gate_sam_handler = agent_gate_sam
    agent_gate_proxy_config_handler = agent_gate_proxy_config
    agent_gate_dockerfile_handler = agent_gate_dockerfile
    agent_gate_configuration_management_handler = agent_gate_configuration_management

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

    @mcp.tool(name="agent_gate_cdk")
    def _agent_gate_cdk_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return the gate for an AWS CDK Cloud Assembly or asset manifest."""
        return agent_gate_cdk_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_azure")
    def _agent_gate_azure_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return the gate decision for Azure Bicep/ARM What-If JSON."""
        return agent_gate_azure_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_bicep")
    def _agent_gate_bicep_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return the gate decision for Azure Bicep source before compilation."""
        return agent_gate_bicep_handler(input_path, framework=framework)

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

    @mcp.tool(name="agent_gate_pulumi_project")
    def _agent_gate_pulumi_project_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return the gate for Pulumi project, stack, or policy-pack YAML.

        Args:
            input_path: Path to Pulumi.yaml, Pulumi.<stack>.yaml, or PulumiPolicy.yaml.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_pulumi_project_handler(input_path, framework=framework)

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
        """Return a gate for Docker Compose or a Nomad plan/jobspec.

        Args:
            input_path: Local path to Compose YAML, Nomad plan JSON, or HCL/JSON jobspec.
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
        """Return a gate for Packer template source or saved inspect output.

        Args:
            input_path: Local path to a Packer template or saved `packer inspect` output.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_packer_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_skaffold")
    def _agent_gate_skaffold_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Skaffold pipeline configuration.

        Args:
            input_path: Local path to skaffold.yaml or another Skaffold Config.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_skaffold_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_devspace")
    def _agent_gate_devspace_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for DevSpace project configuration.

        Args:
            input_path: Local path to devspace.yaml.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_devspace_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_tilt")
    def _agent_gate_tilt_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Tiltfile source.

        Args:
            input_path: Local path to a Tiltfile.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_tilt_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_cue")
    def _agent_gate_cue_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for CUE source, module metadata, or workflow tasks.

        Args:
            input_path: Local path to a .cue source file.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_cue_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_jsonnet")
    def _agent_gate_jsonnet_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Jsonnet source, Tanka environments, or dependency metadata.

        Args:
            input_path: Local path to Jsonnet/Tanka source or metadata.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_jsonnet_handler(input_path, framework=framework)

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

    @mcp.tool(name="agent_gate_nix")
    def _agent_gate_nix_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for flake.nix, flake.lock, or a NixOS module.

        Args:
            input_path: Local path to Nix source or a flake lock file.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_nix_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_dsc")
    def _agent_gate_dsc_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for DSC v3 documents or PowerShell DSC source.

        Args:
            input_path: Local path to a DSC JSON/YAML document or PowerShell source.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_dsc_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_cfengine")
    def _agent_gate_cfengine_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for CFEngine policy or Augments JSON without evaluation.

        Args:
            input_path: Local path to a CFEngine .cf policy or Augments JSON file.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_cfengine_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_opa")
    def _agent_gate_opa_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Rego, bundle metadata, or Conftest config without evaluation.

        Args:
            input_path: Local path to .rego, .manifest, .signatures.json, or conftest.toml.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_opa_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_sentinel")
    def _agent_gate_sentinel_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Sentinel policy or CLI configuration without evaluation.

        Args:
            input_path: Local path to .sentinel, sentinel.hcl, or sentinel.json.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_sentinel_handler(input_path, framework=framework)

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

    @mcp.tool(name="agent_gate_traefik")
    def _agent_gate_traefik_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Traefik YAML, JSON, or TOML configuration."""
        return agent_gate_traefik_handler(input_path, framework=framework)

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

    @mcp.tool(name="agent_gate_grafana")
    def _agent_gate_grafana_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Grafana INI or provisioning YAML/JSON configuration."""
        return agent_gate_grafana_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_vault")
    def _agent_gate_vault_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Vault server HCL/JSON configuration."""
        return agent_gate_vault_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_consul")
    def _agent_gate_consul_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Consul agent HCL/JSON configuration."""
        return agent_gate_consul_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_loki")
    def _agent_gate_loki_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Grafana Loki YAML configuration."""
        return agent_gate_loki_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_caddy")
    def _agent_gate_caddy_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Caddyfile or native Caddy JSON."""
        return agent_gate_caddy_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_terraform_config")
    def _agent_gate_terraform_config_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Terraform configuration HCL/JSON."""
        return agent_gate_terraform_config_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_terraform_lock")
    def _agent_gate_terraform_lock_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for a Terraform/OpenTofu dependency lock file.

        Args:
            input_path: Local path to .terraform.lock.hcl.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_terraform_lock_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_terraform_state")
    def _agent_gate_terraform_state_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return the gate for saved Terraform/OpenTofu state JSON.

        Args:
            input_path: Path to show -json state output or a raw v4 state snapshot.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_terraform_state_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_terragrunt")
    def _agent_gate_terragrunt_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Terragrunt HCL/JSON configuration."""
        return agent_gate_terragrunt_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_helm")
    def _agent_gate_helm_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Helm Chart.yaml, values YAML, or template source."""
        return agent_gate_helm_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_kustomize")
    def _agent_gate_kustomize_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Kustomize source configuration."""
        return agent_gate_kustomize_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_crossplane")
    def _agent_gate_crossplane_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Crossplane package and resource source."""
        return agent_gate_crossplane_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_serverless")
    def _agent_gate_serverless_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for Serverless Framework service source."""
        return agent_gate_serverless_handler(input_path, framework=framework)

    @mcp.tool(name="agent_gate_sam")
    def _agent_gate_sam_tool(
        input_path: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for AWS SAM template source."""
        return agent_gate_sam_handler(input_path, framework=framework)

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

    @mcp.tool(name="agent_gate_configuration_management")
    def _agent_gate_configuration_management_tool(
        input_path: str,
        ecosystem: str,
        framework: str | None = None,
    ) -> dict[str, object]:
        """Return a gate for supported configuration-management source.

        Args:
            input_path: Local path to a playbook, Jenkinsfile, recipe, or manifest.
            ecosystem: ansible, ansible-project, jenkins, jenkins-jcasc, chef,
                chef-project, puppet, puppet-project, salt-project, dsc, or cfengine.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_configuration_management_handler(
            input_path,
            ecosystem,
            framework=framework,
        )

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
