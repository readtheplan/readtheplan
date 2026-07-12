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
    """Return the gate decision for GitHub Actions, GitLab CI, or CircleCI YAML."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.pipelines import (
        PipelineInputError,
        analyze_pipeline,
        parse_pipeline_yaml,
    )

    if ecosystem not in {"github-actions", "gitlab-ci", "circleci"}:
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="ecosystem must be github-actions, gitlab-ci, or circleci",
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
    agent_gate_workload_handler = agent_gate_workload

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
        """Return a gate for GitHub Actions, GitLab CI, or CircleCI YAML.

        Args:
            input_path: Local path to the pipeline YAML file.
            ecosystem: github-actions, gitlab-ci, or circleci.
            framework: Optional compliance framework for control checks.
        """
        return agent_gate_pipeline_handler(
            input_path,
            ecosystem,
            framework=framework,
        )

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
