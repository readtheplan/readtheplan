from __future__ import annotations

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
                    f"plan_path {plan_path!r} resolves outside the allowed "
                    f"working root {root}"
                ),
            ) from None
    return resolved


def _resolve_path(plan_path: str) -> str:
    """Validate *plan_path* against the working root and return the resolved
    absolute path as a string."""
    return str(_validate_path(plan_path))


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


def agent_gate_cloudformation(input_path: str) -> dict[str, object]:
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
        data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MCPToolInputError(
            code="INPUT_ERROR", message=f"Cannot read {input_path}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise MCPToolInputError(
            code="INVALID_INPUT", message="Input must be a JSON object"
        )

    return analyze_cloudformation(data)


def agent_gate_kubernetes(input_path: str) -> dict[str, object]:
    """Return the agent-gate decision for a Kubernetes manifest diff.

    Accepts a JSON file with either:
      - {"old_manifests": [...], "new_manifests": [...]} — diff format
      - {"resources": [...]} — single manifest format
    """
    import json

    from readtheplan.adapters.kubernetes import analyze_kubernetes

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )

    try:
        data = json.loads(Path(input_path).read_bytes())
    except FileNotFoundError:
        raise MCPToolInputError(
            code="FILE_NOT_FOUND",
            message=f"File not found: {input_path}",
        )
    except json.JSONDecodeError as exc:
        raise MCPToolInputError(
            code="INVALID_JSON",
            message=f"Invalid JSON in {input_path}: {exc}",
        )

    if not isinstance(data, dict):
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="Input must be a JSON object",
        )

    return analyze_kubernetes(data)


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
    try:
        summary = analyze_plan_file(plan_path, use_rules=True)
    except PlanError as exc:
        raise MCPToolInputError(code="PLAN_ERROR", message=str(exc)) from exc

    return summary


def create_server() -> Any:
    FastMCP = _load_fastmcp()
    mcp = FastMCP("readtheplan")

    analyze_plan_handler = analyze_plan
    agent_gate_handler = agent_gate
    agent_gate_cfn_handler = agent_gate_cloudformation
    agent_gate_k8s_handler = agent_gate_kubernetes

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
    def _agent_gate_cfn_tool(input_path: str) -> dict[str, object]:
        """Return the agent-gate decision for a CloudFormation Change Set / template diff."""
        return agent_gate_cfn_handler(input_path)

    @mcp.tool(name="agent_gate_kubernetes")
    def _agent_gate_k8s_tool(input_path: str) -> dict[str, object]:
        """Return the agent-gate decision for a Kubernetes manifest diff.

        Args:
            input_path: Path to a JSON file. Supports two formats:
                - {"old_manifests": [...], "new_manifests": [...]} — diff format
                - {"resources": [...]} — single manifest format
        """
        return agent_gate_k8s_handler(input_path)

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
