from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from readtheplan.agent_gate import agent_gate_to_dict
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


def analyze_plan(plan_path: str) -> dict[str, object]:
    """Analyze a local Terraform plan JSON file for the MCP tool."""
    summary = _summary_for_tool(plan_path)
    return summary_to_dict(summary)


def agent_gate(plan_path: str) -> dict[str, object]:
    """Return the local coding-agent gate decision for a Terraform plan JSON file."""
    summary = _summary_for_tool(plan_path)
    return agent_gate_to_dict(summary)


def agent_gate_cloudformation(input_path: str) -> dict[str, object]:
    """Return the agent-gate decision for a CloudFormation Change Set / template diff."""
    from readtheplan.adapters.cloudformation import analyze_cloudformation

    if not isinstance(input_path, str) or not input_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="input_path must be a non-empty string",
        )

    from pathlib import Path

    try:
        import json

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


def _summary_for_tool(plan_path: str) -> PlanSummary:
    if not isinstance(plan_path, str) or not plan_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="plan_path must be a non-empty string",
        )

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

    @mcp.tool(name="analyze_plan")
    def _analyze_plan_tool(plan_path: str) -> dict[str, object]:
        """Analyze a local Terraform plan JSON file and return the CLI JSON summary."""
        return analyze_plan_handler(plan_path)

    @mcp.tool(name="agent_gate")
    def _agent_gate_tool(plan_path: str) -> dict[str, object]:
        """Return proceed, warn, or block instructions for a local Terraform plan."""
        return agent_gate_handler(plan_path)

    @mcp.tool(name="agent_gate_cloudformation")
    def _agent_gate_cfn_tool(input_path: str) -> dict[str, object]:
        """Return the agent-gate decision for a CloudFormation Change Set / template diff."""
        return agent_gate_cfn_handler(input_path)

    return mcp


def main() -> None:
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
