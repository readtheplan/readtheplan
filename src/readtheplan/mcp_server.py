from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from readtheplan.plan import PlanError, analyze_plan_file
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
    if not isinstance(plan_path, str) or not plan_path.strip():
        raise MCPToolInputError(
            code="INVALID_INPUT",
            message="plan_path must be a non-empty string",
        )

    try:
        summary = analyze_plan_file(plan_path, use_rules=True)
    except PlanError as exc:
        raise MCPToolInputError(code="PLAN_ERROR", message=str(exc)) from exc

    return summary_to_dict(summary)


def create_server() -> Any:
    FastMCP = _load_fastmcp()
    mcp = FastMCP("readtheplan")

    analyze_plan_handler = analyze_plan

    @mcp.tool(name="analyze_plan")
    def _analyze_plan_tool(plan_path: str) -> dict[str, object]:
        """Analyze a local Terraform plan JSON file and return the CLI JSON summary."""
        return analyze_plan_handler(plan_path)

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
