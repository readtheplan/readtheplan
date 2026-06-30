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
from readtheplan.evolution import EvolutionEngine
from readtheplan.plan import PlanError, PlanSummary, analyze_plan_file
from readtheplan.summary import summary_to_dict


class MissingMCPDependencyError(RuntimeError):
    """Raised when the ``mcp`` extra is not installed."""


def _ensure_deps() -> None:
    try:
        import mcp.types as _types  # noqa: F401
    except ImportError:
        raise MissingMCPDependencyError(
            "The MCP server requires the ``mcp`` extra. "
            "Install it with: ``pip install readtheplan[mcp]```"
        )


def _check_plan(path: str) -> None:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Plan file not found: {path}")


@dataclass
class GateRequest:
    plan_file: str
    framework: str = "soc2"
    catalog_path: str | None = None
    max_resources: int = 100


def create_server() -> Any:
    _ensure_deps()
    import mcp.server as server
    import mcp.server.stdio
    import mcp.types as types
    from mcp.server.models import InitializationOptions

    app = server.Server("readtheplan")

    @app.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="agent_gate",
                description=(
                    "Evaluate an IaC plan and return the agent-gate decision "
                    "(proceed / warn / block) with compliance score, required "
                    "checks, evidence checklist, and auditor summary. "
                    "Supports Terraform, CloudFormation, and Kubernetes."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["plan_file"],
                    "properties": {
                        "plan_file": {
                            "type": "string",
                            "description": "Path to the plan JSON file",
                        },
                        "framework": {
                            "type": "string",
                            "description": "Compliance framework (soc2, hipaa, pci_dss, cis)",
                            "default": "soc2",
                        },
                        "catalog_path": {
                            "type": "string",
                            "description": "Path to a custom control catalog JSON",
                        },
                        "max_resources": {
                            "type": "integer",
                            "description": "Max resources to evaluate (default 100)",
                            "default": 100,
                        },
                    },
                },
            ),
            types.Tool(
                name="agent_gate_summary",
                description=(
                    "Return a plain-text summary of the agent-gate decision "
                    "suitable for PR comments."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["plan_file"],
                    "properties": {
                        "plan_file": {
                            "type": "string",
                            "description": "Path to the plan JSON file",
                        },
                        "framework": {
                            "type": "string",
                            "description": "Compliance framework",
                            "default": "soc2",
                        },
                    },
                },
            ),
            types.Tool(
                name="agent_gate_cfn",
                description=(
                    "Return the agent-gate decision for a CloudFormation "
                    "Change Set / template diff."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["input_path"],
                    "properties": {
                        "input_path": {
                            "type": "string",
                            "description": "Path to the CFN input JSON",
                        },
                    },
                },
            ),
            types.Tool(
                name="evolution_status",
                description=(
                    "Return evolution engine statistics and recent run data."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="evolution_dashboard",
                description=(
                    "Generate the HTML evolution dashboard "
                    "and return its file path."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="evolution_patterns",
                description=(
                    "Return all detected patterns and their evolution status."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="agent_gate_kubernetes",
                description=(
                    "Return the agent-gate decision for a "
                    "Kubernetes manifest diff."
                ),
                inputSchema={
                    "type": "object",
                    "required": ["input_path"],
                    "properties": {
                        "input_path": {
                            "type": "string",
                            "description": "Path to the K8s input JSON",
                        },
                    },
                },
            ),
        ]

    @app.call_tool()
    async def call_tool(
        name: str, arguments: dict
    ) -> list[types.TextContent]:
        if name == "agent_gate":
            return [types.TextContent(
                type="text",
                text=str(_agent_gate_handler(arguments)),
            )]
        elif name == "agent_gate_summary":
            return [types.TextContent(
                type="text",
                text=str(summary_to_dict(
                    _agent_gate_handler(arguments, summary_only=True)
                )),
            )]
        elif name == "agent_gate_cfn":
            return [types.TextContent(
                type="text",
                text=str(agent_gate_cfn_handler(arguments.get("input_path", ""))),
            )]
        elif name == "evolution_status":
            return [types.TextContent(
                type="text",
                text=str(EvolutionEngine().get_stats()),
            )]
        elif name == "evolution_dashboard":
            path = EvolutionEngine().generate_html_dashboard()
            return [types.TextContent(
                type="text",
                text=str({"dashboard_path": str(path)}),
            )]
        elif name == "evolution_patterns":
            return [types.TextContent(
                type="text",
                text=str(EvolutionEngine().get_all_patterns()),
            )]
        elif name == "agent_gate_kubernetes":
            return [types.TextContent(
                type="text",
                text=str(agent_gate_k8s_handler(arguments.get("input_path", ""))),
            )]
        raise ValueError(f"Unknown tool: {name}")

    return app


def _agent_gate_handler(
    arguments: dict,
    summary_only: bool = False,
) -> dict:
    """Handle an agent_gate tool invocation."""
    from readtheplan.plan import analyze_plan_file as analyze

    plan_file = arguments.get("plan_file", "")
    framework = arguments.get("framework", "soc2")
    catalog_path = arguments.get("catalog_path")
    max_resources = arguments.get("max_resources", 100)

    _check_plan(plan_file)

    catalog: ControlCatalog | None = None
    if catalog_path:
        catalog = load_catalog(catalog_path)
    else:
        try:
            catalog = load_catalog(framework)
        except (CatalogSchemaError, FrameworkNotFoundError):
            catalog = None

    summary = analyze(plan_file, max_resources=max_resources)
    return agent_gate_to_dict(summary, catalog)


def agent_gate_cfn_handler(input_path: str) -> dict:
    """Handle CloudFormation gate request."""
    from readtheplan.cfn import cfn_to_gate

    return cfn_to_gate(input_path)


def agent_gate_k8s_handler(input_path: str) -> dict:
    """Handle Kubernetes gate request."""
    from readtheplan.k8s import k8s_to_gate

    return k8s_to_gate(input_path)


def main() -> None:
    _ensure_deps()
    import mcp.server.stdio

    app = create_server()
    with mcp.server.stdio.stdio_server() as (read, write):
        import asyncio
        asyncio.run(app.run(read, write, InitializationOptions(
            server_name="readtheplan",
            server_version="0.3.0",
        )))


if __name__ == "__main__":
    main()
