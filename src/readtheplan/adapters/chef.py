from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_RESOURCE = re.compile(
    r"^\s*(?P<type>apt_package|bash|cookbook_file|directory|execute|file|group|log|"
    r"package|remote_file|ruby_block|service|template|user)\s+['\"](?P<name>[^'\"]+)['\"]",
    re.MULTILINE,
)
_ACTION_BLOCK = re.compile(r"\baction\s+(?P<actions>\[[^\]]+\]|:[a-z_]+)")
_ACTION_NAME = re.compile(r":(?P<action>[a-z_]+)")
_DANGEROUS_TYPES = {"bash", "execute", "ruby_block"}
_SAFE_TYPES = {"log"}
_DESTRUCTIVE_ACTIONS = {"delete", "disable", "nothing", "purge", "remove", "restart", "stop"}


class ChefAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "chef"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        source = input_data.get("chef_recipe")
        return isinstance(source, str) and bool(_RESOURCE.search(source))

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        lines = str(input_data.get("chef_recipe", "")).splitlines()
        changes: list[dict[str, Any]] = []
        for index, line in enumerate(lines):
            match = _RESOURCE.match(line)
            if not match:
                continue
            block_lines = [line]
            for candidate in lines[index + 1 :]:
                block_lines.append(candidate)
                if candidate.strip() == "end":
                    break
            block = "\n".join(block_lines)
            action_block = _ACTION_BLOCK.search(block)
            actions = (
                _ACTION_NAME.findall(action_block.group("actions"))
                if action_block
                else ["converge"]
            )
            changes.append(
                {
                    "Type": match.group("type"),
                    "Name": match.group("name"),
                    "Actions": actions,
                    "Address": f"recipe:{index + 1}",
                }
            )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        resource = str(raw.get("Type", "unknown"))
        actions = tuple(str(action) for action in raw.get("Actions", ["converge"]))
        risk = "review"
        explanation = (
            f"Chef resource '{resource}' converges system configuration; review desired state."
        )
        if resource in _SAFE_TYPES:
            risk = "safe"
            explanation = "Chef log resources report information without changing infrastructure."
        elif resource in _DANGEROUS_TYPES:
            risk = "dangerous"
            explanation = (
                f"Chef resource '{resource}' can execute arbitrary code during convergence."
            )
        elif destructive := next(
            (action for action in actions if action in _DESTRUCTIVE_ACTIONS), None
        ):
            risk = "dangerous"
            explanation = (
                f"Chef resource '{resource}' requests availability-changing "
                f"action '{destructive}'."
            )
        return ResourceChange(
            address=str(raw.get("Address", raw.get("Name", "recipe"))),
            resource_type=f"chef_{resource}",
            actions=actions,
            risk=risk,
            explanation=explanation,
        )


def analyze_chef(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = ChefAdapter().analyze(data, tool_name="Chef")
    summary = PlanSummary(
        path=Path("chef://"), terraform_version=None, resource_changes=tuple(changes)
    )
    return agent_gate_to_dict(summary, catalog=catalog, tool_name="Chef")
