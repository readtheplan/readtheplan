from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_RESOURCE = re.compile(
    r"^\s*(?P<type>apt_package|apt_repository|ark|bash|batch|chef_gem|cookbook_file|"
    r"cron|cron_d|deploy|directory|execute|file|firewall_rule|git|group|http_request|"
    r"link|log|mount|package|powershell_script|reboot|remote_directory|remote_file|"
    r"route|ruby_block|script|service|sudo|systemd_unit|template|user|windows_service|"
    r"windows_task|yum_package|yum_repository)\s+['\"](?P<name>[^'\"]+)['\"]",
    re.MULTILINE,
)
_INCLUDE = re.compile(
    r"^\s*(?P<type>include_recipe|include_attribute|require_relative)\s*[(']?['\"]"
    r"(?P<name>[^'\"]+)['\"]",
    re.MULTILINE,
)
_ACTION_BLOCK = re.compile(r"\baction\s+(?P<actions>\[[^\]]+\]|:[a-z_]+)")
_ACTION_NAME = re.compile(r":(?P<action>[a-z_]+)")
_PROPERTY = re.compile(
    r"^\s*(?P<name>checksum|command|group|mode|not_if|notifies|only_if|owner|sensitive|"
    r"source|subscribes|user)\s+(?P<value>.+?)\s*$",
    re.MULTILINE,
)
_EXECUTION_TYPES = {
    "bash",
    "batch",
    "cron",
    "cron_d",
    "execute",
    "powershell_script",
    "ruby_block",
    "script",
    "windows_task",
}
_BOUNDARY_TYPES = {"firewall_rule", "mount", "route"}
_DANGEROUS_TYPES = _EXECUTION_TYPES | _BOUNDARY_TYPES | {"reboot", "sudo"}
_SAFE_TYPES = {"log"}
_DESTRUCTIVE_ACTIONS = {"delete", "disable", "purge", "remove", "restart", "stop"}
_REMOTE_TYPES = {
    "apt_repository",
    "ark",
    "chef_gem",
    "deploy",
    "git",
    "http_request",
    "remote_directory",
    "remote_file",
    "yum_repository",
}
_IDENTITY_TYPES = {"group", "user"}


class ChefAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "chef"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        source = input_data.get("chef_recipe")
        return isinstance(source, str) and bool(_RESOURCE.search(source) or _INCLUDE.search(source))

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        lines = str(input_data.get("chef_recipe", "")).splitlines()
        changes: list[dict[str, Any]] = []
        for index, line in enumerate(lines):
            match = _RESOURCE.match(line)
            if not match:
                continue
            block_lines = [line]
            if re.search(r"\bdo\s*(?:\|[^|]*\|)?\s*$", line):
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
            properties: dict[str, list[str]] = {}
            for property_match in _PROPERTY.finditer(block):
                properties.setdefault(property_match.group("name"), []).append(
                    property_match.group("value")
                )
            changes.append(
                {
                    "Type": match.group("type"),
                    "Name": match.group("name"),
                    "Actions": actions,
                    "Address": f"recipe:{index + 1}",
                    "Properties": properties,
                }
            )
        for match in _INCLUDE.finditer(str(input_data.get("chef_recipe", ""))):
            line_number = str(input_data.get("chef_recipe", "")).count("\n", 0, match.start()) + 1
            changes.append(
                {
                    "Type": match.group("type"),
                    "Name": match.group("name"),
                    "Actions": ["include"],
                    "Address": f"recipe:{line_number}",
                    "Properties": {},
                }
            )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        resource = str(raw.get("Type", "unknown"))
        actions = tuple(str(action) for action in raw.get("Actions", ["converge"]))
        properties = raw.get("Properties")
        properties = properties if isinstance(properties, dict) else {}
        risk = "review"
        explanation = (
            f"Chef resource '{resource}' converges system configuration; review desired state."
        )
        if resource in _SAFE_TYPES:
            risk = "safe"
            explanation = "Chef log resources report information without changing infrastructure."
        elif resource in _DANGEROUS_TYPES:
            risk = "dangerous"
            if resource in _EXECUTION_TYPES:
                explanation = (
                    f"Chef resource '{resource}' can execute arbitrary or scheduled code "
                    "during convergence."
                )
            elif resource in _BOUNDARY_TYPES:
                explanation = (
                    f"Chef resource '{resource}' changes network, routing, or mounted-storage "
                    "boundaries."
                )
            elif resource == "reboot":
                explanation = "Chef can reboot the managed node and interrupt availability."
            else:
                explanation = "Chef changes sudo policy and local privilege boundaries."
        elif resource in _IDENTITY_TYPES:
            risk = "dangerous"
            explanation = f"Chef resource '{resource}' changes local identity or group membership."
        elif resource in _REMOTE_TYPES:
            explanation = (
                f"Chef resource '{resource}' retrieves or deploys external content; review "
                "source trust, version pinning, checksum verification, and credentials."
            )
            source_values = " ".join(properties.get("source", []))
            if ("http://" in source_values or "latest" in source_values) and not properties.get(
                "checksum"
            ):
                risk = "dangerous"
                explanation += " The source is mutable or unencrypted and has no checksum."
        elif resource in {"include_recipe", "include_attribute", "require_relative"}:
            explanation = (
                f"Chef '{resource}' loads code or attributes not expanded in this recipe; "
                "review the referenced cookbook and dependency lock."
            )
        elif destructive := next(
            (action for action in actions if action in _DESTRUCTIVE_ACTIONS), None
        ):
            risk = "dangerous"
            explanation = (
                f"Chef resource '{resource}' requests availability-changing action '{destructive}'."
            )
        if any("immediately" in value for value in properties.get("notifies", [])):
            risk = "dangerous"
            explanation += " It immediately notifies another resource during convergence."
        if properties.get("only_if") or properties.get("not_if"):
            risk = "dangerous"
            explanation += " Shell or Ruby guard code can execute while deciding convergence."
        if any("0777" in value or "'777'" in value for value in properties.get("mode", [])):
            risk = "dangerous"
            explanation += " It requests world-writable file permissions."
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
