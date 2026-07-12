from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_RESOURCE = re.compile(
    r"^\s*(?P<type>augeas|cron|exec|file|firewall|group|mount|package|service|user)"
    r"\s*\{\s*['\"](?P<name>[^'\"]+)['\"]\s*:",
    re.MULTILINE,
)
_ENSURE = re.compile(r"\bensure\s*=>\s*(?::|['\"])?(?P<state>[a-z_]+)")
_DANGEROUS_TYPES = {"exec", "firewall"}
_DANGEROUS_STATES = {"absent", "disabled", "down", "purged", "stopped", "unmounted"}


class PuppetAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "puppet"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        source = input_data.get("puppet_manifest")
        return isinstance(source, str) and bool(_RESOURCE.search(source))

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        lines = str(input_data.get("puppet_manifest", "")).splitlines()
        changes: list[dict[str, Any]] = []
        for index, line in enumerate(lines):
            match = _RESOURCE.match(line)
            if not match:
                continue
            block_lines = [line]
            for candidate in lines[index + 1 :]:
                block_lines.append(candidate)
                if candidate.strip() == "}":
                    break
            block = "\n".join(block_lines)
            ensure = _ENSURE.search(block)
            state = ensure.group("state") if ensure else "present"
            changes.append(
                {
                    "Type": match.group("type"),
                    "Name": match.group("name"),
                    "State": state,
                    "Address": f"manifest:{index + 1}",
                }
            )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        resource = str(raw.get("Type", "unknown"))
        state = str(raw.get("State", "present"))
        risk = "review"
        explanation = (
            f"Puppet resource '{resource}' enforces system state; review the catalog change."
        )
        if resource in _DANGEROUS_TYPES:
            risk = "dangerous"
            explanation = (
                f"Puppet resource '{resource}' can execute commands or alter connectivity."
            )
        elif state in _DANGEROUS_STATES:
            risk = "dangerous"
            explanation = (
                f"Puppet resource '{resource}' enforces availability-changing state '{state}'."
            )
        return ResourceChange(
            address=str(raw.get("Address", raw.get("Name", "manifest"))),
            resource_type=f"puppet_{resource}",
            actions=(state,),
            risk=risk,
            explanation=explanation,
        )


def analyze_puppet(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = PuppetAdapter().analyze(data, tool_name="Puppet")
    summary = PlanSummary(
        path=Path("puppet://"), terraform_version=None, resource_changes=tuple(changes)
    )
    return agent_gate_to_dict(summary, catalog=catalog, tool_name="Puppet")
