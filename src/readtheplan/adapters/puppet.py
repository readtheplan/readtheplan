from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_RESOURCE = re.compile(
    r"^\s*(?P<virtual>@{1,2})?(?P<type>augeas|computer|cron|exec|file|filebucket|"
    r"firewall|group|host|interface|mailalias|maillist|mount|notify|package|resources|"
    r"route|schedule|scheduled_task|selboolean|service|ssh_authorized_key|stage|tidy|"
    r"user|yumrepo|zfs|zpool|[a-z][a-z0-9_]*(?:::[a-z][a-z0-9_]*)+)"
    r"\s*\{\s*['\"](?P<name>[^'\"]+)['\"]\s*:",
    re.MULTILINE,
)
_ENSURE = re.compile(r"\bensure\s*=>\s*(?::|['\"])?(?P<state>[a-z_]+)")
_PROPERTY = re.compile(
    r"^\s*(?P<name>command|content|mode|notify|provider|purge|refreshonly|require|"
    r"source|subscribe|user)\s*=>\s*(?P<value>.+?)(?:,\s*)?$",
    re.MULTILINE,
)
_CLASS_FUNCTION = re.compile(
    r"^\s*(?P<function>include|contain|require)\s+(?P<target>[a-z][a-z0-9_:]*)\s*$",
    re.MULTILINE,
)
_DYNAMIC_FUNCTION = re.compile(
    r"\b(?P<function>lookup|hiera|epp|inline_epp|template|generate|create_resources)\s*\("
)
_COLLECTOR = re.compile(
    r"^\s*(?P<type>[A-Z][A-Za-z0-9_:]*)\s*(?P<operator><<\||<\|)"
    r"(?P<query>.*?)(?:\|>>|\|>)",
    re.MULTILINE,
)
_DANGEROUS_TYPES = {
    "cron",
    "exec",
    "firewall",
    "mount",
    "resources",
    "route",
    "scheduled_task",
}
_IDENTITY_TYPES = {"group", "ssh_authorized_key", "user"}
_SAFE_TYPES = {"notify"}
_DANGEROUS_STATES = {"absent", "disabled", "down", "purged", "stopped", "unmounted"}


class PuppetAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "puppet"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        source = input_data.get("puppet_manifest")
        return isinstance(source, str) and bool(
            _RESOURCE.search(source)
            or _CLASS_FUNCTION.search(source)
            or _DYNAMIC_FUNCTION.search(source)
            or _COLLECTOR.search(source)
        )

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
            properties: dict[str, list[str]] = {}
            for property_match in _PROPERTY.finditer(block):
                properties.setdefault(property_match.group("name"), []).append(
                    property_match.group("value")
                )
            changes.append(
                {
                    "Type": match.group("type"),
                    "Name": match.group("name"),
                    "State": state,
                    "Address": f"manifest:{index + 1}",
                    "Virtual": match.group("virtual") or "",
                    "Properties": properties,
                }
            )
        source = str(input_data.get("puppet_manifest", ""))
        for match in _CLASS_FUNCTION.finditer(source):
            changes.append(
                {
                    "Type": "class_include",
                    "Name": match.group("target"),
                    "State": match.group("function"),
                    "Address": f"manifest:{source.count(chr(10), 0, match.start()) + 1}",
                    "Virtual": "",
                    "Properties": {},
                }
            )
        for match in _DYNAMIC_FUNCTION.finditer(source):
            changes.append(
                {
                    "Type": "dynamic_function",
                    "Name": match.group("function"),
                    "State": "evaluate",
                    "Address": f"manifest:{source.count(chr(10), 0, match.start()) + 1}",
                    "Virtual": "",
                    "Properties": {},
                }
            )
        for match in _COLLECTOR.finditer(source):
            changes.append(
                {
                    "Type": "resource_collector",
                    "Name": match.group("type"),
                    "State": "collect",
                    "Address": f"manifest:{source.count(chr(10), 0, match.start()) + 1}",
                    "Virtual": "@@" if match.group("operator") == "<<|" else "@",
                    "Properties": {"query": [match.group("query").strip()]},
                }
            )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        resource = str(raw.get("Type", "unknown"))
        state = str(raw.get("State", "present"))
        virtual = str(raw.get("Virtual", ""))
        properties = raw.get("Properties")
        properties = properties if isinstance(properties, dict) else {}
        risk = "review"
        explanation = (
            f"Puppet resource '{resource}' enforces system state; review the catalog change."
        )
        if resource in _SAFE_TYPES:
            risk = "safe"
            explanation = f"Puppet resource '{resource}' only records catalog information."
        elif resource in _DANGEROUS_TYPES:
            risk = "dangerous"
            explanation = (
                f"Puppet resource '{resource}' can execute commands or alter connectivity."
            )
        elif resource in _IDENTITY_TYPES:
            risk = "dangerous"
            explanation = f"Puppet resource '{resource}' changes local identity or SSH trust."
        elif resource == "class_include":
            explanation = (
                "Puppet includes or contains a class whose resources are not expanded in "
                "this manifest; review module provenance and data binding."
            )
        elif resource == "dynamic_function":
            explanation = (
                "Puppet evaluates external data, templates, generated commands, or dynamic "
                "resources; review lookup hierarchy, inputs, and generated catalog content."
            )
        elif resource == "resource_collector":
            risk = "dangerous"
            explanation = (
                "Puppet realizes matching virtual or exported resources across the catalog"
                + (" without a filter." if not properties.get("query", [""])[0] else ".")
            )
        elif state in _DANGEROUS_STATES:
            risk = "dangerous"
            explanation = (
                f"Puppet resource '{resource}' enforces availability-changing state '{state}'."
            )
        if virtual == "@@":
            risk = "dangerous"
            explanation += " It exports state through PuppetDB for collection by other nodes."
        elif virtual == "@" and resource != "resource_collector":
            risk = "review"
            explanation += " It is virtual and takes effect only when realized."
        values = " ".join(value for items in properties.values() for value in items)
        if "http://" in values or "0777" in values or "'777'" in values:
            risk = "dangerous"
            explanation += " It uses an unencrypted source or world-writable permissions."
        if properties.get("notify") or properties.get("subscribe"):
            risk = "dangerous"
            explanation += " It can refresh dependent resources when state changes."
        return ResourceChange(
            address=str(raw.get("Address", raw.get("Name", "manifest"))),
            resource_type=f"puppet_{resource.replace('::', '_')}",
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
