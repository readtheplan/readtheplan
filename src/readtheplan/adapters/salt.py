from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class SaltInputError(ValueError):
    """Raised when text is not a recognizable Salt SLS state file."""


_STATE_FUNCTION = re.compile(r"^[A-Za-z_][\w-]*\.[A-Za-z_][\w-]*$")
_STATE_LINE = re.compile(
    r"^(?P<indent>\s+)(?P<function>[A-Za-z_][\w-]*\.[A-Za-z_][\w-]*):\s*(?:#.*)?$"
)
_JINJA_MARKERS = ("{%", "{{", "{#")
_RENDER_COMMAND = re.compile(r"salt\s*\[\s*['\"](?:cmd|module)\.", re.IGNORECASE)
_SENSITIVE_NAMES = ("password", "passwd", "secret", "token", "api_key", "private_key")

_DANGEROUS_MODULES = {
    "ansiblegate",
    "blockdev",
    "cloud",
    "cmd",
    "disk",
    "docker_container",
    "docker_network",
    "docker_volume",
    "firewall",
    "firewalld",
    "iptables",
    "ipset",
    "kubernetes",
    "lvm",
    "module",
    "mount",
    "network",
    "raid",
    "state",
    "sysctl",
}
_DESTRUCTIVE_FUNCTIONS = {
    ("cron", "absent"),
    ("file", "absent"),
    ("group", "absent"),
    ("host", "absent"),
    ("pkg", "purged"),
    ("pkg", "removed"),
    ("service", "dead"),
    ("service", "disabled"),
    ("user", "absent"),
}


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise SaltInputError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _argument_map(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    result: dict[str, Any] = {}
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                result.update(item)
    return result


def _contains_sensitive_input(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            any(token in str(key).lower() for token in _SENSITIVE_NAMES)
            or _contains_sensitive_input(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_input(item) for item in value)
    text = str(value).lower()
    return any(token in text for token in ("pillar.get", "sdb://", "vault.read"))


def _state(
    state_id: str,
    function_name: str,
    args: Any,
    address: str,
) -> dict[str, Any]:
    module, function = function_name.split(".", 1)
    return {
        "ID": state_id,
        "Module": module,
        "Function": function,
        "Args": args,
        "Address": address,
    }


def _scan_dynamic_sls(source: str) -> list[dict[str, Any]]:
    states: list[dict[str, Any]] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        match = _STATE_LINE.match(line)
        if not match:
            continue
        function_name = match.group("function")
        states.append(
            _state(
                f"dynamic-line-{line_number}",
                function_name,
                {},
                f"line[{line_number}].{function_name}",
            )
        )
    return states


def parse_salt_sls(source: str) -> dict[str, Any]:
    """Parse static YAML SLS or conservatively scan a templated SLS file."""
    if not source.strip():
        raise SaltInputError("input is empty")
    dynamic = any(marker in source for marker in _JINJA_MARKERS)
    states: list[dict[str, Any]] = []
    include: Any = None
    exclude: Any = None

    try:
        document = yaml.load(source, Loader=_UniqueKeyLoader)
    except SaltInputError:
        raise
    except yaml.YAMLError as exc:
        if not dynamic:
            raise SaltInputError(f"invalid YAML: {exc}") from exc
        document = None

    if isinstance(document, dict):
        include = document.get("include")
        exclude = document.get("exclude")
        for state_id, body in document.items():
            if state_id in {"include", "exclude"}:
                continue
            if state_id == "extend":
                states.append(
                    {
                        "ID": "extend",
                        "Module": "meta",
                        "Function": "extend",
                        "Args": body,
                        "Address": "sls.extend",
                    }
                )
                continue
            if not isinstance(body, dict):
                continue
            for function_name, args in body.items():
                if isinstance(function_name, str) and _STATE_FUNCTION.fullmatch(function_name):
                    states.append(
                        _state(
                            str(state_id),
                            function_name,
                            args,
                            f"states.{state_id}.{function_name}",
                        )
                    )
    elif document is not None and not dynamic:
        raise SaltInputError("Salt SLS input must be a YAML object")

    if dynamic and not states:
        states = _scan_dynamic_sls(source)
    if not states and include is None and exclude is None and not dynamic:
        raise SaltInputError("no Salt state functions were found")

    return {
        "salt_sls": {
            "states": states,
            "include": include,
            "exclude": exclude,
            "dynamic_renderer": dynamic,
            "render_command": bool(_RENDER_COMMAND.search(source)),
        }
    }


class SaltAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "salt"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        sls = input_data.get("salt_sls")
        return isinstance(sls, dict) and isinstance(sls.get("states"), list)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        sls = input_data["salt_sls"]
        changes = list(sls.get("states", []))
        if sls.get("include") is not None:
            changes.append(
                {
                    "ID": "include",
                    "Module": "meta",
                    "Function": "include",
                    "Args": sls["include"],
                    "Address": "sls.include",
                }
            )
        if sls.get("exclude") is not None:
            changes.append(
                {
                    "ID": "exclude",
                    "Module": "meta",
                    "Function": "exclude",
                    "Args": sls["exclude"],
                    "Address": "sls.exclude",
                }
            )
        if sls.get("dynamic_renderer"):
            changes.append(
                {
                    "ID": "renderer",
                    "Module": "meta",
                    "Function": "dynamic_renderer",
                    "Args": {},
                    "Address": "sls.renderer",
                }
            )
        if sls.get("render_command"):
            changes.append(
                {
                    "ID": "renderer-command",
                    "Module": "meta",
                    "Function": "render_command",
                    "Args": {},
                    "Address": "sls.renderer.command",
                }
            )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        module = str(raw.get("Module") or "unknown").lower()
        function = str(raw.get("Function") or "unknown").lower()
        args = _argument_map(raw.get("Args"))
        state_name = f"{module}.{function}"
        risk = "review"
        explanation = (
            f"Salt state '{state_name}' changes managed system state; review target, "
            "arguments, requisites, and rollback."
        )

        if module == "test":
            risk = "safe"
            explanation = f"Salt state '{state_name}' is a test/no-op state."
        elif function == "render_command":
            risk = "dangerous"
            explanation = (
                "Salt Jinja rendering invokes an execution module. Rendering the SLS can "
                "run commands before state enforcement begins."
            )
        elif function == "dynamic_renderer":
            risk = "review"
            explanation = (
                "Salt SLS uses Jinja or another template expression. Review the rendered "
                "highstate because static scanning cannot resolve every generated state."
            )
        elif module == "meta" and function in {"include", "extend", "exclude"}:
            risk = "review"
            explanation = (
                f"Salt SLS {function}s state data not fully expanded in this artifact; "
                "review the resolved highstate."
            )
        elif (module, function) in _DESTRUCTIVE_FUNCTIONS:
            risk = "dangerous"
            explanation = f"Salt state '{state_name}' removes or disables managed state."
        elif module in _DANGEROUS_MODULES:
            risk = "dangerous"
            explanation = (
                f"Salt state '{state_name}' can execute commands or change host, storage, "
                "network, container, or cloud control-plane state."
            )

        if _contains_sensitive_input(args):
            risk = "dangerous"
            explanation += (
                " The state references credential-like arguments or external secret data; "
                "verify Pillar/SDB scope and output masking."
            )

        return ResourceChange(
            address=str(raw.get("Address") or raw.get("ID") or "<unknown>"),
            resource_type=f"salt_{module}_{function}",
            actions=("execute",),
            risk=risk,
            explanation=explanation,
        )


def analyze_salt(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = SaltAdapter().analyze(data, tool_name="Salt")
    summary = PlanSummary(
        path=Path("salt://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Salt")
    gate["adapter"] = "salt"
    gate["total_changes"] = len(changes)
    return gate
