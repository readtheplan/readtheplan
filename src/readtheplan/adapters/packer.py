from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class PackerInspectError(ValueError):
    """Raised when text is not recognized as ``packer inspect`` output."""


_MACHINE_LINE = re.compile(r"^\d+,")
_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)?$")
_PUBLISHING_POST_PROCESSORS = {
    "alicloud-import",
    "amazon-import",
    "artifactory",
    "docker-import",
    "docker-push",
    "googlecompute-export",
    "shell-local",
    "vagrant-cloud",
    "vsphere",
}
_PASSIVE_POST_PROCESSORS = {"checksum", "manifest"}


def _decode_machine_output(source: str) -> str:
    """Decode Packer's line-oriented machine-readable UI messages."""
    decoded: list[str] = []
    machine_lines = 0
    for line in source.splitlines():
        if not _MACHINE_LINE.match(line):
            continue
        machine_lines += 1
        try:
            row = next(csv.reader(io.StringIO(line)))
        except (csv.Error, StopIteration):
            continue
        if len(row) < 5 or row[2] != "ui":
            continue
        data = ",".join(row[4:])
        data = data.replace("%!(PACKER_COMMA)", ",")
        decoded.append(data.replace("\\r", "\r").replace("\\n", "\n"))
    return "\n".join(decoded) if machine_lines else source


def _component_name(line: str) -> str | None:
    value = line.strip()
    if not value or value.startswith((">", "<")) or value.endswith(":"):
        return None
    return value if _COMPONENT.fullmatch(value) else None


def parse_packer_inspect(source: str) -> dict[str, Any]:
    """Parse human or ``-machine-readable`` Packer inspect output."""
    if not source.strip():
        raise PackerInspectError("input is empty")
    text = _decode_machine_output(source)
    lowered = text.lower()
    if "packer inspect:" not in lowered:
        raise PackerInspectError("input is not Packer inspect output")

    mode = "hcl2" if "hcl2 mode" in lowered else "json" if "json mode" in lowered else "unknown"
    builds: list[dict[str, Any]] = []
    sensitive_variables = 0
    unknown_variables = 0

    current_build: dict[str, Any] | None = None
    section = ""
    in_variables = False
    in_hcl_builds = False
    legacy_required_variables = False
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        lowered_line = stripped.lower()
        if lowered_line in {"> input-variables:", "required variables:"}:
            in_variables = True
            legacy_required_variables = lowered_line == "required variables:"
            section = ""
            continue
        if lowered_line in {
            "> local-variables:",
            "optional variables and their defaults:",
        }:
            in_variables = lowered_line.startswith("optional")
            legacy_required_variables = False
            section = ""
            continue
        if in_variables:
            if legacy_required_variables and _COMPONENT.fullmatch(stripped):
                unknown_variables += 1
            elif "<sensitive>" in lowered_line:
                sensitive_variables += 1
            elif "<unknown>" in lowered_line:
                unknown_variables += 1

        if lowered_line in {"> builds:", "builders:"}:
            in_variables = False
            in_hcl_builds = lowered_line == "> builds:"
            section = "builders" if lowered_line == "builders:" else "builds"
            current_build = None
            continue
        if lowered_line == "provisioners:" and mode == "json":
            in_variables = False
            section = "provisioners"
            if current_build is None:
                current_build = {
                    "name": "legacy-json",
                    "sources": [],
                    "provisioners": [],
                    "post_processors": [],
                }
                builds.append(current_build)
            continue
        if in_hcl_builds and stripped.startswith(">") and stripped.endswith(":"):
            build_name = stripped[1:-1].strip()
            if build_name.lower() == "description":
                continue
            current_build = {
                "name": build_name or f"build-{len(builds) + 1}",
                "sources": [],
                "provisioners": [],
                "post_processors": [],
            }
            builds.append(current_build)
            continue
        if lowered_line == "sources:":
            section = "sources"
            continue
        if lowered_line == "provisioners:":
            section = "provisioners"
            continue
        if lowered_line == "post-processors:":
            section = "post_processors"
            continue

        component = _component_name(raw_line)
        if component is None:
            continue
        if section == "builders" and mode == "json":
            if current_build is None:
                current_build = {
                    "name": "legacy-json",
                    "sources": [],
                    "provisioners": [],
                    "post_processors": [],
                }
                builds.append(current_build)
            current_build["sources"].append(component)
        elif current_build is not None and section in {
            "sources",
            "provisioners",
            "post_processors",
        }:
            current_build[section].append(component)

    return {
        "packer_inspect": {
            "mode": mode,
            "builds": builds,
            "sensitive_variables": sensitive_variables,
            "unknown_variables": unknown_variables,
        }
    }


def parse_packer(source: str) -> dict[str, Any]:
    """Parse saved inspect output or native Packer HCL/JSON template source."""
    try:
        return parse_packer_inspect(source)
    except PackerInspectError as inspect_error:
        from readtheplan.adapters.packer_template import (
            PackerTemplateInputError,
            parse_packer_template,
        )

        try:
            return parse_packer_template(source)
        except PackerTemplateInputError as template_error:
            raise PackerInspectError(
                f"input is neither Packer inspect output nor template: {template_error}"
            ) from inspect_error


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {
        "Address": address,
        "Kind": kind,
        "Risk": risk,
        "Explanation": explanation,
    }


class PackerInspectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "packer"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        inspect = input_data.get("packer_inspect")
        template = input_data.get("packer_template")
        return (
            isinstance(inspect, dict)
            and isinstance(inspect.get("builds"), list)
            or isinstance(template, dict)
            and isinstance(template.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        if "packer_template" in input_data:
            from readtheplan.adapters.packer_template import packer_template_changes

            return packer_template_changes(input_data["packer_template"])
        inspect = input_data["packer_inspect"]
        changes: list[dict[str, Any]] = []

        if inspect.get("sensitive_variables"):
            changes.append(
                _change(
                    "inspect.input_variables.sensitive",
                    "secret_input",
                    "dangerous",
                    "Packer inspect reports sensitive input variables; verify credential "
                    "scope, injection, masking, and build-log handling.",
                )
            )
        if inspect.get("unknown_variables"):
            changes.append(
                _change(
                    "inspect.input_variables.unknown",
                    "unresolved_variable",
                    "review",
                    "Packer inspect could not resolve one or more variables; component "
                    "behavior may change when build-time values are supplied.",
                )
            )

        for build_index, build in enumerate(inspect.get("builds", [])):
            if not isinstance(build, dict):
                continue
            build_name = str(build.get("name") or f"build-{build_index + 1}")
            address = f"builds.{build_name}"
            for source_index, source in enumerate(build.get("sources", [])):
                source_ref = str(source)
                source_type = source_ref.split(".", 1)[0]
                risk = "review" if source_type == "null" else "dangerous"
                explanation = (
                    "Packer null builder exercises a provisioner chain without creating "
                    "a machine image; review host execution and build inputs."
                    if source_type == "null"
                    else "Packer builder can create temporary infrastructure and a machine "
                    "image artifact; review plugin provenance, source image, network, "
                    "credentials, cleanup, and destination ownership."
                )
                changes.append(
                    _change(
                        f"{address}.sources[{source_index}]",
                        "builder",
                        risk,
                        explanation,
                    )
                )
            for provisioner_index, provisioner in enumerate(build.get("provisioners", [])):
                name = str(provisioner)
                safe = name in {"breakpoint", "sleep"}
                risk = "safe" if safe else "review" if name == "file" else "dangerous"
                explanation = (
                    f"Packer provisioner '{name}' pauses or sequences the build."
                    if safe
                    else f"Packer provisioner '{name}' copies content into the build; "
                    "review source, destination, permissions, and sensitive data."
                    if name == "file"
                    else f"Packer provisioner '{name}' executes or applies configuration "
                    "during image creation; review commands, scripts, credentials, and scope."
                )
                changes.append(
                    _change(
                        f"{address}.provisioners[{provisioner_index}]",
                        "provisioner",
                        risk,
                        explanation,
                    )
                )
            for processor_index, processor in enumerate(build.get("post_processors", [])):
                name = str(processor)
                if name in _PASSIVE_POST_PROCESSORS:
                    risk = "safe"
                    explanation = (
                        f"Packer post-processor '{name}' records artifact metadata or "
                        "integrity information without publishing the artifact."
                    )
                elif name in _PUBLISHING_POST_PROCESSORS:
                    risk = "dangerous"
                    explanation = (
                        f"Packer post-processor '{name}' can execute locally or publish "
                        "the build artifact; verify destination, credentials, overwrite "
                        "behavior, retention, and provenance."
                    )
                else:
                    risk = "review"
                    explanation = (
                        f"Packer post-processor '{name}' transforms the build artifact; "
                        "review its resolved configuration and output boundary."
                    )
                changes.append(
                    _change(
                        f"{address}.post_processors[{processor_index}]",
                        "post_processor",
                        risk,
                        explanation,
                    )
                )

        if not inspect.get("builds"):
            changes.append(
                _change(
                    "inspect.builds",
                    "unresolved",
                    "review",
                    "Packer inspect reports no statically resolved builds.",
                )
            )
        changes.append(
            _change(
                "inspect.limitations",
                "inspection_limit",
                "review",
                "Packer inspect enumerates components but does not validate plugin-specific "
                "configuration. Review the template and run packer validate separately.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"packer_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_packer(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = PackerInspectAdapter().analyze(data, tool_name="Packer")
    summary = PlanSummary(
        path=Path("packer://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Packer")
    gate["adapter"] = "packer"
    gate["artifact_type"] = "template" if "packer_template" in data else "inspect"
    gate["total_changes"] = len(changes)
    return gate
