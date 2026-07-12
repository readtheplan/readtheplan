from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class VagrantInputError(ValueError):
    """Raised when text is not a recognizable Vagrantfile."""


_CONFIGURE = re.compile(r"\bVagrant\.configure\s*\(")
_DSL_MARKER = re.compile(
    r"\b[A-Za-z_]\w*\.vm\.(?:box|define|network|provider|provision|synced_folder)\b"
)
_BOX = re.compile(r"\b[A-Za-z_]\w*\.vm\.box\s*=\s*['\"](?P<name>[^'\"]+)['\"]")
_BOX_VERSION = re.compile(r"\b[A-Za-z_]\w*\.vm\.box_version\s*=")
_BOX_URL = re.compile(r"\b[A-Za-z_]\w*\.vm\.box_url\s*=\s*['\"](?P<url>[^'\"]+)['\"]")
_PROVIDER = re.compile(r"\.vm\.provider\s*(?:\(|\s)\s*['\"](?P<name>[^'\"]+)['\"]")
_PROVISION = re.compile(r"\.vm\.provision\s*(?:\(|\s)\s*['\"](?P<name>[^'\"]+)['\"]")
_NETWORK = re.compile(r"\.vm\.network\s*(?:\(|\s)\s*['\"](?P<name>[^'\"]+)['\"]")
_SYNCED_FOLDER = re.compile(
    r"\.vm\.synced_folder\s*(?:\(|\s)\s*['\"](?P<host>[^'\"]*)['\"]\s*,\s*['\"](?P<guest>[^'\"]*)['\"]"
)
_DEFINE = re.compile(r"\.vm\.define\s*(?:\(|\s)\s*['\"](?P<name>[^'\"]+)['\"]")
_TRIGGER = re.compile(r"\.(?:trigger|run|run_remote)\b")
_PRIVATE_KEY = re.compile(r"\.ssh\.private_key_path\s*=")
_RUBY_COMMAND = re.compile(r"(?:`[^`]+`|%x[({]|\b(?:system|exec|spawn)\s*\(|IO\.popen|Open3\.)")
_DYNAMIC_RUBY = re.compile(r"^\s*(?:require(?:_relative)?|load|eval)\b")
_CUSTOMIZE = re.compile(r"\.(?:customize|gui|memory|cpus|instance_type|ami|region)\b")
_SENSITIVE_HOST_PATH = re.compile(
    r"(?:^|[/\\])(?:\.ssh|\.aws|\.azure|\.config/gcloud|\.kube)(?:[/\\]|$)",
    re.IGNORECASE,
)


def _change(kind: str, name: str, line_number: int, detail: str = "") -> dict[str, Any]:
    return {
        "Kind": kind,
        "Name": name,
        "Address": f"line[{line_number}].{kind}",
        "Detail": detail,
    }


def parse_vagrantfile(source: str) -> dict[str, Any]:
    """Conservatively scan a Vagrantfile without evaluating its Ruby code."""
    if not source.strip():
        raise VagrantInputError("input is empty")
    if not (_CONFIGURE.search(source) or _DSL_MARKER.search(source)):
        raise VagrantInputError("no Vagrant configuration DSL was found")

    changes: list[dict[str, Any]] = []
    box_is_pinned = bool(_BOX_VERSION.search(source))
    for line_number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if match := _BOX.search(line):
            detail = "pinned" if box_is_pinned else "unpinned"
            changes.append(_change("box", match.group("name"), line_number, detail))
        if match := _BOX_URL.search(line):
            changes.append(_change("box_url", match.group("url"), line_number))
        if match := _PROVIDER.search(line):
            changes.append(_change("provider", match.group("name"), line_number))
        if match := _PROVISION.search(line):
            changes.append(_change("provisioner", match.group("name"), line_number))
        if match := _NETWORK.search(line):
            changes.append(_change("network", match.group("name"), line_number, line))
        if match := _SYNCED_FOLDER.search(line):
            detail = f"{match.group('host')} -> {match.group('guest')}"
            if "disabled: true" not in line and "disabled => true" not in line:
                changes.append(_change("synced_folder", match.group("host"), line_number, detail))
        if match := _DEFINE.search(line):
            changes.append(_change("machine", match.group("name"), line_number))
        if _PRIVATE_KEY.search(line):
            changes.append(_change("private_key", "ssh.private_key_path", line_number))
        if _TRIGGER.search(line) and ("trigger" in line or ".run" in line):
            changes.append(_change("trigger", "ruby trigger", line_number))
        if _RUBY_COMMAND.search(line):
            changes.append(_change("ruby_command", "host command execution", line_number))
        if _DYNAMIC_RUBY.search(line):
            changes.append(_change("ruby_dependency", stripped.split(maxsplit=1)[0], line_number))
        if _CUSTOMIZE.search(line) and ".vm." not in line:
            changes.append(
                _change("provider_customization", "provider-specific setting", line_number)
            )

    changes.append(
        _change(
            "ruby_boundary",
            "unresolved executable configuration",
            1,
            "Vagrantfile, box, plugin, provider, and home-directory configuration "
            "may merge dynamically.",
        )
    )
    return {"vagrantfile": {"changes": changes}}


class VagrantAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "vagrant"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        document = input_data.get("vagrantfile")
        return isinstance(document, dict) and isinstance(document.get("changes"), list)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        return list(input_data["vagrantfile"]["changes"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        kind = str(raw.get("Kind") or "unknown")
        name = str(raw.get("Name") or "unknown")
        detail = str(raw.get("Detail") or "")
        risk = "review"
        explanation = f"Vagrant {kind.replace('_', ' ')} '{name}' requires review."

        if kind == "box":
            if detail == "pinned":
                explanation = (
                    f"Vagrant box '{name}' is version-pinned; verify its publisher "
                    "and checksum policy."
                )
            else:
                risk = "dangerous"
                explanation = (
                    f"Vagrant box '{name}' is not version-pinned and may change "
                    "between runs."
                )
        elif kind == "box_url":
            risk = "dangerous" if name.lower().startswith("http://") else "review"
            explanation = (
                "Vagrant downloads a box from an explicit URL; verify transport, "
                "checksum, and trust."
            )
        elif kind == "provider":
            explanation = (
                f"Vagrant provider '{name}' can create and control machines on its "
                "configured target."
            )
        elif kind == "provisioner":
            risk = "dangerous"
            explanation = (
                f"Vagrant provisioner '{name}' can execute code or change guest "
                "system state."
            )
        elif kind == "network":
            risk = "dangerous" if name == "public_network" else "review"
            loopback_only = re.search(
                r"host_ip:\s*['\"]127\.0\.0\.1['\"]", detail
            )
            if name == "forwarded_port" and not loopback_only:
                risk = "dangerous"
            explanation = (
                f"Vagrant network '{name}' can expose guest services; verify "
                "interfaces, addresses, and ports."
            )
        elif kind == "synced_folder":
            host = name.replace("\\", "/")
            risky_host = (
                host in {"/", ".."}
                or host.startswith("../")
                or bool(_SENSITIVE_HOST_PATH.search(host))
            )
            risk = "dangerous" if risky_host else "review"
            explanation = (
                f"Vagrant shares host path '{name}' with the guest; verify write "
                "access and sensitive contents."
            )
        elif kind in {"private_key", "trigger", "ruby_command"}:
            risk = "dangerous"
            explanation = {
                "private_key": (
                    "Vagrant references an SSH private key path; protect secret "
                    "material and logs."
                ),
                "trigger": (
                    "Vagrant triggers can execute commands on the host or guest "
                    "during lifecycle operations."
                ),
                "ruby_command": "The Vagrantfile directly executes a host command through Ruby.",
            }[kind]
        elif kind == "ruby_dependency":
            risk = "dangerous"
            explanation = (
                "The Vagrantfile loads or evaluates external Ruby code that this "
                "static scan cannot inspect."
            )
        elif kind == "provider_customization":
            explanation = (
                "Provider-specific customization can alter compute, network, storage, "
                "or image settings."
            )
        elif kind == "machine":
            explanation = (
                f"Vagrant defines machine '{name}'; review its resolved provider, "
                "network, and provisioning configuration."
            )
        elif kind == "ruby_boundary":
            explanation = detail

        return ResourceChange(
            address=str(raw.get("Address") or name),
            resource_type=f"vagrant_{kind}",
            actions=("execute",),
            risk=risk,
            explanation=explanation,
        )


def analyze_vagrant(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = VagrantAdapter().analyze(data, tool_name="Vagrant")
    summary = PlanSummary(
        path=Path("vagrant://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Vagrant")
    gate["adapter"] = "vagrant"
    gate["total_changes"] = len(changes)
    return gate
