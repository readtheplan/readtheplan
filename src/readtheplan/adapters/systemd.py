from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class SystemdUnitInputError(ValueError):
    """Raised when text is not a recognizable systemd unit file."""


_UNIT_SECTIONS = {
    "Automount",
    "Install",
    "Mount",
    "Path",
    "Service",
    "Slice",
    "Socket",
    "Swap",
    "Timer",
    "Unit",
}
_EXEC_KEYS = {
    "ExecCondition",
    "ExecReload",
    "ExecStart",
    "ExecStartPost",
    "ExecStartPre",
    "ExecStop",
    "ExecStopPost",
}
_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|credential|passwd|password|private[_-]?key|secret|token)(?:$|[_-])",
    re.IGNORECASE,
)
_LISTEN_KEYS = {
    "ListenDatagram",
    "ListenFIFO",
    "ListenMessageQueue",
    "ListenNetlink",
    "ListenSequentialPacket",
    "ListenSpecial",
    "ListenStream",
    "ListenUSBFunction",
}
_BOOLEAN_SANDBOX = {
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "NoNewPrivileges",
    "PrivateDevices",
    "PrivateIPC",
    "PrivateMounts",
    "PrivateNetwork",
    "PrivateTmp",
    "ProtectClock",
    "ProtectControlGroups",
    "ProtectHostname",
    "ProtectKernelLogs",
    "ProtectKernelModules",
    "ProtectKernelTunables",
    "ProtectProc",
    "RestrictRealtime",
    "RestrictSUIDSGID",
}
_SAFE_METADATA = {
    "Description",
    "Documentation",
    "SourcePath",
    "SyslogIdentifier",
}
_DANGEROUS_CAPABILITIES = {
    "CAP_BPF",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_CHROOT",
    "CAP_SYS_MODULE",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
}


def _is_true(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _is_false(value: str) -> bool:
    return value.strip().lower() in {"0", "false", "no", "off"}


def _change(
    section: str,
    key: str,
    value: str,
    line_number: int,
    occurrence: int,
    *,
    kind: str | None = None,
) -> dict[str, Any]:
    return {
        "Section": section,
        "Key": key,
        "Value": value,
        "Line": line_number,
        "Kind": kind or key,
        "Address": f"{section}.{key}[{occurrence}]",
    }


def _logical_lines(source: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    lines = source.splitlines()
    index = 0
    while index < len(lines):
        line_number = index + 1
        logical = lines[index]
        index += 1
        while logical.rstrip().endswith("\\") and index < len(lines):
            logical = logical.rstrip()[:-1] + " " + lines[index].lstrip()
            index += 1
        result.append((line_number, logical))
    return result


def parse_systemd_unit(source: str) -> dict[str, Any]:
    """Parse a systemd unit while preserving repeated and reset directives."""
    if not source.strip():
        raise SystemdUnitInputError("input is empty")

    section = ""
    entries: list[dict[str, Any]] = []
    occurrences: Counter[tuple[str, str]] = Counter()
    sections: set[str] = set()
    for line_number, raw_line in _logical_lines(source):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            if not section:
                raise SystemdUnitInputError(f"empty section name at line {line_number}")
            sections.add(section)
            continue
        if not section:
            raise SystemdUnitInputError(
                f"directive appears before a section at line {line_number}"
            )
        if "=" not in raw_line:
            raise SystemdUnitInputError(f"invalid directive at line {line_number}")
        key, value = raw_line.split("=", 1)
        key = key.strip()
        if not key or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key):
            raise SystemdUnitInputError(f"invalid directive name at line {line_number}")
        occurrence = occurrences[(section, key)]
        occurrences[(section, key)] += 1
        entries.append(_change(section, key, value.strip(), line_number, occurrence))

    recognized = sections & _UNIT_SECTIONS
    typed = recognized - {"Unit", "Install"}
    if not recognized or not typed:
        raise SystemdUnitInputError(
            "unit must contain a recognized type section such as [Service], [Socket], or [Timer]"
        )

    derived: list[dict[str, Any]] = []
    if "Service" in sections:
        service_values = {
            entry["Key"]: entry["Value"]
            for entry in entries
            if entry["Section"] == "Service"
        }
        user = str(service_values.get("User") or "")
        dynamic_user = _is_true(str(service_values.get("DynamicUser") or ""))
        if not user and not dynamic_user:
            derived.append(
                _change(
                    "Service",
                    "RuntimeIdentity",
                    "inherited/default",
                    1,
                    0,
                    kind="runtime_identity",
                )
            )
        restart = str(service_values.get("Restart") or "").lower()
        restart_delay = service_values.get("RestartSec")
        restart_modes = {"always", "on-abnormal", "on-failure", "on-success", "on-watchdog"}
        if restart in restart_modes and not restart_delay:
            derived.append(
                _change(
                    "Service",
                    "RestartLoop",
                    restart,
                    1,
                    0,
                    kind="restart_loop",
                )
            )
        derived.append(
            _change(
                "Service",
                "SandboxBoundary",
                "manager defaults and omitted hardening directives",
                1,
                0,
                kind="sandbox_boundary",
            )
        )
    for unit_section, kind in (
        ("Socket", "activated_unit_boundary"),
        ("Timer", "triggered_unit_boundary"),
        ("Path", "triggered_unit_boundary"),
    ):
        if unit_section in sections:
            derived.append(
                _change(
                    unit_section,
                    "TargetUnitBoundary",
                    "referenced or implicit unit not included",
                    1,
                    0,
                    kind=kind,
                )
            )
    derived.append(
        _change(
            "Unit",
            "MergeBoundary",
            "vendor unit, drop-ins, manager defaults, and runtime properties",
            1,
            0,
            kind="merge_boundary",
        )
    )
    return {
        "systemd_unit": {
            "sections": sorted(sections),
            "entries": entries + derived,
        }
    }


def _environment_has_secret(value: str) -> bool:
    for assignment in re.findall(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=", value):
        if _SECRET_KEY.search(assignment):
            return True
    return False


def _world_writable_mode(value: str) -> bool:
    mode = value.strip().removeprefix("0")
    return bool(mode) and mode[-1] in {"2", "3", "6", "7"}


class SystemdUnitAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "systemd"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        unit = input_data.get("systemd_unit")
        return isinstance(unit, dict) and isinstance(unit.get("entries"), list)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        return list(input_data["systemd_unit"]["entries"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        section = str(raw.get("Section") or "Unit")
        key = str(raw.get("Key") or "unknown")
        value = str(raw.get("Value") or "")
        kind = str(raw.get("Kind") or key).lower()
        risk = "review"
        explanation = f"systemd directive {section}.{key} requires review."

        if key in _EXEC_KEYS:
            risk = "dangerous"
            explanation = (
                f"systemd {key}= executes host command '{value}'; verify executable, "
                "arguments, prefix modifiers, identity, environment, and failure behavior."
            )
        elif key in {"User", "Group", "SupplementaryGroups"}:
            root = value.strip().lower() in {"0", "root"}
            risk = "dangerous" if root else "review"
            explanation = f"systemd {key}= sets process identity or group access to '{value}'."
        elif key == "DynamicUser":
            risk = "safe" if _is_true(value) else "review"
            explanation = "DynamicUser= controls allocation of an ephemeral service identity."
        elif key == "AmbientCapabilities":
            risk = "dangerous" if value else "safe"
            explanation = "AmbientCapabilities= grants Linux capabilities to executed processes."
        elif key == "CapabilityBoundingSet":
            capabilities = {item.lstrip("~") for item in value.upper().split()}
            dangerous = bool(capabilities & _DANGEROUS_CAPABILITIES) and not value.startswith("~")
            risk = "dangerous" if dangerous else "safe" if not value else "review"
            explanation = "CapabilityBoundingSet= limits or grants the service capability set."
        elif key in _BOOLEAN_SANDBOX:
            risk = "safe" if _is_true(value) else "dangerous" if _is_false(value) else "review"
            explanation = f"{key}= controls a systemd process-sandbox boundary."
        elif key == "ProtectSystem":
            risk = "safe" if value.lower() in {"yes", "true", "full", "strict"} else "review"
            explanation = "ProtectSystem= controls read-only access to host system paths."
        elif key == "ProtectHome":
            risk = "safe" if value.lower() in {"yes", "true", "read-only", "tmpfs"} else "review"
            explanation = "ProtectHome= controls access to user home directories."
        elif key in {"Environment", "UnsetEnvironment"}:
            sensitive = _environment_has_secret(value)
            risk = "dangerous" if sensitive else "review"
            explanation = "Environment directives alter process environment inherited by commands."
            if sensitive:
                explanation += " A variable name appears credential-bearing."
        elif key in {"EnvironmentFile", "PassEnvironment"}:
            risk = "dangerous" if key == "EnvironmentFile" else "review"
            explanation = f"{key}= imports environment data outside this unit artifact."
        elif key in {
            "LoadCredential",
            "LoadCredentialEncrypted",
            "SetCredential",
            "SetCredentialEncrypted",
            "ImportCredential",
        }:
            risk = "dangerous"
            explanation = f"{key}= supplies credential material to the service."
        elif key in {"RootDirectory", "RootImage", "MountImages", "ExtensionImages"}:
            risk = "dangerous"
            explanation = f"{key}= changes the filesystem/image root visible to the service."
        elif key in {"BindPaths", "TemporaryFileSystem"}:
            risk = "dangerous"
            explanation = f"{key}= mounts writable filesystem content into the service namespace."
        elif key == "BindReadOnlyPaths":
            explanation = "BindReadOnlyPaths= exposes host filesystem content read-only."
        elif key in {"ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths"}:
            sensitive_write = key == "ReadWritePaths" and any(
                path in value.split() for path in ("/", "/boot", "/etc", "/usr")
            )
            risk = "dangerous" if sensitive_write else "review"
            explanation = f"{key}= changes filesystem access granted to the service."
        elif key in {"DeviceAllow", "DevicePolicy"}:
            safe_policy = key == "DevicePolicy" and value.lower() in {"closed", "strict"}
            risk = "safe" if safe_policy else "dangerous" if key == "DeviceAllow" else "review"
            explanation = f"{key}= controls access to host devices."
        elif key in _LISTEN_KEYS:
            network = bool(re.search(r"(?:^|:)(?:\d+)$", value)) or value.startswith("[")
            risk = "dangerous" if network else "review"
            explanation = f"{key}= creates a socket endpoint at '{value}'."
        elif key == "SocketMode":
            risk = "dangerous" if _world_writable_mode(value) else "review"
            explanation = "SocketMode= controls permissions on a filesystem socket or FIFO."
        elif key in {"SocketUser", "SocketGroup", "Accept", "BindToDevice", "FreeBind"}:
            explanation = f"{key}= changes socket ownership, activation, or network binding."
        elif section == "Timer" and key.startswith("On"):
            explanation = f"{key}= schedules activation of another systemd unit."
        elif section == "Timer" and key in {"Persistent", "WakeSystem", "RandomizedDelaySec"}:
            risk = "dangerous" if key == "WakeSystem" and _is_true(value) else "review"
            explanation = f"{key}= changes missed-run, wake, or timer-distribution behavior."
        elif key == "Restart":
            risk = "dangerous" if value.lower() == "always" else "review"
            explanation = "Restart= controls automatic command re-execution after exit or failure."
        elif key == "KillMode" and value.lower() == "none":
            risk = "dangerous"
            explanation = "KillMode=none can leave service processes running after unit stop."
        elif key == "SendSIGKILL" and _is_false(value):
            risk = "dangerous"
            explanation = "SendSIGKILL=no can leave processes alive after the stop timeout."
        elif section in {"Mount", "Automount", "Swap"} and key in {
            "What",
            "Where",
            "Options",
            "Type",
        }:
            risk = "dangerous" if section in {"Mount", "Swap"} else "review"
            explanation = f"{section}.{key}= changes host storage or mount behavior."
        elif section == "Path" and key.startswith("Path"):
            explanation = f"{key}= triggers another unit from host filesystem activity."
        elif key in {"OnFailure", "OnSuccess", "Wants", "Requires", "Requisite", "BindsTo"}:
            explanation = f"{key}= links this unit's lifecycle to other systemd units."
        elif key == "DefaultDependencies" and _is_false(value):
            risk = "dangerous"
            explanation = "DefaultDependencies=no removes systemd's implicit ordering safeguards."
        elif key in _SAFE_METADATA:
            risk = "safe"
            explanation = f"{key}= records descriptive or logging metadata."
        elif not value:
            explanation = (
                f"An empty {section}.{key}= resets earlier values from the vendor unit or drop-ins."
            )
        elif kind == "runtime_identity":
            risk = "dangerous"
            explanation = (
                "System service has no explicit User= or DynamicUser=yes and normally "
                "inherits the manager's root identity."
            )
        elif kind == "restart_loop":
            risk = "dangerous"
            explanation = (
                f"Restart={value} has no explicit RestartSec= delay; verify start-rate "
                "limits and failure-loop behavior."
            )
        elif kind == "sandbox_boundary":
            explanation = (
                "Effective sandboxing also depends on omitted directives, manager defaults, "
                "kernel support, and the complete merged unit."
            )
        elif kind in {"activated_unit_boundary", "triggered_unit_boundary"}:
            explanation = (
                "This unit activates another explicit or implicit unit whose commands, "
                "identity, and sandbox are not present in this artifact."
            )
        elif kind == "merge_boundary":
            explanation = (
                "systemd merges vendor units, transient/generated units, drop-ins, reset "
                "directives, manager defaults, and runtime properties. Review the output "
                "of systemd-analyze cat-config/security in the target trust boundary."
            )

        return ResourceChange(
            address=str(raw.get("Address") or f"{section}.{key}"),
            resource_type=f"systemd_{kind}",
            actions=("execute",),
            risk=risk,
            explanation=explanation,
        )


def analyze_systemd(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = SystemdUnitAdapter().analyze(data, tool_name="systemd")
    summary = PlanSummary(
        path=Path("systemd://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="systemd")
    gate["adapter"] = "systemd"
    gate["total_changes"] = len(changes)
    return gate
