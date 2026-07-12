from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class DockerfileInputError(ValueError):
    """Raised when text is not a recognizable Dockerfile/Containerfile."""


_INSTRUCTION = re.compile(r"^(?P<name>[A-Za-z]+)\s+(?P<value>.*)$", re.DOTALL)
_HEREDOC = re.compile(r"<<-?\s*['\"]?(?P<delimiter>[A-Za-z_][\w.-]*)['\"]?")
_SYNTAX = re.compile(r"^\s*#\s*syntax\s*=\s*(?P<frontend>\S+)", re.IGNORECASE)
_ESCAPE = re.compile(r"^\s*#\s*escape\s*=\s*(?P<escape>[`\\])", re.IGNORECASE | re.MULTILINE)
_FROM = re.compile(
    r"^(?:(?:--platform=\S+)\s+)?(?P<image>\S+)(?:\s+[Aa][Ss]\s+(?P<stage>[\w.-]+))?$"
)
_SECRET_NAME = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|auth|credential|passwd|password|private[_-]?key|secret|token)(?:$|[_-])",
    re.IGNORECASE,
)
_SENSITIVE_SOURCE = re.compile(
    r"(?:^|[/\\])(?:\.aws|\.azure|\.env|\.git|\.kube|\.npmrc|\.pypirc|\.ssh|id_rsa|id_ed25519)(?:$|[/\\])",
    re.IGNORECASE,
)
_REMOTE_SOURCE = re.compile(r"^(?:https?|git|ssh)://|^git@", re.IGNORECASE)
_KNOWN = {
    "ADD",
    "ARG",
    "CMD",
    "COPY",
    "ENTRYPOINT",
    "ENV",
    "EXPOSE",
    "FROM",
    "HEALTHCHECK",
    "LABEL",
    "MAINTAINER",
    "ONBUILD",
    "RUN",
    "SHELL",
    "STOPSIGNAL",
    "USER",
    "VOLUME",
    "WORKDIR",
}


def _change(
    kind: str,
    name: str,
    value: str,
    line_number: int,
    **metadata: Any,
) -> dict[str, Any]:
    return {
        "Kind": kind,
        "Name": name,
        "Value": value,
        "Address": f"line[{line_number}].{kind.lower()}",
        **metadata,
    }


def _logical_instructions(source: str) -> list[tuple[int, str, str]]:
    lines = source.splitlines()
    escape_match = _ESCAPE.search(source)
    escape = escape_match.group("escape") if escape_match else "\\"
    instructions: list[tuple[int, str, str]] = []
    index = 0
    while index < len(lines):
        raw = lines[index]
        line_number = index + 1
        stripped = raw.strip()
        index += 1
        if not stripped or stripped.startswith("#"):
            continue

        logical = stripped
        while logical.rstrip().endswith(escape) and index < len(lines):
            logical = logical.rstrip()[:-1] + " " + lines[index].strip()
            index += 1

        match = _INSTRUCTION.match(logical)
        if not match:
            instructions.append((line_number, "UNKNOWN", logical))
            continue
        name = match.group("name").upper()
        value = match.group("value").strip()
        heredoc = _HEREDOC.search(value)
        if heredoc:
            delimiter = heredoc.group("delimiter")
            body: list[str] = []
            while index < len(lines):
                candidate = lines[index]
                index += 1
                if candidate.strip() == delimiter:
                    break
                body.append(candidate)
            else:
                raise DockerfileInputError(
                    f"unterminated heredoc '{delimiter}' starting at line {line_number}"
                )
            value = value + "\n" + "\n".join(body)
        instructions.append((line_number, name, value))
    return instructions


def _split_key_value(value: str) -> tuple[str, str]:
    if "=" in value:
        key, item = value.split("=", 1)
        return key.strip(), item.strip()
    parts = value.split(None, 1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def _copy_sources(value: str) -> list[str]:
    without_flags = re.sub(r"^(?:--[\w-]+(?:=|\s+)\S+\s+)+", "", value)
    if without_flags.startswith("["):
        try:
            import json

            items = json.loads(without_flags)
            return [str(item) for item in items[:-1]] if isinstance(items, list) else []
        except (ValueError, TypeError):
            return []
    try:
        parts = shlex.split(without_flags)
    except ValueError:
        parts = without_flags.split()
    return parts[:-1]


def parse_dockerfile(source: str) -> dict[str, Any]:
    """Parse Dockerfile instructions without invoking a Dockerfile frontend."""
    if not source.strip():
        raise DockerfileInputError("input is empty")
    instructions = _logical_instructions(source)
    if not instructions or not any(name == "FROM" for _, name, _ in instructions):
        raise DockerfileInputError("Dockerfile must contain a FROM instruction")

    changes: list[dict[str, Any]] = []
    if syntax := _SYNTAX.search(source):
        changes.append(
            _change("frontend", syntax.group("frontend"), syntax.group("frontend"), 1)
        )

    stages: set[str] = set()
    current_stage = "stage-0"
    stage_index = -1
    stage_users: dict[str, str | None] = {}
    stage_lines: dict[str, int] = {}
    seen_from = False
    for line_number, name, value in instructions:
        if not seen_from and name not in {"ARG", "FROM"}:
            changes.append(_change("pre_from", name, value, line_number))
            continue
        if name == "FROM":
            seen_from = True
            match = _FROM.match(value)
            if not match:
                changes.append(_change("base_image", value, value, line_number))
                continue
            stage_index += 1
            image = match.group("image")
            alias = match.group("stage")
            current_stage = alias or f"stage-{stage_index}"
            internal = image.lower() in stages
            changes.append(
                _change(
                    "base_image",
                    image,
                    value,
                    line_number,
                    Internal=internal,
                )
            )
            stages.add(current_stage.lower())
            stage_users[current_stage] = None
            stage_lines[current_stage] = line_number
            continue

        if name == "USER":
            stage_users[current_stage] = value
        kind = name.lower() if name in _KNOWN else "unknown_instruction"
        metadata: dict[str, Any] = {"Stage": current_stage}
        if name in {"COPY", "ADD"}:
            from_match = re.search(r"--from=(?P<source>\S+)", value)
            if from_match:
                source_stage = from_match.group("source")
                external = source_stage.lower() not in stages
                metadata["ExternalFrom"] = source_stage if external else ""
                metadata["MutableFrom"] = external and "@sha256:" not in source_stage
        changes.append(_change(kind, name, value, line_number, **metadata))

    if stage_users:
        final_stage = next(reversed(stage_users))
        final_user = stage_users[final_stage]
        changes.append(
            _change(
                "runtime_user",
                final_user or "inherited/default",
                final_user or "",
                stage_lines[final_stage],
            )
        )
    changes.append(
        _change(
            "context_boundary",
            "build context and .dockerignore",
            "",
            1,
        )
    )
    return {"dockerfile": {"changes": changes}}


class DockerfileAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "dockerfile"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        document = input_data.get("dockerfile")
        return isinstance(document, dict) and isinstance(document.get("changes"), list)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        return list(input_data["dockerfile"]["changes"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        kind = str(raw.get("Kind") or "unknown")
        name = str(raw.get("Name") or "unknown")
        value = str(raw.get("Value") or "")
        risk = "review"
        explanation = f"Dockerfile instruction '{name}' requires review."

        if kind == "base_image":
            internal = bool(raw.get("Internal"))
            if name.lower() == "scratch":
                risk = "safe"
                explanation = "The build stage starts from Docker's empty scratch base."
            elif internal:
                explanation = f"Build stage reuses local stage '{name}'."
            elif "@sha256:" in name.lower():
                explanation = f"Base image '{name}' is digest-pinned; verify its provenance."
            else:
                risk = "dangerous"
                explanation = (
                    f"Base image '{name}' is mutable or unresolved; pin an approved "
                    "image digest."
                )
        elif kind == "run":
            risk = "dangerous"
            explanation = "RUN executes build-time commands with builder and network access."
            if "--mount=type=secret" in value or "--mount=type=ssh" in value:
                explanation += (
                    " BuildKit mounts sensitive credentials temporarily; verify their "
                    "scope and command output."
                )
            if "--security=insecure" in value or "--network=host" in value or "--device=" in value:
                explanation += " The instruction requests an elevated BuildKit entitlement."
        elif kind in {"arg", "env"}:
            key, assigned = _split_key_value(value)
            if _SECRET_NAME.search(key):
                risk = "dangerous"
                explanation = (
                    f"{kind.upper()} '{key}' appears secret-bearing and may leak "
                    "through image metadata, history, or provenance."
                )
            elif kind == "env":
                explanation = (
                    f"ENV '{key}' persists in the resulting image and runtime "
                    "environment."
                )
            else:
                risk = "safe" if assigned else "review"
                explanation = (
                    f"ARG '{key}' controls later build instructions; verify supplied "
                    "values and reproducibility."
                )
        elif kind in {"copy", "add"}:
            sources = _copy_sources(value)
            sensitive = any(_SENSITIVE_SOURCE.search(source) for source in sources)
            remote = kind == "add" and any(_REMOTE_SOURCE.search(source) for source in sources)
            mutable_from = bool(raw.get("MutableFrom"))
            risk = "dangerous" if sensitive or remote or mutable_from else "review"
            explanation = (
                f"{kind.upper()} imports files into an image layer; verify source, "
                "ownership, permissions, and .dockerignore coverage."
            )
            if sensitive:
                explanation += (
                    " A source path appears to contain credentials or repository "
                    "metadata."
                )
            if remote:
                explanation += " Remote ADD fetches mutable external content during the build."
            if mutable_from:
                explanation += (
                    f" External source '{raw['ExternalFrom']}' is not digest-pinned."
                )
        elif kind == "user":
            root = value.split(":", 1)[0].strip().lower() in {"0", "root", "administrator"}
            risk = "dangerous" if root else "review"
            explanation = f"USER sets subsequent build and runtime identity to '{value}'."
        elif kind == "runtime_user":
            root = not value or value.split(":", 1)[0].strip().lower() in {
                "0",
                "root",
                "administrator",
            }
            risk = "dangerous" if root else "review"
            explanation = (
                "Final image has no explicit non-root USER and may run as root."
                if root
                else f"Final image declares runtime USER '{value}'; verify its UID and permissions."
            )
        elif kind in {"cmd", "entrypoint"}:
            shell_form = not value.lstrip().startswith("[")
            risk = "dangerous" if shell_form else "review"
            explanation = f"{kind.upper()} defines the container process."
            if shell_form:
                explanation += " Shell form can impair signal handling and expands through a shell."
        elif kind == "healthcheck":
            risk = "dangerous" if value.upper() == "NONE" else "review"
            explanation = "HEALTHCHECK disables or executes runtime health detection."
        elif kind == "onbuild":
            risk = "dangerous"
            explanation = (
                "ONBUILD defers an instruction that executes when downstream images "
                "use this image."
            )
        elif kind == "stopsignal":
            risk = "dangerous" if value.upper() in {"9", "SIGKILL"} else "review"
            explanation = f"STOPSIGNAL changes container shutdown behavior to '{value}'."
        elif kind == "workdir":
            relative = not value.startswith(("/", "\\")) and not re.match(r"^[A-Za-z]:[/\\]", value)
            risk = "dangerous" if relative else "review"
            explanation = f"WORKDIR changes the instruction and runtime directory to '{value}'."
            if relative:
                explanation += " Relative paths can depend on mutable base-image state."
        elif kind == "frontend":
            risk = "safe" if "@sha256:" in name.lower() else "review"
            explanation = (
                "Dockerfile syntax selects external frontend behavior; pin custom "
                "frontends immutably."
            )
        elif kind == "pre_from":
            risk = "dangerous"
            explanation = (
                f"Instruction '{name}' appears before the first FROM and is invalid "
                "or frontend-dependent."
            )
        elif kind == "unknown_instruction":
            explanation = (
                f"Unknown Dockerfile instruction '{name}' may depend on a custom "
                "frontend."
            )
        elif kind == "context_boundary":
            explanation = (
                "Static Dockerfile analysis cannot see the build context, .dockerignore "
                "exclusions, build arguments, or builder entitlements."
            )
        elif kind == "label":
            key, _ = _split_key_value(value)
            risk = "dangerous" if _SECRET_NAME.search(key) else "safe"
            explanation = "LABEL records metadata that persists in the image."
            if risk == "dangerous":
                explanation += " The label name appears secret-bearing."
        elif kind == "maintainer":
            risk = "safe"
            explanation = "MAINTAINER records deprecated image author metadata."
        elif kind in {"expose", "volume", "shell"}:
            explanation = f"{kind.upper()} changes image runtime or command-execution metadata."

        return ResourceChange(
            address=str(raw.get("Address") or name),
            resource_type=f"dockerfile_{kind}",
            actions=("execute",),
            risk=risk,
            explanation=explanation,
        )


def analyze_dockerfile(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = DockerfileAdapter().analyze(data, tool_name="Dockerfile")
    summary = PlanSummary(
        path=Path("dockerfile://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Dockerfile")
    gate["adapter"] = "dockerfile"
    gate["total_changes"] = len(changes)
    return gate
