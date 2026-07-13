from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_TEAMCITY_SIGNATURE = re.compile(
    r"(?:jetbrains\.buildServer\.configs\.kotlin|\bBuildType\s*\(|\bproject\s*\{)",
    re.IGNORECASE,
)
_SENSITIVE_NAME = re.compile(
    r"(?:^|[._-])(?:api[._-]?key|credential|passwd|password|private[._-]?key|secret|token)"
    r"(?:$|[._-])",
    re.IGNORECASE,
)
_QUOTED_ASSIGNMENT = re.compile(r"\b(?:image|imageName)\s*=\s*['\"](?P<value>[^'\"]+)")


def _strip_kotlin_comments(source: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    block = False
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if block:
            if char == "*" and following == "/":
                block = False
                index += 2
                continue
            if char == "\n":
                output.append(char)
            index += 1
            continue
        if quote:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            output.append(char)
            index += 1
            continue
        if char == "/" and following == "*":
            block = True
            index += 2
            continue
        if char == "/" and following == "/":
            while index < len(source) and source[index] != "\n":
                index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


class TeamCityAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "teamcity"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        source = input_data.get("teamcity")
        return isinstance(source, str) and _TEAMCITY_SIGNATURE.search(source) is not None

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        source = _strip_kotlin_comments(str(input_data.get("teamcity", "")))
        changes: list[dict[str, Any]] = []
        for line_number, raw_line in enumerate(source.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            address = f"teamcity:{line_number}"
            self._line_changes(line, address, changes)
        if not changes:
            changes.append(
                self._change(
                    "teamcity",
                    "unresolved",
                    "review",
                    "TeamCity Kotlin DSL was recognized but contains no supported settings.",
                )
            )
        changes.append(
            self._change(
                "teamcity.effective_configuration",
                "effective_configuration",
                "review",
                "TeamCity execution also depends on project permissions, agent capabilities, "
                "server plugins, secure parameters, templates, and generated DSL settings.",
            )
        )
        return changes

    def _line_changes(
        self, line: str, address: str, changes: list[dict[str, Any]]
    ) -> None:
        if re.search(
            r"\b(?:ProcessBuilder\s*\(|Runtime\.getRuntime\s*\(\)\.exec|"
            r"ScriptEngineManager\s*\(|URLClassLoader\s*\()",
            line,
        ):
            changes.append(
                self._change(
                    address,
                    "dsl_execution",
                    "dangerous",
                    "TeamCity Kotlin DSL invokes host-side code while settings are generated; "
                    "this can affect the server before any build starts.",
                )
            )
        if re.search(r"\b(?:File|Path)\s*\(|\.readText\s*\(|\.writeText\s*\(", line):
            changes.append(
                self._change(
                    address,
                    "dsl_file_access",
                    "dangerous",
                    "TeamCity Kotlin DSL reads or writes files during settings generation; "
                    "verify paths, repository trust, and server-side data exposure.",
                )
            )
        if re.search(
            r"\b(?:scriptContent\s*=|commandLine\s*\{|powerShell\s*\{|"
            r"python\s*\{|kotlinScript\s*\{|exec\s*\{)",
            line,
            re.IGNORECASE,
        ):
            changes.append(
                self._change(
                    address,
                    "command",
                    "dangerous",
                    "TeamCity build step executes arbitrary code on a build agent.",
                )
            )
        if re.search(r"\b(?:sshExec|sshAgent)\s*\{", line, re.IGNORECASE):
            changes.append(
                self._change(
                    address,
                    "ssh",
                    "dangerous",
                    "TeamCity step executes remotely or exposes SSH credentials to an agent.",
                )
            )
        if re.search(
            r"\b(?:password|remote|credentials)\s*\(|credentialsJSON:", line, re.IGNORECASE
        ) or self._sensitive_parameter(line):
            changes.append(
                self._change(
                    address,
                    "secret_input",
                    "dangerous",
                    "TeamCity configuration introduces credential material or a sensitive "
                    "parameter; verify tokenization, scope, access controls, and log masking.",
                )
            )
        if re.search(r"\b(?:GitVcsRoot|root\s*\()", line):
            changes.append(
                self._change(
                    address,
                    "vcs_root",
                    "review",
                    "TeamCity VCS root imports source and may use repository credentials; "
                    "review URL, branch rules, checkout mode, and authentication.",
                )
            )
        if re.search(r"\bauthMethod\s*=", line):
            changes.append(
                self._change(
                    address,
                    "vcs_authentication",
                    "dangerous",
                    "TeamCity VCS authentication changes credential and host trust boundaries.",
                )
            )
        if re.search(r"\btriggers\s*\{|\b(?:schedule|finishBuild)\s*\{", line):
            changes.append(
                self._change(
                    address,
                    "trigger",
                    "review",
                    "TeamCity trigger changes which commits, schedules, or upstream builds run.",
                )
            )
        if re.search(r"\bdependencies\s*\{|\b(?:snapshot|artifacts)\s*\(", line):
            changes.append(
                self._change(
                    address,
                    "dependency",
                    "review",
                    "TeamCity dependency imports artifacts or controls build-chain execution.",
                )
            )
        if re.search(r"\brequirements\s*\{|\b(?:equals|contains|matches)\s*\(", line):
            changes.append(
                self._change(
                    address,
                    "agent_requirement",
                    "review",
                    "TeamCity agent requirement selects workers and their network or host access.",
                )
            )
        if re.search(
            r"\b(?:commitStatusPublisher|pullRequests|dockerRegistryConnections|"
            r"hashiCorpVault|awsConnection|kubernetesExecutor)\s*\{",
            line,
            re.IGNORECASE,
        ):
            changes.append(
                self._change(
                    address,
                    "external_integration",
                    "dangerous",
                    "TeamCity feature connects builds to an external service or execution "
                    "backend; verify permissions and credential scope.",
                )
            )
        if re.search(r"\b(?:swabra|freeDiskSpace)\s*\{", line, re.IGNORECASE):
            changes.append(
                self._change(
                    address,
                    "cleanup",
                    "dangerous",
                    "TeamCity cleanup feature can remove workspace or agent files.",
                )
            )
        image_match = _QUOTED_ASSIGNMENT.search(line)
        if image_match:
            image = image_match.group("value")
            changes.append(
                self._change(
                    address,
                    "image",
                    "review" if "@sha256:" in image.lower() else "dangerous",
                    "TeamCity container image executes build code; pin a trusted digest and "
                    "review registry authentication.",
                )
            )
        if re.search(r"\b(?:artifactRules|publishArtifacts)\s*=", line):
            changes.append(
                self._change(
                    address,
                    "artifact",
                    "review",
                    "TeamCity artifact rules move build output across retention and trust "
                    "boundaries.",
                )
            )

    def _sensitive_parameter(self, line: str) -> bool:
        match = re.search(r"\b(?:param|text)\s*\(\s*['\"](?P<name>[^'\"]+)", line)
        return match is not None and _SENSITIVE_NAME.search(match.group("name")) is not None

    def _change(self, address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
        return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}

    def normalize_change(self, raw_change: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw_change["Address"]),
            resource_type=f"teamcity_{raw_change['Kind']}",
            actions=("execute",),
            risk=str(raw_change["Risk"]),
            explanation=str(raw_change["Explanation"]),
        )


def analyze_teamcity(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    adapter = TeamCityAdapter()
    changes = adapter.analyze(data, tool_name="TeamCity")
    summary = PlanSummary(
        path=Path("teamcity://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="TeamCity")
    gate["adapter"] = adapter.adapter_name
    gate["total_changes"] = len(changes)
    return gate
