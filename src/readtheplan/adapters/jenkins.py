from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_STEP_PATTERNS = (
    ("shared_library", re.compile(r"(?:@Library\s*\(|\blibrary\s*(?:\(|['\"]))")),
    ("load_groovy", re.compile(r"\bload\s*(?:\(|['\"])")),
    ("evaluate_groovy", re.compile(r"\bevaluate\s*\(")),
    ("script_block", re.compile(r"\bscript\s*\{")),
    ("with_credentials", re.compile(r"\bwithCredentials\s*\(")),
    ("ssh_agent", re.compile(r"\bsshagent\s*\(")),
    ("credentials", re.compile(r"\bcredentials\s*\(")),
    ("kubernetes_agent", re.compile(r"\b(?:kubernetes|podTemplate)\s*(?:\{|\()")),
    ("docker_agent", re.compile(r"\bagent\s*\{\s*docker(?:file)?\b")),
    ("container_image", re.compile(r"\bimage\s+['\"][^'\"]+['\"]")),
    ("agent_args", re.compile(r"\bargs\s+['\"][^'\"]+['\"]")),
    ("powershell", re.compile(r"\bpowershell\s*(?:\(|['\"])")),
    ("pwsh", re.compile(r"\bpwsh\s*(?:\(|['\"])")),
    ("shell", re.compile(r"\bsh\s*(?:\(|['\"])")),
    ("batch", re.compile(r"\bbat\s*(?:\(|['\"])")),
    ("delete_dir", re.compile(r"\bdeleteDir\s*\(")),
    ("clean_workspace", re.compile(r"\bcleanWs\s*\(")),
    ("write_file", re.compile(r"\bwriteFile\s*(?:\(|\s)")),
    ("http_request", re.compile(r"\bhttpRequest\s*(?:\(|\s)")),
    ("input", re.compile(r"\binput\s*(?:\(|message\s*:)")),
    ("downstream_build", re.compile(r"\bbuild\s+(?:job\s*:|\()")),
    ("checkout", re.compile(r"\b(?:checkout\s+(?:scm|\()|git\s*(?:\(|url\s*:))")),
    ("trigger", re.compile(r"\b(?:cron|pollSCM|upstream)\s*\(")),
    ("parallel", re.compile(r"\bparallel\s*(?:\(|\{)")),
    ("retry", re.compile(r"\bretry\s*\(")),
    ("timeout", re.compile(r"\btimeout\s*\(")),
    ("stash", re.compile(r"\b(?:stash|unstash)\s*(?:\(|\s)")),
    ("archive", re.compile(r"\barchiveArtifacts\s*(?:\(|artifacts\s*:)")),
    ("junit", re.compile(r"\bjunit\s*(?:\(|['\"])")),
    ("echo", re.compile(r"\becho\s+(?:\(|['\"])")),
)

_DANGEROUS_STEPS = {
    "agent_args",
    "batch",
    "clean_workspace",
    "credentials",
    "delete_dir",
    "evaluate_groovy",
    "kubernetes_agent",
    "load_groovy",
    "powershell",
    "pwsh",
    "script_block",
    "shell",
    "ssh_agent",
    "with_credentials",
}
_SAFE_STEPS = {"archive", "echo", "junit"}
_MUTABLE_IMAGE = re.compile(r"\bimage\s+['\"](?P<image>[^'\"]+)['\"]")
_SHARED_LIBRARY_REF = re.compile(r"@Library\s*\(\s*['\"](?P<ref>[^'\"]+)['\"]")


def _strip_comments(source: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    block_comment = False
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if block_comment:
            if char == "*" and following == "/":
                block_comment = False
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
            block_comment = True
            index += 2
            continue
        if char == "/" and following == "/":
            while index < len(source) and source[index] != "\n":
                index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


class JenkinsAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "jenkins"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        source = input_data.get("jenkinsfile")
        return isinstance(source, str) and bool(
            re.search(r"\b(?:pipeline\s*\{|node\s*\(|stages\s*\{)", source)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        source = _strip_comments(str(input_data.get("jenkinsfile", "")))
        changes: list[dict[str, Any]] = []
        for line_number, line in enumerate(source.splitlines(), start=1):
            code = line.strip()
            if not code:
                continue
            for step, pattern in _STEP_PATTERNS:
                if pattern.search(code):
                    changes.append(
                        {"Step": step, "Address": f"Jenkinsfile:{line_number}", "Source": code}
                    )
        if source.strip() and not changes:
            changes.append(
                {
                    "Step": "unparsed_pipeline",
                    "Address": "Jenkinsfile",
                    "Source": "Pipeline contains no recognized built-in steps.",
                }
            )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        step = str(raw.get("Step", "unknown"))
        source = str(raw.get("Source", ""))
        risk = "review"
        explanation = f"Jenkins step '{step}' affects pipeline execution and requires review."
        if step in _DANGEROUS_STEPS:
            risk = "dangerous"
            if step in {
                "batch",
                "evaluate_groovy",
                "load_groovy",
                "powershell",
                "pwsh",
                "script_block",
                "shell",
            }:
                explanation = f"Jenkins step '{step}' can execute arbitrary build-agent code."
            elif step in {"credentials", "ssh_agent", "with_credentials"}:
                explanation = (
                    f"Jenkins step '{step}' exposes managed credentials to pipeline code or "
                    "agent processes."
                )
            elif step in {"clean_workspace", "delete_dir"}:
                explanation = f"Jenkins step '{step}' deletes workspace state and artifacts."
            else:
                explanation = (
                    f"Jenkins step '{step}' can give an ephemeral build agent host-level "
                    "or cluster-level access."
                )
        elif step in _SAFE_STEPS:
            risk = "safe"
            explanation = f"Jenkins step '{step}' records output without changing infrastructure."
        elif step == "unparsed_pipeline":
            explanation = (
                "Jenkins pipeline syntax was recognized, but no supported steps were found; "
                "manual review is required."
            )
        elif step == "container_image":
            match = _MUTABLE_IMAGE.search(source)
            image = match.group("image") if match else "<dynamic>"
            if "@sha256:" not in image:
                risk = "dangerous"
                explanation = (
                    f"Jenkins agent image '{image}' is not pinned by digest; mutable build "
                    "environments can change pipeline behavior."
                )
        elif step == "shared_library":
            explanation = (
                "Jenkins loads a shared Pipeline library whose external Groovy code is not "
                "expanded in this Jenkinsfile; review source trust and version pinning."
            )
            match = _SHARED_LIBRARY_REF.search(source)
            reference = match.group("ref") if match else ""
            version = reference.rsplit("@", 1)[-1] if "@" in reference else ""
            if not version or version.lower() in {"main", "master", "latest", "head"}:
                risk = "dangerous"
                explanation += " The selected library version is mutable or implicit."
        elif step == "trigger":
            explanation = (
                "Jenkins automatically triggers this pipeline from a schedule, SCM polling, "
                "or an upstream job; review deployment gates and concurrency."
            )
        elif step in {"checkout", "http_request", "stash", "write_file"}:
            explanation = (
                f"Jenkins step '{step}' moves code, data, or artifacts across a trust "
                "boundary; review destinations, credentials, integrity, and retention."
            )

        if step == "agent_args" and not any(
            token in source
            for token in ("--privileged", "/var/run/docker.sock", "--device", "--network=host")
        ):
            risk = "review"
            explanation = "Jenkins passes runtime arguments to a build agent; review host access."

        return ResourceChange(
            address=str(raw.get("Address", "Jenkinsfile")),
            resource_type=f"jenkins_{step}",
            actions=("execute",),
            risk=risk,
            explanation=explanation,
        )


def analyze_jenkins(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = JenkinsAdapter().analyze(data, tool_name="Jenkins")
    summary = PlanSummary(
        path=Path("jenkins://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    return agent_gate_to_dict(summary, catalog=catalog, tool_name="Jenkins")
