from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_STEP_PATTERNS = (
    ("with_credentials", re.compile(r"\bwithCredentials\s*\(")),
    ("powershell", re.compile(r"\bpowershell\s*(?:\(|['\"])")),
    ("shell", re.compile(r"\bsh\s*(?:\(|['\"])")),
    ("batch", re.compile(r"\bbat\s*(?:\(|['\"])")),
    ("delete_dir", re.compile(r"\bdeleteDir\s*\(")),
    ("input", re.compile(r"\binput\s*(?:\(|message\s*:)") ),
    ("downstream_build", re.compile(r"\bbuild\s+(?:job\s*:|\()")),
    ("checkout", re.compile(r"\b(?:checkout|git)\s*(?:\(|url\s*:)") ),
    ("archive", re.compile(r"\b(?:archiveArtifacts|junit)\s*(?:\(|artifacts\s*:)") ),
    ("echo", re.compile(r"\becho\s+(?:\(|['\"])")),
)

_DANGEROUS_STEPS = {"batch", "delete_dir", "powershell", "shell", "with_credentials"}
_SAFE_STEPS = {"archive", "echo"}


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
        source = str(input_data.get("jenkinsfile", ""))
        changes: list[dict[str, Any]] = []
        for line_number, line in enumerate(source.splitlines(), start=1):
            code = line.split("//", 1)[0].strip()
            if not code:
                continue
            for step, pattern in _STEP_PATTERNS:
                if pattern.search(code):
                    changes.append(
                        {"Step": step, "Address": f"Jenkinsfile:{line_number}", "Source": code}
                    )
                    break
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
        risk = "review"
        explanation = f"Jenkins step '{step}' affects pipeline execution and requires review."
        if step in _DANGEROUS_STEPS:
            risk = "dangerous"
            explanation = (
                f"Jenkins step '{step}' can execute commands, delete state, "
                "or expose credentials."
            )
        elif step in _SAFE_STEPS:
            risk = "safe"
            explanation = f"Jenkins step '{step}' records output without changing infrastructure."
        elif step == "unparsed_pipeline":
            explanation = (
                "Jenkins pipeline syntax was recognized, but no supported steps were found; "
                "manual review is required."
            )

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
