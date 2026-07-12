from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class AtlantisInputError(ValueError):
    """Raised when YAML is not recognizable Atlantis configuration."""


_SECRET_NAME = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|credential|password|private[_-]?key|secret|token)(?:$|[_-])",
    re.IGNORECASE,
)
_REQUIREMENTS = {"approved", "mergeable", "undiverged"}


def parse_atlantis_config(source: str) -> dict[str, Any]:
    """Parse repo-level atlantis.yaml or server-side repos.yaml."""
    if not source.strip():
        raise AtlantisInputError("input is empty")
    try:
        parsed = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise AtlantisInputError(str(exc)) from exc
    if not isinstance(parsed, dict):
        raise AtlantisInputError("Atlantis configuration must be a YAML object")
    projects = parsed.get("projects")
    repos = parsed.get("repos")
    if isinstance(projects, list) or "version" in parsed:
        config_type = "repo"
        if not isinstance(projects, list):
            raise AtlantisInputError("repo-level configuration must contain a projects list")
    elif isinstance(repos, list):
        config_type = "server"
    else:
        raise AtlantisInputError(
            "expected repo-level projects/version or server-side repos configuration"
        )
    return {"atlantis_config": {"config_type": config_type, "document": parsed}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class AtlantisAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "atlantis"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("atlantis_config")
        return (
            isinstance(config, dict)
            and config.get("config_type") in {"repo", "server"}
            and isinstance(config.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        config = input_data["atlantis_config"]
        document = config["document"]
        changes = (
            self._repo_config(document)
            if config["config_type"] == "repo"
            else self._server_config(document)
        )
        changes.append(
            _change(
                "atlantis.effective_configuration",
                "effective_configuration",
                "review",
                "Effective Atlantis behavior combines repo YAML, last-match server-side repo "
                "rules, flags/environment, VCS permissions, hooks, and server credentials.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"atlantis_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )

    def _repo_config(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        version = document.get("version")
        changes.append(
            _change(
                "version",
                "schema_version",
                "safe" if version == 3 else "review",
                "Atlantis repo configuration schema version should be explicitly supported.",
            )
        )
        parallel_apply = document.get("parallel_apply", False)
        parallel_plan = document.get("parallel_plan", False)
        if parallel_apply:
            changes.append(
                _change(
                    "parallel_apply",
                    "parallel_apply",
                    "dangerous",
                    "Parallel applies can concurrently mutate dependent infrastructure states.",
                )
            )
        if parallel_plan:
            changes.append(
                _change(
                    "parallel_plan",
                    "parallel_plan",
                    "review",
                    "Parallel plans increase provider/API concurrency across projects.",
                )
            )
        abort = document.get("abort_on_execution_order_fail")
        if abort is not None:
            changes.append(
                _change(
                    "abort_on_execution_order_fail",
                    "execution_failure_policy",
                    "safe" if abort is True else "dangerous",
                    "Execution-order failure policy controls whether later project groups "
                    "continue.",
                )
            )
        for index, project in enumerate(document.get("projects", [])):
            address = f"projects[{index}]"
            if not isinstance(project, dict):
                changes.append(
                    _change(address, "unresolved", "review", "Atlantis project is not an object.")
                )
                continue
            changes.extend(self._project(project, address))
        changes.extend(self._workflows(document.get("workflows"), "workflows", repo_defined=True))
        return changes

    def _project(self, project: dict[str, Any], address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        directory = project.get("dir")
        if directory is None:
            changes.append(
                _change(
                    f"{address}.dir",
                    "unresolved",
                    "review",
                    "Atlantis project has no explicit Terraform working directory.",
                )
            )
        else:
            outside = str(directory).startswith(("/", ".."))
            changes.append(
                _change(
                    f"{address}.dir",
                    "project_directory",
                    "dangerous" if outside else "review",
                    "Project directory selects repository content used as Terraform working state.",
                )
            )
        if project.get("workspace") is not None:
            changes.append(
                _change(
                    f"{address}.workspace",
                    "workspace",
                    "review",
                    "Terraform workspace changes the state and variable context.",
                )
            )
        if project.get("terraform_version") is not None:
            changes.append(
                _change(
                    f"{address}.terraform_version",
                    "terraform_version",
                    "review",
                    "Atlantis may download and execute the selected Terraform version.",
                )
            )
        for key in ("plan_requirements", "apply_requirements", "import_requirements"):
            requirements = {str(item) for item in _as_list(project.get(key))}
            if key not in project:
                risk = "review"
                explanation = f"{key} is inherited from server-side configuration."
            else:
                invalid = requirements - _REQUIREMENTS
                required = {"approved", "mergeable", "undiverged"}
                risk = "safe" if required <= requirements else "dangerous"
                explanation = (
                    f"{key} controls approval, mergeability, and source-divergence gates."
                )
                if invalid:
                    risk = "review"
                    explanation += f" Unknown requirements: {', '.join(sorted(invalid))}."
            changes.append(_change(f"{address}.{key}", "command_requirements", risk, explanation))
        if project.get("workflow") is not None:
            changes.append(
                _change(
                    f"{address}.workflow",
                    "workflow_selection",
                    "review",
                    "Project selects a workflow whose commands and server authorization must "
                    "match.",
                )
            )
        locks = project.get("repo_locks")
        if isinstance(locks, dict):
            mode = str(locks.get("mode") or "")
            risk = "safe" if mode == "on_plan" else "review" if mode == "on_apply" else "dangerous"
            changes.append(
                _change(
                    f"{address}.repo_locks",
                    "repo_locks",
                    risk,
                    "Repository locking prevents conflicting plan/apply operations.",
                )
            )
        autoplan = project.get("autoplan")
        if isinstance(autoplan, dict):
            enabled = autoplan.get("enabled", True)
            changes.append(
                _change(
                    f"{address}.autoplan",
                    "autoplan",
                    "review" if enabled else "dangerous",
                    "Autoplan controls whether changed infrastructure is automatically planned.",
                )
            )
        if project.get("execution_order_group") is not None:
            changes.append(
                _change(
                    f"{address}.execution_order_group",
                    "execution_order",
                    "review",
                    "Execution groups control ordering and concurrency across Terraform states.",
                )
            )
        return changes

    def _server_config(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for index, repo in enumerate(document.get("repos", [])):
            address = f"repos[{index}]"
            if not isinstance(repo, dict):
                changes.append(
                    _change(address, "unresolved", "review", "Atlantis repo rule is not an object.")
                )
                continue
            repo_id = str(repo.get("id") or "")
            wildcard = repo_id in {"/.*/", "/.*/$", ""}
            changes.append(
                _change(
                    f"{address}.id",
                    "repository_scope",
                    "dangerous" if wildcard else "review",
                    "Server-side repo rule selects repositories that inherit its permissions.",
                )
            )
            requirements = {str(item) for item in _as_list(repo.get("apply_requirements"))}
            complete_requirements = {"approved", "mergeable", "undiverged"} <= requirements
            changes.append(
                _change(
                    f"{address}.apply_requirements",
                    "command_requirements",
                    "safe" if complete_requirements else "dangerous",
                    "Server-side apply requirements are the authoritative default mutation gate.",
                )
            )
            overrides = {str(item) for item in _as_list(repo.get("allowed_overrides"))}
            if overrides:
                sensitive = overrides & {
                    "apply_requirements",
                    "plan_requirements",
                    "import_requirements",
                    "workflow",
                    "custom_policy_check",
                }
                changes.append(
                    _change(
                        f"{address}.allowed_overrides",
                        "allowed_overrides",
                        "dangerous" if sensitive else "review",
                        "Allowed overrides delegate server security controls to repository YAML.",
                    )
                )
            if repo.get("allow_custom_workflows") is not None:
                enabled = repo["allow_custom_workflows"] is True
                changes.append(
                    _change(
                        f"{address}.allow_custom_workflows",
                        "custom_workflows",
                        "dangerous" if enabled else "safe",
                        "Custom repo workflows let pull-request content define commands on the "
                        "Atlantis server.",
                    )
                )
            if repo.get("allowed_workflows") is not None:
                changes.append(
                    _change(
                        f"{address}.allowed_workflows",
                        "allowed_workflows",
                        "review",
                        "Workflow allowlist constrains server-defined executable workflows.",
                    )
                )
            if repo.get("policy_check") is not None:
                changes.append(
                    _change(
                        f"{address}.policy_check",
                        "policy_check",
                        "safe" if repo["policy_check"] is True else "dangerous",
                        "Policy checks gate infrastructure plans before apply.",
                    )
                )
        changes.extend(self._workflows(document.get("workflows"), "workflows", repo_defined=False))
        for key in ("pre_workflow_hooks", "post_workflow_hooks"):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        key,
                        "workflow_hooks",
                        "dangerous",
                        f"Atlantis {key} execute server-side commands around workflows.",
                    )
                )
        return changes

    def _workflows(
        self, workflows: Any, address: str, *, repo_defined: bool
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if not isinstance(workflows, dict):
            return changes
        for name, workflow in workflows.items():
            if not isinstance(workflow, dict):
                changes.append(
                    _change(
                        f"{address}.{name}",
                        "unresolved",
                        "review",
                        "Atlantis workflow is not an object.",
                    )
                )
                continue
            for phase in ("plan", "apply", "import", "policy_check"):
                phase_config = workflow.get(phase)
                if not isinstance(phase_config, dict):
                    continue
                for index, step in enumerate(_as_list(phase_config.get("steps"))):
                    step_address = f"{address}.{name}.{phase}.steps[{index}]"
                    if isinstance(step, str):
                        risk = "dangerous" if step in {"apply", "import"} else "review"
                        changes.append(
                            _change(
                                step_address,
                                "workflow_step",
                                risk,
                                f"Atlantis built-in {step} step executes in the server context.",
                            )
                        )
                    elif isinstance(step, dict):
                        changes.extend(
                            self._workflow_step(step, step_address, repo_defined=repo_defined)
                        )
                    else:
                        changes.append(
                            _change(
                                step_address,
                                "unresolved",
                                "review",
                                "Atlantis workflow step requires manual review.",
                            )
                        )
        return changes

    def _workflow_step(
        self, step: dict[str, Any], address: str, *, repo_defined: bool
    ) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if "run" in step:
            changes.append(
                _change(
                    f"{address}.run",
                    "custom_command",
                    "dangerous",
                    "Custom workflow runs arbitrary commands with Atlantis server access and "
                    "credentials."
                    + (" Command is controlled by repository content." if repo_defined else ""),
                )
            )
        env = step.get("env")
        if isinstance(env, dict):
            name = str(env.get("name") or "")
            command = env.get("command")
            risk = "dangerous" if command is not None or _SECRET_NAME.search(name) else "review"
            changes.append(
                _change(
                    f"{address}.env",
                    "environment",
                    risk,
                    "Workflow environment can inject static values or command output into later "
                    "Terraform steps.",
                )
            )
        for built_in in ("init", "plan", "apply", "import", "policy_check"):
            if built_in in step:
                risk = "dangerous" if built_in in {"apply", "import"} else "review"
                changes.append(
                    _change(
                        f"{address}.{built_in}",
                        "workflow_step",
                        risk,
                        f"Atlantis {built_in} step may include extra arguments and server-side "
                        "execution context.",
                    )
                )
        return changes


def analyze_atlantis(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = AtlantisAdapter().analyze(data, tool_name="Atlantis")
    summary = PlanSummary(
        path=Path("atlantis://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Atlantis")
    gate["adapter"] = "atlantis"
    gate["total_changes"] = len(changes)
    return gate
