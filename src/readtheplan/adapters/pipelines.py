from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class PipelineInputError(ValueError):
    """Raised when CI workflow YAML is invalid or has the wrong shape."""


_SHA_REF = re.compile(r"^[0-9a-fA-F]{40}$")
_GITLAB_GLOBAL_KEYS = {
    "before_script",
    "cache",
    "default",
    "include",
    "image",
    "services",
    "spec",
    "stages",
    "types",
    "variables",
    "workflow",
}


def parse_pipeline_yaml(source: str, ecosystem: str) -> dict[str, Any]:
    """Parse one CI configuration without YAML 1.1's ``on`` boolean coercion."""
    if not source.strip():
        raise PipelineInputError("input is empty")

    class WorkflowLoader(yaml.SafeLoader):
        pass

    WorkflowLoader.yaml_implicit_resolvers = {
        key: list(value) for key, value in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    for first_char, resolvers in list(WorkflowLoader.yaml_implicit_resolvers.items()):
        WorkflowLoader.yaml_implicit_resolvers[first_char] = [
            (tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"
        ]
    WorkflowLoader.add_implicit_resolver(
        "tag:yaml.org,2002:bool",
        re.compile(r"^(?:true|false)$", re.IGNORECASE),
        list("tTfF"),
    )
    try:
        parsed = yaml.load(source, Loader=WorkflowLoader)
    except yaml.YAMLError as exc:
        raise PipelineInputError(str(exc)) from exc
    if not isinstance(parsed, dict):
        raise PipelineInputError("pipeline YAML must be an object")

    wrappers = {
        "github-actions": "github_actions",
        "gitlab-ci": "gitlab_ci",
        "circleci": "circleci",
    }
    try:
        wrapper = wrappers[ecosystem]
    except KeyError as exc:
        raise PipelineInputError(f"unsupported pipeline ecosystem: {ecosystem}") from exc
    return {wrapper: parsed}


def _contains_secret(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_secret(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    text = str(value).lower()
    return "secrets." in text or "ci_job_token" in text or "circle_oidc_token" in text


def _is_full_sha_reference(reference: str) -> bool:
    _, separator, ref = reference.rpartition("@")
    return bool(separator and _SHA_REF.fullmatch(ref))


def _is_digest_pinned_image(reference: Any) -> bool:
    if isinstance(reference, dict):
        reference = reference.get("name") or reference.get("image") or ""
    return "@sha256:" in str(reference).lower()


def _change(
    address: str,
    kind: str,
    risk: str,
    explanation: str,
) -> dict[str, str]:
    return {
        "Address": address,
        "Kind": kind,
        "Risk": risk,
        "Explanation": explanation,
    }


class _PipelineAdapter(BaseAdapter):
    wrapper_key = ""
    tool_name = "CI pipeline"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        return isinstance(input_data.get(self.wrapper_key), dict)

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"{self.adapter_name.replace('-', '_')}_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


class GitHubActionsAdapter(_PipelineAdapter):
    wrapper_key = "github_actions"
    tool_name = "GitHub Actions"

    @property
    def adapter_name(self) -> str:
        return "github-actions"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        workflow = input_data[self.wrapper_key]
        changes = [self._permissions("workflow.permissions", workflow.get("permissions"))]
        jobs = workflow.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            return changes + [
                _change(
                    "workflow.jobs",
                    "unresolved",
                    "review",
                    "GitHub Actions workflow has no statically analyzable jobs; "
                    "review reusable or generated configuration.",
                )
            ]
        for job_name, raw_job in jobs.items():
            if not isinstance(raw_job, dict):
                changes.append(
                    _change(
                        f"jobs.{job_name}",
                        "unresolved",
                        "review",
                        "GitHub Actions job is not an object and requires manual review.",
                    )
                )
                continue
            if "permissions" in raw_job:
                changes.append(
                    self._permissions(f"jobs.{job_name}.permissions", raw_job["permissions"])
                )
            if raw_job.get("environment") is not None:
                changes.append(
                    _change(
                        f"jobs.{job_name}.environment",
                        "environment",
                        "review",
                        "GitHub Actions job targets a deployment environment; "
                        "verify protection rules and approvers.",
                    )
                )
            reusable = raw_job.get("uses")
            if isinstance(reusable, str):
                risk = (
                    "review"
                    if reusable.startswith("./") or _is_full_sha_reference(reusable)
                    else "dangerous"
                )
                changes.append(
                    _change(
                        f"jobs.{job_name}.uses",
                        "reusable_workflow",
                        risk,
                        "Reusable workflow executes external pipeline code; require "
                        "a trusted source and immutable commit reference.",
                    )
                )
            steps = raw_job.get("steps", [])
            if not isinstance(steps, list):
                changes.append(
                    _change(
                        f"jobs.{job_name}.steps",
                        "unresolved",
                        "review",
                        "GitHub Actions steps are generated or malformed and "
                        "require manual review.",
                    )
                )
                continue
            for index, step in enumerate(steps):
                address = f"jobs.{job_name}.steps[{index}]"
                if not isinstance(step, dict):
                    changes.append(
                        _change(
                            address,
                            "unresolved",
                            "review",
                            "GitHub Actions step is not an object and requires manual review.",
                        )
                    )
                    continue
                if "run" in step:
                    changes.append(
                        _change(
                            address,
                            "run",
                            "dangerous",
                            "GitHub Actions run step executes arbitrary commands on the runner.",
                        )
                    )
                elif isinstance(step.get("uses"), str):
                    action = step["uses"]
                    local = action.startswith("./")
                    pinned = _is_full_sha_reference(action) or (
                        action.startswith("docker://") and _is_digest_pinned_image(action)
                    )
                    risk = "review" if local or pinned else "dangerous"
                    changes.append(
                        _change(
                            address,
                            "action",
                            risk,
                            "GitHub Action executes reusable code; verify its source "
                            "and pin third-party actions to a full commit SHA.",
                        )
                    )
                else:
                    changes.append(
                        _change(
                            address,
                            "unresolved",
                            "review",
                            "GitHub Actions step has no recognized run or uses directive.",
                        )
                    )
                if _contains_secret(step):
                    changes.append(
                        _change(
                            f"{address}.secrets",
                            "secret_input",
                            "dangerous",
                            "GitHub Actions step receives secret material; verify the "
                            "callee, log handling, and least-privilege exposure.",
                        )
                    )
        return changes

    def _permissions(self, address: str, permissions: Any) -> dict[str, str]:
        if permissions is None:
            return _change(
                address,
                "permissions",
                "review",
                "GITHUB_TOKEN permissions inherit repository defaults; declare "
                "an explicit least-privilege policy.",
            )
        read_only = isinstance(permissions, dict) and all(
            str(value).lower() in {"read", "none"} for value in permissions.values()
        )
        if permissions == {} or str(permissions).lower() == "read-all" or read_only:
            return _change(
                address,
                "permissions",
                "safe",
                "GITHUB_TOKEN permissions are disabled or read-only at this scope.",
            )
        text = str(permissions).lower()
        risk = "dangerous" if "write" in text else "review"
        return _change(
            address,
            "permissions",
            risk,
            "GITHUB_TOKEN permission scope can mutate repository or deployment "
            "state; verify every granted capability.",
        )


class GitLabCIAdapter(_PipelineAdapter):
    wrapper_key = "gitlab_ci"
    tool_name = "GitLab CI"

    @property
    def adapter_name(self) -> str:
        return "gitlab-ci"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        pipeline = input_data[self.wrapper_key]
        changes: list[dict[str, Any]] = []
        includes = pipeline.get("include", [])
        includes = includes if isinstance(includes, list) else [includes]
        for index, include in enumerate(includes):
            if not include:
                continue
            remote = isinstance(include, str) and include.startswith(("http://", "https://"))
            remote = (
                remote
                or isinstance(include, dict)
                and any(key in include for key in ("remote", "project", "component"))
            )
            pinned = isinstance(include, dict) and (
                bool(include.get("integrity"))
                or _SHA_REF.fullmatch(str(include.get("ref", ""))) is not None
            )
            risk = "dangerous" if remote and not pinned else "review"
            changes.append(
                _change(
                    f"include[{index}]",
                    "include",
                    risk,
                    "GitLab CI include imports pipeline code; require a trusted source "
                    "plus integrity or an immutable commit reference.",
                )
            )

        for job_name, raw_job in pipeline.items():
            if job_name in _GITLAB_GLOBAL_KEYS or str(job_name).startswith("."):
                continue
            if not isinstance(raw_job, dict):
                continue
            address = f"jobs.{job_name}"
            if "image" in raw_job:
                risk = "review" if _is_digest_pinned_image(raw_job["image"]) else "dangerous"
                changes.append(
                    _change(
                        f"{address}.image",
                        "image",
                        risk,
                        "GitLab CI job image executes pipeline code; pin the image "
                        "to a trusted digest.",
                    )
                )
            if "script" in raw_job or "run" in raw_job:
                changes.append(
                    _change(
                        f"{address}.script",
                        "script",
                        "dangerous",
                        "GitLab CI job executes arbitrary runner commands.",
                    )
                )
            if "trigger" in raw_job:
                changes.append(
                    _change(
                        f"{address}.trigger",
                        "trigger",
                        "review",
                        "GitLab CI job starts a downstream pipeline; verify project, "
                        "ref, inputs, and forwarded variables.",
                    )
                )
            if "environment" in raw_job:
                changes.append(
                    _change(
                        f"{address}.environment",
                        "environment",
                        "review",
                        "GitLab CI job targets a deployment environment; verify "
                        "protected environments and approvals.",
                    )
                )
            if "secrets" in raw_job or "id_tokens" in raw_job or _contains_secret(raw_job):
                changes.append(
                    _change(
                        f"{address}.secrets",
                        "secret_input",
                        "dangerous",
                        "GitLab CI job receives token or secret material; verify runner "
                        "isolation and least-privilege scope.",
                    )
                )
            if not any(key in raw_job for key in ("script", "run", "trigger")):
                changes.append(
                    _change(
                        address,
                        "unresolved",
                        "review",
                        "GitLab CI job has no recognized script, run, or trigger directive.",
                    )
                )
        if not changes:
            changes.append(
                _change(
                    "pipeline",
                    "unresolved",
                    "review",
                    "GitLab CI configuration contains no statically analyzable jobs.",
                )
            )
        return changes


class CircleCIAdapter(_PipelineAdapter):
    wrapper_key = "circleci"
    tool_name = "CircleCI"

    @property
    def adapter_name(self) -> str:
        return "circleci"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        pipeline = input_data[self.wrapper_key]
        changes: list[dict[str, Any]] = []
        for orb_name, orb_ref in (
            (pipeline.get("orbs") or {}).items() if isinstance(pipeline.get("orbs"), dict) else []
        ):
            pinned = "@" in str(orb_ref) and not str(orb_ref).endswith(
                ("@volatile", "@dev:alpha", "@dev:latest")
            )
            changes.append(
                _change(
                    f"orbs.{orb_name}",
                    "orb",
                    "review" if pinned else "dangerous",
                    "CircleCI orb imports executable configuration; verify the "
                    "publisher and use an immutable production version.",
                )
            )
        jobs = pipeline.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            return changes + [
                _change(
                    "pipeline.jobs",
                    "unresolved",
                    "review",
                    "CircleCI configuration has no statically analyzable jobs.",
                )
            ]
        for job_name, raw_job in jobs.items():
            if not isinstance(raw_job, dict):
                changes.append(
                    _change(
                        f"jobs.{job_name}",
                        "unresolved",
                        "review",
                        "CircleCI job is not an object and requires manual review.",
                    )
                )
                continue
            if "machine" in raw_job:
                changes.append(
                    _change(
                        f"jobs.{job_name}.machine",
                        "machine",
                        "review",
                        "CircleCI machine executor grants a full VM; verify image, "
                        "isolation, and command scope.",
                    )
                )
            docker_images = raw_job.get("docker", [])
            if isinstance(docker_images, list):
                for image_index, image in enumerate(docker_images):
                    risk = "review" if _is_digest_pinned_image(image) else "dangerous"
                    changes.append(
                        _change(
                            f"jobs.{job_name}.docker[{image_index}]",
                            "image",
                            risk,
                            "CircleCI Docker executor image runs pipeline code; "
                            "pin the image to a trusted digest.",
                        )
                    )
            steps = raw_job.get("steps", [])
            if not isinstance(steps, list):
                changes.append(
                    _change(
                        f"jobs.{job_name}.steps",
                        "unresolved",
                        "review",
                        "CircleCI steps are generated or malformed and require manual review.",
                    )
                )
                continue
            for index, step in enumerate(steps):
                address = f"jobs.{job_name}.steps[{index}]"
                key = (
                    step
                    if isinstance(step, str)
                    else next(iter(step), "unresolved")
                    if isinstance(step, dict) and step
                    else "unresolved"
                )
                if key == "run":
                    changes.append(
                        _change(
                            address,
                            "run",
                            "dangerous",
                            "CircleCI run step executes arbitrary commands on the runner.",
                        )
                    )
                elif key == "add_ssh_keys":
                    changes.append(
                        _change(
                            address,
                            "ssh_keys",
                            "dangerous",
                            "CircleCI add_ssh_keys exposes private SSH credentials to the job.",
                        )
                    )
                elif key == "setup_remote_docker":
                    changes.append(
                        _change(
                            address,
                            "remote_docker",
                            "dangerous",
                            "CircleCI remote Docker grants a separate execution "
                            "environment for arbitrary container operations.",
                        )
                    )
                elif key in {"checkout", "store_artifacts", "store_test_results"}:
                    changes.append(
                        _change(
                            address,
                            str(key),
                            "safe",
                            f"CircleCI {key} step reads source or records build output.",
                        )
                    )
                else:
                    changes.append(
                        _change(
                            address,
                            "reusable_step",
                            "review",
                            "CircleCI reusable, orb, or special step requires review "
                            "of its resolved implementation.",
                        )
                    )
        return changes


def analyze_pipeline(
    adapter: _PipelineAdapter, data: dict[str, Any], *, catalog=None
) -> dict[str, Any]:
    changes = adapter.analyze(data, tool_name=adapter.tool_name)
    summary = PlanSummary(
        path=Path(f"{adapter.adapter_name}://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name=adapter.tool_name)
    gate["adapter"] = adapter.adapter_name
    gate["total_changes"] = len(changes)
    return gate


def analyze_github_actions(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_pipeline(GitHubActionsAdapter(), data, catalog=catalog)


def analyze_gitlab_ci(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_pipeline(GitLabCIAdapter(), data, catalog=catalog)


def analyze_circleci(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_pipeline(CircleCIAdapter(), data, catalog=catalog)
