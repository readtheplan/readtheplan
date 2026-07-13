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
        if ecosystem in {"drone-ci", "bamboo"}:
            documents = list(yaml.load_all(source, Loader=WorkflowLoader))
            if not documents or any(not isinstance(document, dict) for document in documents):
                label = "Drone pipeline" if ecosystem == "drone-ci" else "Bamboo Specs"
                raise PipelineInputError(f"{label} YAML documents must be objects")
            parsed: Any = {"documents": documents}
        else:
            parsed = yaml.load(source, Loader=WorkflowLoader)
    except yaml.YAMLError as exc:
        raise PipelineInputError(str(exc)) from exc
    if not isinstance(parsed, dict):
        raise PipelineInputError("pipeline YAML must be an object")

    wrappers = {
        "azure-pipelines": "azure_pipelines",
        "bamboo": "bamboo",
        "bitbucket-pipelines": "bitbucket_pipelines",
        "buildkite": "buildkite",
        "github-actions": "github_actions",
        "gitlab-ci": "gitlab_ci",
        "circleci": "circleci",
        "concourse": "concourse",
        "drone-ci": "drone_ci",
        "travis-ci": "travis_ci",
        "woodpecker-ci": "woodpecker_ci",
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


_AZURE_SCRIPT_KEYS = {"bash", "powershell", "pwsh", "script"}
_AZURE_SERVICE_CONNECTION_KEYS = {
    "azureSubscription",
    "connectedServiceName",
    "connectedServiceNameARM",
    "containerRegistry",
    "dockerRegistryEndpoint",
    "environmentServiceName",
    "kubernetesServiceConnection",
    "serviceConnection",
    "sshEndpoint",
}
_AZURE_INFRA_TASKS = (
    "azurecli",
    "azurepowershell",
    "azurefunctionapp",
    "azurewebapp",
    "docker",
    "helmdeploy",
    "kubernetes",
    "kubectl",
    "sshoverssh",
    "terraform",
)
_SENSITIVE_VARIABLE_NAME = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|credential|passwd|password|private[_-]?key|secret|token)(?:$|[_-])",
    re.IGNORECASE,
)


def _azure_template_risk(template: Any, repository_pins: dict[str, bool]) -> str:
    reference = str(template)
    _, separator, repository = reference.rpartition("@")
    if not separator:
        return "review"
    return "review" if repository_pins.get(repository, False) else "dangerous"


class AzurePipelinesAdapter(_PipelineAdapter):
    wrapper_key = "azure_pipelines"
    tool_name = "Azure Pipelines"

    @property
    def adapter_name(self) -> str:
        return "azure-pipelines"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        pipeline = input_data[self.wrapper_key]
        changes: list[dict[str, Any]] = []
        repository_pins = self._resources(pipeline.get("resources"), changes)

        if isinstance(pipeline.get("extends"), dict):
            template = pipeline["extends"].get("template", "<dynamic>")
            changes.append(
                _change(
                    "extends.template",
                    "template",
                    _azure_template_risk(template, repository_pins),
                    "Azure Pipelines extends imports executable pipeline structure; "
                    "verify required-template enforcement and pin external repositories.",
                )
            )

        self._variables(pipeline.get("variables"), "variables", changes, repository_pins)
        for trigger_key in ("trigger", "pr", "schedules"):
            if pipeline.get(trigger_key) is not None:
                changes.append(
                    _change(
                        trigger_key,
                        "trigger",
                        "review",
                        "Pipeline trigger controls which source changes or schedules can "
                        "reach agents and protected resources; verify branch and path filters.",
                    )
                )
        if pipeline.get("pool") is not None:
            self._pool(pipeline["pool"], "pool", changes)
        self._steps(pipeline.get("steps"), "steps", changes, repository_pins)
        self._jobs(pipeline.get("jobs"), "jobs", changes, repository_pins)

        stages = pipeline.get("stages")
        if isinstance(stages, list):
            for index, stage in enumerate(stages):
                address = f"stages[{index}]"
                if not isinstance(stage, dict):
                    changes.append(
                        _change(
                            address,
                            "unresolved",
                            "review",
                            "Azure Pipelines stage is generated or malformed.",
                        )
                    )
                    continue
                if "template" in stage:
                    self._template(stage["template"], address, changes, repository_pins)
                    continue
                if stage.get("lockBehavior") is not None:
                    changes.append(
                        _change(
                            f"{address}.lockBehavior",
                            "lock_behavior",
                            "review",
                            "Stage lock behavior controls concurrent deployment execution.",
                        )
                    )
                self._variables(
                    stage.get("variables"), f"{address}.variables", changes, repository_pins
                )
                self._jobs(stage.get("jobs"), f"{address}.jobs", changes, repository_pins)

        changes.append(
            _change(
                "pipeline.protected_resources",
                "protected_resources",
                "review",
                "Approvals, checks, variable-group authorization, service-connection "
                "permissions, and environment protections live outside pipeline YAML.",
            )
        )
        return changes

    def _resources(
        self, resources: Any, changes: list[dict[str, Any]]
    ) -> dict[str, bool]:
        pins: dict[str, bool] = {}
        if not isinstance(resources, dict):
            return pins
        repositories = resources.get("repositories", [])
        if isinstance(repositories, list):
            for index, repository in enumerate(repositories):
                if not isinstance(repository, dict):
                    continue
                alias = str(repository.get("repository") or f"repository-{index}")
                ref = str(repository.get("ref") or "")
                pinned = bool(_SHA_REF.fullmatch(ref.removeprefix("refs/heads/")))
                pins[alias] = pinned
                changes.append(
                    _change(
                        f"resources.repositories[{index}]",
                        "repository",
                        "review" if pinned else "dangerous",
                        "Repository resources import pipeline or source code; require "
                        "a trusted endpoint and immutable commit reference.",
                    )
                )
                if repository.get("endpoint") is not None:
                    changes.append(
                        _change(
                            f"resources.repositories[{index}].endpoint",
                            "service_connection",
                            "dangerous",
                            "Repository resource uses a service connection with "
                            "external credentials.",
                        )
                    )
        containers = resources.get("containers", [])
        if isinstance(containers, list):
            for index, container in enumerate(containers):
                if not isinstance(container, dict):
                    continue
                image = container.get("image", "")
                changes.append(
                    _change(
                        f"resources.containers[{index}].image",
                        "image",
                        "review" if _is_digest_pinned_image(image) else "dangerous",
                        "Pipeline container executes job code; pin the image to a trusted digest.",
                    )
                )
                if container.get("endpoint") is not None:
                    changes.append(
                        _change(
                            f"resources.containers[{index}].endpoint",
                            "service_connection",
                            "dangerous",
                            "Container resource uses registry credentials from a "
                            "service connection.",
                        )
                    )
        for resource_kind in ("builds", "packages", "pipelines", "webhooks"):
            values = resources.get(resource_kind)
            if isinstance(values, list):
                for index, _ in enumerate(values):
                    changes.append(
                        _change(
                            f"resources.{resource_kind}[{index}]",
                            f"resource_{resource_kind.rstrip('s')}",
                            "review",
                            "Pipeline resource can import artifacts, packages, triggers, "
                            "or external event data; verify source and authorization.",
                        )
                    )
        return pins

    def _variables(
        self,
        variables: Any,
        address: str,
        changes: list[dict[str, Any]],
        repository_pins: dict[str, bool],
    ) -> None:
        if isinstance(variables, dict):
            items = variables.items()
            for name, _ in items:
                if _SENSITIVE_VARIABLE_NAME.search(str(name)):
                    changes.append(
                        _change(
                            f"{address}.{name}",
                            "inline_secret",
                            "dangerous",
                            "Credential-like variable is declared inline in versioned YAML.",
                        )
                    )
            return
        if not isinstance(variables, list):
            return
        for index, variable in enumerate(variables):
            if not isinstance(variable, dict):
                continue
            item_address = f"{address}[{index}]"
            if variable.get("group") is not None:
                changes.append(
                    _change(
                        item_address,
                        "variable_group",
                        "dangerous",
                        "Variable group may expose protected secrets; verify pipeline "
                        "authorization, approvals, checks, and least-privilege scope.",
                    )
                )
            elif variable.get("template") is not None:
                self._template(
                    variable["template"], item_address, changes, repository_pins
                )
            elif _SENSITIVE_VARIABLE_NAME.search(str(variable.get("name", ""))):
                changes.append(
                    _change(
                        item_address,
                        "inline_secret",
                        "dangerous",
                        "Credential-like variable is declared inline in versioned YAML.",
                    )
                )

    def _pool(self, pool: Any, address: str, changes: list[dict[str, Any]]) -> None:
        managed_image = isinstance(pool, dict) and pool.get("vmImage") is not None
        changes.append(
            _change(
                address,
                "pool",
                "review" if managed_image else "dangerous",
                "Agent pool executes pipeline code with access to its host and network; "
                "verify image provenance, isolation, and self-hosted agent trust.",
            )
        )

    def _jobs(
        self,
        jobs: Any,
        address: str,
        changes: list[dict[str, Any]],
        repository_pins: dict[str, bool],
    ) -> None:
        if not isinstance(jobs, list):
            return
        for index, job in enumerate(jobs):
            job_address = f"{address}[{index}]"
            if not isinstance(job, dict):
                changes.append(
                    _change(
                        job_address,
                        "unresolved",
                        "review",
                        "Azure Pipelines job is generated or malformed.",
                    )
                )
                continue
            if "template" in job:
                self._template(job["template"], job_address, changes, repository_pins)
                continue
            if "deployment" in job:
                changes.append(
                    _change(
                        f"{job_address}.environment",
                        "environment",
                        "review",
                        "Deployment job targets an environment; verify resource ownership, "
                        "exclusive locks, approvals, and checks.",
                    )
                )
            if job.get("pool") is not None:
                self._pool(job["pool"], f"{job_address}.pool", changes)
            if job.get("container") is not None:
                container = job["container"]
                risk = "review" if _is_digest_pinned_image(container) else "dangerous"
                changes.append(
                    _change(
                        f"{job_address}.container",
                        "image",
                        risk,
                        "Job container executes pipeline code; pin direct images to a digest "
                        "and review named container resources.",
                    )
                )
            self._variables(
                job.get("variables"),
                f"{job_address}.variables",
                changes,
                repository_pins,
            )
            self._steps(job.get("steps"), f"{job_address}.steps", changes, repository_pins)
            strategy = job.get("strategy")
            if isinstance(strategy, dict):
                self._strategy_steps(
                    strategy,
                    f"{job_address}.strategy",
                    changes,
                    repository_pins,
                )

    def _strategy_steps(
        self,
        value: Any,
        address: str,
        changes: list[dict[str, Any]],
        repository_pins: dict[str, bool],
    ) -> None:
        if not isinstance(value, dict):
            return
        for key, item in value.items():
            item_address = f"{address}.{key}"
            if key == "steps":
                self._steps(item, item_address, changes, repository_pins)
            elif isinstance(item, dict):
                self._strategy_steps(item, item_address, changes, repository_pins)

    def _steps(
        self,
        steps: Any,
        address: str,
        changes: list[dict[str, Any]],
        repository_pins: dict[str, bool],
    ) -> None:
        if not isinstance(steps, list):
            return
        for index, step in enumerate(steps):
            step_address = f"{address}[{index}]"
            if not isinstance(step, dict):
                changes.append(
                    _change(
                        step_address,
                        "unresolved",
                        "review",
                        "Azure Pipelines step is generated or malformed.",
                    )
                )
                continue
            if step.get("template") is not None:
                self._template(step["template"], step_address, changes, repository_pins)
                continue
            script_key = next((key for key in _AZURE_SCRIPT_KEYS if key in step), None)
            if script_key:
                changes.append(
                    _change(
                        step_address,
                        "script",
                        "dangerous",
                        f"Azure Pipelines {script_key} step executes arbitrary agent commands.",
                    )
                )
            elif step.get("task") is not None:
                task = str(step["task"])
                infra = any(token in task.lower() for token in _AZURE_INFRA_TASKS)
                changes.append(
                    _change(
                        step_address,
                        "task",
                        "dangerous" if infra else "review",
                        "Azure Pipelines task executes built-in or extension code; verify "
                        "publisher, major version, inputs, and deployment scope.",
                    )
                )
                inputs = step.get("inputs")
                if isinstance(inputs, dict):
                    for key in _AZURE_SERVICE_CONNECTION_KEYS & inputs.keys():
                        changes.append(
                            _change(
                                f"{step_address}.inputs.{key}",
                                "service_connection",
                                "dangerous",
                                "Task receives a service connection capable of authenticating "
                                "to infrastructure or an external service.",
                            )
                        )
            elif step.get("checkout") is not None:
                persist = str(step.get("persistCredentials", "false")).lower() == "true"
                changes.append(
                    _change(
                        step_address,
                        "checkout",
                        "dangerous" if persist else "review",
                        "Checkout imports repository content into the agent; persisted "
                        "credentials allow later steps to reuse the OAuth token.",
                    )
                )
            elif any(key in step for key in ("download", "downloadBuild", "getPackage")):
                changes.append(
                    _change(
                        step_address,
                        "download",
                        "review",
                        "Download step imports pipeline artifacts or packages; verify provenance.",
                    )
                )
            elif "publish" in step:
                changes.append(
                    _change(
                        step_address,
                        "publish",
                        "review",
                        "Publish step exports files from the agent; verify content and retention.",
                    )
                )
            else:
                changes.append(
                    _change(
                        step_address,
                        "unresolved",
                        "review",
                        "Azure Pipelines step has no recognized execution directive.",
                    )
                )
            if self._secret_input(step):
                changes.append(
                    _change(
                        f"{step_address}.secrets",
                        "secret_input",
                        "dangerous",
                        "Step receives a credential-like variable; verify explicit environment "
                        "mapping, masking, command-line exposure, and log handling.",
                    )
                )

    def _template(
        self,
        template: Any,
        address: str,
        changes: list[dict[str, Any]],
        repository_pins: dict[str, bool],
    ) -> None:
        changes.append(
            _change(
                address,
                "template",
                _azure_template_risk(template, repository_pins),
                "Azure Pipelines template imports executable configuration; review "
                "parameters and pin external repository resources immutably.",
            )
        )

    def _secret_input(self, value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                _SENSITIVE_VARIABLE_NAME.search(str(key)) is not None
                or self._secret_input(item)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return any(self._secret_input(item) for item in value)
        text = str(value)
        return any(
            _SENSITIVE_VARIABLE_NAME.search(name) is not None
            for name in re.findall(r"\$\(([^)]+)\)", text)
        )


_BITBUCKET_VARIABLE = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)
_EXACT_PIPE_VERSION = re.compile(r"^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")


class BitbucketPipelinesAdapter(_PipelineAdapter):
    wrapper_key = "bitbucket_pipelines"
    tool_name = "Bitbucket Pipelines"

    @property
    def adapter_name(self) -> str:
        return "bitbucket-pipelines"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        pipeline = input_data[self.wrapper_key]
        changes: list[dict[str, Any]] = []

        if pipeline.get("image") is not None:
            self._image(pipeline["image"], "image", changes)
        if pipeline.get("clone") is not None:
            changes.append(
                _change(
                    "clone",
                    "clone",
                    "review",
                    "Clone options control source history, LFS, submodules, and repository "
                    "content made available to every step.",
                )
            )
        if str(pipeline.get("export", "false")).lower() == "true":
            changes.append(
                _change(
                    "export",
                    "export",
                    "review",
                    "Exported pipeline configuration can be imported by other repositories; "
                    "review its compatibility and trust boundary.",
                )
            )
        self._definitions(pipeline.get("definitions"), changes)

        pipelines = pipeline.get("pipelines")
        if not isinstance(pipelines, dict) or not pipelines:
            changes.append(
                _change(
                    "pipelines",
                    "unresolved",
                    "review",
                    "Bitbucket configuration has no statically analyzable pipelines object.",
                )
            )
        else:
            for selector, body in pipelines.items():
                selector_address = f"pipelines.{selector}"
                changes.append(
                    _change(
                        selector_address,
                        "trigger",
                        "review",
                        "Pipeline selector controls which branches, tags, pull requests, "
                        "custom invocations, or schedules can reach deployment resources.",
                    )
                )
                if isinstance(body, list):
                    self._entries(body, selector_address, changes)
                elif isinstance(body, dict):
                    for pattern, entries in body.items():
                        pattern_address = f"{selector_address}.{pattern}"
                        if isinstance(entries, list):
                            self._entries(entries, pattern_address, changes)
                        elif isinstance(entries, dict) and "import" in entries:
                            self._import(entries["import"], pattern_address, changes)
                        else:
                            changes.append(
                                _change(
                                    pattern_address,
                                    "unresolved",
                                    "review",
                                    "Pipeline selector is generated, imported, or malformed.",
                                )
                            )

        changes.append(
            _change(
                "pipeline.external_settings",
                "external_settings",
                "review",
                "Secured workspace/repository/deployment variables, deployment permissions, "
                "runner registration, dynamic pipeline providers, and SSH keys live outside YAML.",
            )
        )
        return changes

    def _definitions(self, definitions: Any, changes: list[dict[str, Any]]) -> None:
        if not isinstance(definitions, dict):
            return
        services = definitions.get("services")
        if isinstance(services, dict):
            for name, service in services.items():
                address = f"definitions.services.{name}"
                image = service.get("image") if isinstance(service, dict) else service
                self._image(image, address, changes, kind="service_image")
                if str(name).lower() == "docker" or (
                    isinstance(service, dict) and service.get("type") == "docker"
                ):
                    changes.append(
                        _change(
                            f"{address}.docker",
                            "docker_service",
                            "dangerous",
                            "Docker service permits container builds or daemon operations from "
                            "pipeline commands.",
                        )
                    )
                if self._secret_reference(service):
                    changes.append(self._secret_change(f"{address}.secrets"))
        caches = definitions.get("caches")
        if isinstance(caches, dict):
            for name in caches:
                changes.append(
                    _change(
                        f"definitions.caches.{name}",
                        "cache",
                        "review",
                        "Custom cache persists files between builds; verify keys, paths, "
                        "poisoning resistance, and secret exclusion.",
                    )
                )

    def _entries(
        self, entries: list[Any], address: str, changes: list[dict[str, Any]]
    ) -> None:
        for index, entry in enumerate(entries):
            entry_address = f"{address}[{index}]"
            if not isinstance(entry, dict):
                changes.append(
                    _change(
                        entry_address,
                        "unresolved",
                        "review",
                        "Pipeline entry is an unresolved YAML alias or malformed value.",
                    )
                )
                continue
            if "step" in entry:
                self._step(entry["step"], f"{entry_address}.step", changes)
            elif "variables" in entry:
                variables = entry["variables"]
                if isinstance(variables, list):
                    for variable_index, variable in enumerate(variables):
                        variable_address = (
                            f"{entry_address}.variables[{variable_index}]"
                        )
                        name = (
                            variable.get("name", "")
                            if isinstance(variable, dict)
                            else ""
                        )
                        sensitive = _SENSITIVE_VARIABLE_NAME.search(str(name)) is not None
                        changes.append(
                            _change(
                                variable_address,
                                "custom_variable",
                                "dangerous" if sensitive else "review",
                                "Custom pipeline variable is supplied at invocation time; "
                                "verify allowed values, defaults, and secret handling.",
                            )
                        )
            elif "parallel" in entry:
                parallel = entry["parallel"]
                parallel_steps = (
                    parallel.get("steps") if isinstance(parallel, dict) else parallel
                )
                if isinstance(parallel_steps, list):
                    self._entries(parallel_steps, f"{entry_address}.parallel", changes)
                else:
                    changes.append(
                        _change(
                            f"{entry_address}.parallel",
                            "unresolved",
                            "review",
                            "Parallel step group is generated or malformed.",
                        )
                    )
            elif "stage" in entry:
                stage = entry["stage"]
                if not isinstance(stage, dict):
                    changes.append(
                        _change(
                            f"{entry_address}.stage",
                            "unresolved",
                            "review",
                            "Pipeline stage is generated or malformed.",
                        )
                    )
                    continue
                if stage.get("deployment") is not None or stage.get("environment") is not None:
                    changes.append(self._deployment(f"{entry_address}.stage.deployment"))
                stage_steps = stage.get("steps")
                if isinstance(stage_steps, list):
                    self._entries(stage_steps, f"{entry_address}.stage.steps", changes)
            elif "import" in entry:
                self._import(entry["import"], entry_address, changes)
            else:
                changes.append(
                    _change(
                        entry_address,
                        "unresolved",
                        "review",
                        "Pipeline entry has no recognized step, stage, parallel, or import key.",
                    )
                )

    def _step(self, step: Any, address: str, changes: list[dict[str, Any]]) -> None:
        if not isinstance(step, dict):
            changes.append(
                _change(
                    address,
                    "unresolved",
                    "review",
                    "Bitbucket pipeline step is generated or malformed.",
                )
            )
            return
        if step.get("image") is not None:
            self._image(step["image"], f"{address}.image", changes)
        runs_on = step.get("runs-on")
        if runs_on is not None:
            labels = runs_on if isinstance(runs_on, list) else [runs_on]
            self_hosted = any(str(label).lower() == "self.hosted" for label in labels)
            changes.append(
                _change(
                    f"{address}.runs-on",
                    "runner",
                    "dangerous" if self_hosted else "review",
                    "Runner labels select execution infrastructure; self-hosted runners "
                    "can access the host and private network.",
                )
            )
        if step.get("deployment") is not None:
            changes.append(self._deployment(f"{address}.deployment"))
        if str(step.get("oidc", "false")).lower() == "true":
            changes.append(
                _change(
                    f"{address}.oidc",
                    "oidc",
                    "dangerous",
                    "OIDC issues a workload identity token; verify resource-server audience, "
                    "repository, branch, environment, and subject policies.",
                )
            )
        if step.get("type") == "pipeline":
            changes.append(
                _change(
                    f"{address}.type",
                    "child_pipeline",
                    "review",
                    "Child pipeline executes additional pipeline configuration and passes "
                    "selected variables or artifacts.",
                )
            )
        if step.get("trigger") is not None:
            changes.append(
                _change(
                    f"{address}.trigger",
                    "manual_trigger",
                    "review",
                    "Manual trigger changes the approval and execution boundary for this step.",
                )
            )
        if step.get("condition") is not None:
            changes.append(
                _change(
                    f"{address}.condition",
                    "condition",
                    "review",
                    "Step condition changes which commits and file changes can reach "
                    "commands, credentials, or deployment resources.",
                )
            )
        for service_index, service in enumerate(self._as_list(step.get("services"))):
            changes.append(
                _change(
                    f"{address}.services[{service_index}]",
                    "service",
                    "dangerous" if str(service).lower() == "docker" else "review",
                    "Service container shares the step network; verify image, credentials, "
                    "ports, data, and Docker daemon access.",
                )
            )
        for cache_index, _ in enumerate(self._as_list(step.get("caches"))):
            changes.append(
                _change(
                    f"{address}.caches[{cache_index}]",
                    "cache",
                    "review",
                    "Step restores a persistent cache; verify key isolation and poisoning risk.",
                )
            )
        scripts = self._as_list(step.get("script"))
        for index, command in enumerate(scripts):
            script_address = f"{address}.script[{index}]"
            if isinstance(command, dict) and command.get("pipe") is not None:
                self._pipe(command, script_address, changes)
            else:
                changes.append(
                    _change(
                        script_address,
                        "script",
                        "dangerous",
                        "Bitbucket Pipelines script executes arbitrary commands in the step.",
                    )
                )
                if self._secret_reference(command):
                    changes.append(self._secret_change(f"{script_address}.secrets"))
        if not scripts and step.get("type") != "pipeline":
            changes.append(
                _change(
                    f"{address}.script",
                    "unresolved",
                    "review",
                    "Bitbucket pipeline step has no statically analyzable script commands.",
                )
            )
        for index, command in enumerate(self._as_list(step.get("after-script"))):
            after_address = f"{address}.after-script[{index}]"
            changes.append(
                _change(
                    after_address,
                    "after_script",
                    "dangerous",
                    "Bitbucket after-script executes commands even after the main script phase.",
                )
            )
            if self._secret_reference(command):
                changes.append(self._secret_change(f"{after_address}.secrets"))
        if step.get("artifacts") is not None:
            changes.append(
                _change(
                    f"{address}.artifacts",
                    "artifacts",
                    "review",
                    "Artifacts persist or transfer step files; verify paths, capture type, "
                    "retention, and secret exclusion.",
                )
            )
        for variable_key in ("input-variables", "variables"):
            if variable_key in step and self._secret_reference(step[variable_key]):
                changes.append(
                    self._secret_change(f"{address}.{variable_key}.secrets")
                )

    def _pipe(
        self, pipe: dict[str, Any], address: str, changes: list[dict[str, Any]]
    ) -> None:
        reference = str(pipe.get("pipe") or "")
        _, separator, version = reference.rpartition(":")
        pinned = bool(separator and _EXACT_PIPE_VERSION.fullmatch(version))
        changes.append(
            _change(
                address,
                "pipe",
                "review" if pinned else "dangerous",
                "Bitbucket Pipe executes reusable container code; verify publisher and "
                "use an exact reviewed production version.",
            )
        )
        if self._secret_reference(pipe.get("variables")):
            changes.append(self._secret_change(f"{address}.secrets"))

    def _image(
        self,
        image: Any,
        address: str,
        changes: list[dict[str, Any]],
        *,
        kind: str = "image",
    ) -> None:
        changes.append(
            _change(
                address,
                kind,
                "review" if _is_digest_pinned_image(image) else "dangerous",
                "Pipeline image executes build or service code; pin it to a trusted digest "
                "and review private-registry credentials.",
            )
        )
        if isinstance(image, dict) and any(
            key in image for key in ("password", "username", "aws", "aws-oidc-role")
        ):
            changes.append(self._secret_change(f"{address}.credentials"))

    def _import(
        self, reference: Any, address: str, changes: list[dict[str, Any]]
    ) -> None:
        pinned = any(_SHA_REF.fullmatch(part) for part in str(reference).split(":"))
        changes.append(
            _change(
                address,
                "import",
                "review" if pinned else "dangerous",
                "Shared pipeline import executes configuration with the importing "
                "repository's variables and secrets; pin and review the exported pipeline.",
            )
        )

    def _deployment(self, address: str) -> dict[str, str]:
        return _change(
            address,
            "deployment",
            "review",
            "Deployment step or stage receives environment-scoped variables and targets "
            "a protected environment; verify branch restrictions and admin permissions.",
        )

    def _secret_reference(self, value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                _SENSITIVE_VARIABLE_NAME.search(str(key)) is not None
                or self._secret_reference(item)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return any(self._secret_reference(item) for item in value)
        return any(
            _SENSITIVE_VARIABLE_NAME.search(
                match.group("braced") or match.group("plain") or ""
            )
            is not None
            for match in _BITBUCKET_VARIABLE.finditer(str(value))
        )

    def _secret_change(self, address: str) -> dict[str, str]:
        return _change(
            address,
            "secret_input",
            "dangerous",
            "Step, pipe, service, or image references credential-like variables; verify "
            "secured-variable scope, command-line exposure, and log masking.",
        )

    def _as_list(self, value: Any) -> list[Any]:
        if value is None:
            return []
        return value if isinstance(value, list) else [value]


class BuildkiteAdapter(_PipelineAdapter):
    wrapper_key = "buildkite"
    tool_name = "Buildkite"

    @property
    def adapter_name(self) -> str:
        return "buildkite"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        pipeline = input_data[self.wrapper_key]
        changes: list[dict[str, Any]] = []
        if pipeline.get("env") is not None:
            changes.append(self._environment("pipeline.env", pipeline["env"], global_env=True))
        if pipeline.get("agents") is not None:
            changes.append(self._agents("pipeline.agents", pipeline["agents"]))
        steps = pipeline.get("steps")
        if not isinstance(steps, list) or not steps:
            changes.append(
                _change(
                    "pipeline.steps",
                    "unresolved",
                    "review",
                    "Buildkite pipeline has no statically analyzable steps; review uploaded or "
                    "generated pipeline configuration.",
                )
            )
            return changes
        self._steps(steps, "steps", changes)
        changes.append(
            _change(
                "pipeline.effective_configuration",
                "effective_configuration",
                "review",
                "Buildkite execution also depends on agent hooks, cluster/queue policies, "
                "pipeline settings, environment interpolation, and uploaded dynamic steps.",
            )
        )
        return changes

    def _steps(
        self, steps: list[Any], prefix: str, changes: list[dict[str, Any]]
    ) -> None:
        for index, raw_step in enumerate(steps):
            address = f"{prefix}[{index}]"
            if isinstance(raw_step, str):
                kind = raw_step.lower()
                changes.append(
                    _change(
                        address,
                        "wait" if kind in {"wait", "waiter"} else "unresolved",
                        "safe" if kind in {"wait", "waiter"} else "review",
                        "Buildkite wait creates an ordering barrier."
                        if kind in {"wait", "waiter"}
                        else "Buildkite shorthand step requires review.",
                    )
                )
                continue
            if not isinstance(raw_step, dict):
                changes.append(
                    _change(address, "unresolved", "review", "Buildkite step is not an object.")
                )
                continue
            nested = raw_step.get("steps")
            if isinstance(nested, list):
                changes.append(
                    _change(
                        f"{address}.group",
                        "group",
                        "review",
                        "Buildkite group controls conditional and shared execution boundaries.",
                    )
                )
                self._steps(nested, f"{address}.steps", changes)
            command = raw_step.get("command", raw_step.get("commands"))
            if command is not None:
                text = "\n".join(map(str, command)) if isinstance(command, list) else str(command)
                changes.append(
                    _change(
                        f"{address}.command",
                        "command",
                        "dangerous",
                        "Buildkite command step executes arbitrary code on the selected agent.",
                    )
                )
                if re.search(r"buildkite-agent\s+pipeline\s+upload", text, re.IGNORECASE):
                    changes.append(
                        _change(
                            f"{address}.pipeline_upload",
                            "dynamic_pipeline",
                            "dangerous",
                            "Command uploads dynamic pipeline steps not present in this artifact.",
                        )
                    )
                if self._secret_reference(text):
                    changes.append(self._secret(f"{address}.command.secrets"))
            if raw_step.get("plugins") is not None:
                self._plugins(raw_step["plugins"], f"{address}.plugins", changes)
            if raw_step.get("env") is not None:
                changes.append(self._environment(f"{address}.env", raw_step["env"]))
            if raw_step.get("secrets") is not None:
                changes.append(self._secret(f"{address}.secrets"))
            if raw_step.get("agents") is not None:
                changes.append(self._agents(f"{address}.agents", raw_step["agents"]))
            if raw_step.get("trigger") is not None:
                changes.append(
                    _change(
                        f"{address}.trigger",
                        "trigger",
                        "dangerous",
                        "Buildkite trigger starts another pipeline with separate code, settings, "
                        "agents, and secrets.",
                    )
                )
            if "block" in raw_step or "input" in raw_step:
                changes.append(
                    _change(
                        f"{address}.approval",
                        "approval",
                        "review",
                        "Buildkite block/input pauses for user data or approval; verify "
                        "permissions.",
                    )
                )
            if raw_step.get("artifact_paths") is not None:
                changes.append(
                    _change(
                        f"{address}.artifact_paths",
                        "artifacts",
                        "review",
                        "Buildkite artifacts persist agent files; verify paths, retention, and "
                        "credential exclusion.",
                    )
                )
            for key, kind, risk, explanation in (
                ("soft_fail", "soft_fail", "dangerous", "Soft-fail can bypass a failing gate."),
                ("retry", "retry", "review", "Retry can re-execute commands or infrastructure."),
                (
                    "concurrency_group",
                    "concurrency",
                    "review",
                    "Concurrency changes deployment serialization.",
                ),
                (
                    "depends_on",
                    "dependency",
                    "review",
                    "Step dependencies control execution order.",
                ),
            ):
                if raw_step.get(key) is not None:
                    changes.append(_change(f"{address}.{key}", kind, risk, explanation))

    def _plugins(
        self, plugins: Any, address: str, changes: list[dict[str, Any]]
    ) -> None:
        values = plugins if isinstance(plugins, list) else [plugins]
        for index, plugin in enumerate(values):
            reference = next(iter(plugin), "") if isinstance(plugin, dict) else str(plugin)
            ref = str(reference)
            _, separator, version = ref.rpartition("#")
            pinned_version = _SHA_REF.fullmatch(version) or _EXACT_PIPE_VERSION.fullmatch(
                version.lstrip("v")
            )
            pinned = ref.startswith("./") or bool(separator and pinned_version)
            changes.append(
                _change(
                    f"{address}[{index}]",
                    "plugin",
                    "review" if pinned else "dangerous",
                    "Buildkite plugin runs lifecycle hooks on the agent; pin an exact reviewed "
                    "version and verify publisher and configuration.",
                )
            )
            if self._secret_reference(plugin):
                changes.append(self._secret(f"{address}[{index}].secrets"))

    def _environment(self, address: str, value: Any, *, global_env: bool = False) -> dict[str, str]:
        sensitive = self._secret_reference(value)
        risk = "dangerous" if sensitive or global_env else "review"
        scope = "pipeline-wide" if global_env else "step"
        return _change(
            address,
            "environment",
            risk,
            f"Buildkite {scope} environment is interpolated and sent to jobs; avoid literal or "
            "credential-bearing values.",
        )

    def _agents(self, address: str, value: Any) -> dict[str, str]:
        return _change(
            address,
            "agents",
            "review",
            "Buildkite agent and queue selection determines host access, hooks, and secret policy.",
        )

    def _secret_reference(self, value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                _SENSITIVE_VARIABLE_NAME.search(str(key)) is not None
                or self._secret_reference(item)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return any(self._secret_reference(item) for item in value)
        text = str(value)
        return bool(
            re.search(r"\$\{?[A-Za-z_][A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY)", text, re.I)
            or re.search(r"buildkite-agent\s+secret\s+get", text, re.I)
        )

    def _secret(self, address: str) -> dict[str, str]:
        return _change(
            address,
            "secret_input",
            "dangerous",
            "Buildkite step accesses credential material; verify secret policy, queue scope, "
            "interpolation, command-line exposure, and log redaction.",
        )


_TRAVIS_COMMAND_PHASES = (
    "before_install",
    "install",
    "before_script",
    "script",
    "before_cache",
    "after_success",
    "after_failure",
    "after_script",
)


def _pipeline_contains_sensitive_input(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower() in {"from_secret", "secret", "secure"}
            or _SENSITIVE_VARIABLE_NAME.search(str(key)) is not None
            or _pipeline_contains_sensitive_input(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_pipeline_contains_sensitive_input(item) for item in value)
    text = str(value)
    return bool(
        re.search(
            r"(?:\$|\$\{|\$\{\{)[^}\s]*(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY)",
            text,
            re.IGNORECASE,
        )
        or text.lower().startswith("secure:")
    )


class TravisCIAdapter(_PipelineAdapter):
    wrapper_key = "travis_ci"
    tool_name = "Travis CI"

    @property
    def adapter_name(self) -> str:
        return "travis-ci"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        pipeline = input_data[self.wrapper_key]
        changes: list[dict[str, Any]] = []
        self._scope(pipeline, "pipeline", changes)

        jobs = pipeline.get("jobs")
        if isinstance(jobs, dict):
            includes = jobs.get("include", [])
            if isinstance(includes, list):
                for index, job in enumerate(includes):
                    if isinstance(job, dict):
                        self._scope(job, f"jobs.include[{index}]", changes)
                    else:
                        changes.append(
                            _change(
                                f"jobs.include[{index}]",
                                "unresolved",
                                "review",
                                "Travis CI matrix job is not an object and requires review.",
                            )
                        )
            if jobs.get("allow_failures") is not None:
                changes.append(
                    _change(
                        "jobs.allow_failures",
                        "soft_fail",
                        "dangerous",
                        "Allowed failures can bypass a failing security or deployment gate.",
                    )
                )

        if not changes:
            changes.append(
                _change(
                    "pipeline",
                    "unresolved",
                    "review",
                    "Travis CI configuration has no statically analyzable execution phases.",
                )
            )
        changes.append(
            _change(
                "pipeline.effective_configuration",
                "effective_configuration",
                "review",
                "Travis CI execution also depends on repository settings, encrypted variables, "
                "build conditions, and the selected worker image.",
            )
        )
        return changes

    def _scope(
        self,
        scope: dict[str, Any],
        address: str,
        changes: list[dict[str, Any]],
    ) -> None:
        imports = scope.get("import")
        if imports is not None:
            values = imports if isinstance(imports, list) else [imports]
            for index, reference in enumerate(values):
                text = str(reference)
                pinned = re.search(
                    r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])", text
                ) is not None
                changes.append(
                    _change(
                        f"{address}.import[{index}]",
                        "import",
                        "review" if pinned else "dangerous",
                        "Travis CI import executes external build configuration; require a "
                        "trusted source and immutable commit reference.",
                    )
                )

        sudo = scope.get("sudo")
        if sudo is True or str(sudo).lower() in {"required", "enabled", "true"}:
            changes.append(
                _change(
                    f"{address}.sudo",
                    "privileged",
                    "dangerous",
                    "Travis CI job requests elevated worker privileges.",
                )
            )
        services = scope.get("services")
        services = services if isinstance(services, list) else [services] if services else []
        for index, service in enumerate(services):
            risky = str(service).lower() in {"docker", "docker:dind"}
            changes.append(
                _change(
                    f"{address}.services[{index}]",
                    "service",
                    "dangerous" if risky else "review",
                    "Travis CI service changes the job network and worker capabilities; Docker "
                    "service access can control sibling containers and images.",
                )
            )

        for phase in _TRAVIS_COMMAND_PHASES:
            if scope.get(phase) is not None:
                changes.append(
                    _change(
                        f"{address}.{phase}",
                        "script",
                        "dangerous",
                        f"Travis CI {phase} phase executes arbitrary commands on the worker.",
                    )
                )
                if _pipeline_contains_sensitive_input(scope[phase]):
                    changes.append(self._secret(f"{address}.{phase}.secrets"))

        if scope.get("deploy") is not None:
            changes.append(
                _change(
                    f"{address}.deploy",
                    "deployment",
                    "dangerous",
                    "Travis CI deploy provider can mutate external infrastructure or publish "
                    "artifacts; verify provider, conditions, and credentials.",
                )
            )
            if _pipeline_contains_sensitive_input(scope["deploy"]):
                changes.append(self._secret(f"{address}.deploy.secrets"))
        if scope.get("env") is not None:
            sensitive = _pipeline_contains_sensitive_input(scope["env"])
            changes.append(
                _change(
                    f"{address}.env",
                    "secret_input" if sensitive else "environment",
                    "dangerous" if sensitive else "review",
                    "Travis CI environment values enter every command in this scope; keep "
                    "credentials encrypted and narrowly scoped.",
                )
            )
        for key, kind, explanation in (
            ("cache", "cache", "Persistent caches can carry poisoned files between builds."),
            ("addons", "addons", "Addons install packages or connect external services."),
            ("if", "condition", "Build conditions control which refs reach privileged phases."),
            ("branches", "condition", "Branch filters control which refs reach this job."),
            ("notifications", "notification", "Notifications send build data to external systems."),
        ):
            if scope.get(key) is not None:
                changes.append(_change(f"{address}.{key}", kind, "review", explanation))

    def _secret(self, address: str) -> dict[str, str]:
        return _change(
            address,
            "secret_input",
            "dangerous",
            "Travis CI phase receives credential material; verify fork policy, masking, logs, "
            "and deployment scope.",
        )


class _ContainerPipelineAdapter(_PipelineAdapter):
    """Shared static gate for Drone and Woodpecker container-native pipelines."""

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        wrapped = input_data[self.wrapper_key]
        documents = wrapped.get("documents") if isinstance(wrapped, dict) else None
        documents = documents if isinstance(documents, list) else [wrapped]
        changes: list[dict[str, Any]] = []
        for index, pipeline in enumerate(documents):
            address = f"documents[{index}]" if len(documents) > 1 else "pipeline"
            if not isinstance(pipeline, dict):
                changes.append(
                    _change(address, "unresolved", "review", "Pipeline document is not an object.")
                )
                continue
            self._pipeline(pipeline, address, changes)
        if not changes:
            changes.append(
                _change(
                    "pipeline",
                    "unresolved",
                    "review",
                    f"{self.tool_name} configuration has no statically analyzable steps.",
                )
            )
        return changes

    def _pipeline(
        self,
        pipeline: dict[str, Any],
        address: str,
        changes: list[dict[str, Any]],
    ) -> None:
        kind = str(pipeline.get("kind", "pipeline")).lower()
        if kind != "pipeline":
            risk = "safe" if kind == "signature" else "dangerous" if kind == "secret" else "review"
            changes.append(
                _change(
                    f"{address}.kind",
                    kind or "unresolved",
                    risk,
                    f"{self.tool_name} document kind changes the pipeline trust boundary.",
                )
            )
            return

        runner_type = str(pipeline.get("type", "docker")).lower()
        if runner_type not in {"", "docker"}:
            dangerous = runner_type in {"exec", "ssh"}
            changes.append(
                _change(
                    f"{address}.type",
                    "runner",
                    "dangerous" if dangerous else "review",
                    f"{self.tool_name} runner type selects host or cluster execution "
                    "infrastructure; verify isolation and credentials.",
                )
            )
        for key in ("node", "platform", "labels"):
            if pipeline.get(key) is not None:
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "runner_selection",
                        "review",
                        f"{self.tool_name} runner selection controls host, architecture, and "
                        "private-network access.",
                    )
                )
        for key in ("trigger", "when", "depends_on", "runs_on", "concurrency"):
            if pipeline.get(key) is not None:
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "condition" if key in {"trigger", "when"} else "orchestration",
                        "review",
                        f"{self.tool_name} {key} changes when or in what order workflows run.",
                    )
                )
        if pipeline.get("skip_clone") is True or pipeline.get("clone") is not None:
            changes.append(
                _change(
                    f"{address}.clone",
                    "clone",
                    "review",
                    f"{self.tool_name} custom clone behavior changes source and "
                    "credential handling.",
                )
            )
        if pipeline.get("workspace") is not None:
            changes.append(
                _change(
                    f"{address}.workspace",
                    "workspace",
                    "review",
                    "Shared workspace configuration changes persistence and "
                    "cross-step file access.",
                )
            )
        self._volumes(pipeline.get("volumes"), f"{address}.volumes", changes)
        self._containers(pipeline.get("services"), f"{address}.services", changes, service=True)
        self._containers(pipeline.get("steps"), f"{address}.steps", changes, service=False)
        changes.append(
            _change(
                f"{address}.effective_configuration",
                "effective_configuration",
                "review",
                f"{self.tool_name} execution also depends on repository trust, runner backend, "
                "secret policy, plugin allowlists, and server-side settings.",
            )
        )

    def _containers(
        self,
        value: Any,
        address: str,
        changes: list[dict[str, Any]],
        *,
        service: bool,
    ) -> None:
        if isinstance(value, dict):
            containers = [
                {"name": name, **raw} if isinstance(raw, dict) else {"name": name, "image": raw}
                for name, raw in value.items()
            ]
        elif isinstance(value, list):
            containers = value
        else:
            containers = []
        if not containers and not service:
            changes.append(
                _change(
                    address,
                    "unresolved",
                    "review",
                    f"{self.tool_name} pipeline has no statically analyzable steps.",
                )
            )
            return
        for index, raw in enumerate(containers):
            item_address = f"{address}[{index}]"
            if not isinstance(raw, dict):
                changes.append(
                    _change(item_address, "unresolved", "review", "Container entry is malformed.")
                )
                continue
            image = raw.get("image")
            if image is not None:
                changes.append(
                    _change(
                        f"{item_address}.image",
                        "service_image" if service else "image",
                        "review" if _is_digest_pinned_image(image) else "dangerous",
                        f"{self.tool_name} container image executes pipeline code; pin a trusted "
                        "digest and verify registry credentials.",
                    )
                )
            if raw.get("commands") is not None or raw.get("command") is not None:
                changes.append(
                    _change(
                        f"{item_address}.commands",
                        "service_command" if service else "commands",
                        "dangerous",
                        f"{self.tool_name} container executes arbitrary commands.",
                    )
                )
            if raw.get("privileged") is True:
                changes.append(
                    _change(
                        f"{item_address}.privileged",
                        "privileged",
                        "dangerous",
                        "Privileged container can gain host-level capabilities and must be "
                        "restricted to explicitly trusted repositories and runners.",
                    )
                )
            self._volumes(raw.get("volumes"), f"{item_address}.volumes", changes)
            for key in ("environment", "settings", "secrets"):
                if raw.get(key) is not None:
                    sensitive = key == "secrets" or _pipeline_contains_sensitive_input(raw[key])
                    changes.append(
                        _change(
                            f"{item_address}.{key}",
                            "secret_input" if sensitive else key,
                            "dangerous" if sensitive else "review",
                            f"{self.tool_name} {key} enters the container; verify secret scope, "
                            "literal values, plugin trust, and log handling.",
                        )
                    )
            if str(raw.get("failure", "")).lower() in {"ignore", "always"}:
                changes.append(
                    _change(
                        f"{item_address}.failure",
                        "soft_fail",
                        "dangerous",
                        "Failure policy can bypass a failed security or deployment step.",
                    )
                )
            for key, kind, risk in (
                ("detach", "detached", "review"),
                ("when", "condition", "review"),
                ("depends_on", "dependency", "review"),
                ("backend_options", "backend_options", "dangerous"),
                ("network_mode", "host_network", "dangerous"),
                ("devices", "device", "dangerous"),
                ("cap_add", "capability", "dangerous"),
            ):
                if raw.get(key) is not None:
                    if key == "detach" and raw.get(key) is not True:
                        continue
                    changes.append(
                        _change(
                            f"{item_address}.{key}",
                            kind,
                            risk,
                            f"{self.tool_name} {key} changes execution, host, or "
                            "ordering boundaries.",
                        )
                    )
            if image is None and not any(key in raw for key in ("commands", "command", "settings")):
                changes.append(
                    _change(
                        item_address,
                        "unresolved",
                        "review",
                        f"{self.tool_name} container has no recognized image, commands, "
                        "or settings.",
                    )
                )

    def _volumes(
        self,
        value: Any,
        address: str,
        changes: list[dict[str, Any]],
    ) -> None:
        volumes = value if isinstance(value, list) else [value] if value is not None else []
        for index, volume in enumerate(volumes):
            text = str(volume).lower()
            host = isinstance(volume, dict) and any(
                key in volume for key in ("host", "host_path", "hostPath")
            )
            source = text.split(":", 1)[0]
            host = host or source.startswith(("/", "./", "../", "~")) or "docker.sock" in text
            changes.append(
                _change(
                    f"{address}[{index}]",
                    "host_volume" if host else "volume",
                    "dangerous" if host else "review",
                    "Host volume can expose runner files or container-engine control; named "
                    "volumes still persist data across execution boundaries.",
                )
            )


class DroneCIAdapter(_ContainerPipelineAdapter):
    wrapper_key = "drone_ci"
    tool_name = "Drone CI"

    @property
    def adapter_name(self) -> str:
        return "drone-ci"


class WoodpeckerCIAdapter(_ContainerPipelineAdapter):
    wrapper_key = "woodpecker_ci"
    tool_name = "Woodpecker CI"

    @property
    def adapter_name(self) -> str:
        return "woodpecker-ci"


class ConcourseAdapter(_PipelineAdapter):
    wrapper_key = "concourse"
    tool_name = "Concourse CI"

    @property
    def adapter_name(self) -> str:
        return "concourse"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        pipeline = input_data[self.wrapper_key]
        changes: list[dict[str, Any]] = []
        self._resources(pipeline.get("resource_types"), "resource_types", changes, custom=True)
        self._resources(pipeline.get("resources"), "resources", changes, custom=False)
        var_sources = pipeline.get("var_sources")
        if isinstance(var_sources, list):
            for index, source in enumerate(var_sources):
                changes.append(
                    _change(
                        f"var_sources[{index}]",
                        "var_source",
                        "dangerous",
                        "Concourse variable source connects the pipeline to a credential store; "
                        "verify authentication, TLS, paths, and pipeline/team scope.",
                    )
                )
        jobs = pipeline.get("jobs")
        if isinstance(jobs, list):
            for index, job in enumerate(jobs):
                address = f"jobs[{index}]"
                if not isinstance(job, dict):
                    changes.append(
                        _change(address, "unresolved", "review", "Concourse job is malformed.")
                    )
                    continue
                if job.get("public") is True:
                    changes.append(
                        _change(
                            f"{address}.public",
                            "public_job",
                            "dangerous",
                            "Public Concourse job exposes build output and resource metadata.",
                        )
                    )
                for key in ("serial", "serial_groups", "max_in_flight", "interruptible"):
                    if job.get(key) is not None:
                        changes.append(
                            _change(
                                f"{address}.{key}",
                                "scheduling",
                                "review",
                                "Concourse scheduling changes concurrency and interruption "
                                "behavior.",
                            )
                        )
                self._steps(job.get("plan"), f"{address}.plan", changes)
                for hook in ("on_success", "on_failure", "on_abort", "ensure"):
                    if job.get(hook) is not None:
                        self._steps([job[hook]], f"{address}.{hook}", changes)
        if not changes:
            changes.append(
                _change(
                    "pipeline",
                    "unresolved",
                    "review",
                    "Concourse pipeline has no statically analyzable jobs or resources.",
                )
            )
        changes.append(
            _change(
                "pipeline.effective_configuration",
                "effective_configuration",
                "review",
                "Concourse execution also depends on teams, credential managers, workers, "
                "resource implementations, and variables supplied by fly or parent pipelines.",
            )
        )
        return changes

    def _resources(
        self,
        value: Any,
        address: str,
        changes: list[dict[str, Any]],
        *,
        custom: bool,
    ) -> None:
        if not isinstance(value, list):
            return
        for index, resource in enumerate(value):
            item_address = f"{address}[{index}]"
            if not isinstance(resource, dict):
                changes.append(
                    _change(item_address, "unresolved", "review", "Resource is malformed.")
                )
                continue
            kind = "resource_type" if custom else "resource"
            changes.append(
                _change(
                    item_address,
                    kind,
                    "dangerous" if custom else "review",
                    "Custom Concourse resource types execute external container code."
                    if custom
                    else "Concourse resource reads or writes an external system; review source, "
                    "resource implementation, credentials, and version constraints.",
                )
            )
            if resource.get("public") is True:
                changes.append(
                    _change(
                        f"{item_address}.public",
                        "public_resource",
                        "dangerous",
                        "Public resource exposes version metadata outside the pipeline team.",
                    )
                )
            source = resource.get("source")
            if source is not None and _pipeline_contains_sensitive_input(source):
                changes.append(
                    _change(
                        f"{item_address}.source",
                        "secret_input",
                        "dangerous",
                        "Concourse resource source receives credentials; use scoped dynamic vars "
                        "and verify that resource logs cannot disclose them.",
                    )
                )

    def _steps(self, value: Any, address: str, changes: list[dict[str, Any]]) -> None:
        steps = value if isinstance(value, list) else [value] if value is not None else []
        for index, step in enumerate(steps):
            step_address = f"{address}[{index}]"
            if not isinstance(step, dict):
                changes.append(
                    _change(step_address, "unresolved", "review", "Concourse step is malformed.")
                )
                continue
            if "task" in step:
                changes.append(
                    _change(
                        step_address,
                        "task",
                        "dangerous",
                        "Concourse task executes arbitrary code in a worker container.",
                    )
                )
                if step.get("privileged") is True:
                    changes.append(
                        _change(
                            f"{step_address}.privileged",
                            "privileged",
                            "dangerous",
                            "Privileged Concourse task escapes the worker user namespace and can "
                            "gain host-level capabilities.",
                        )
                    )
                config = step.get("config")
                if isinstance(config, dict):
                    self._task_config(config, f"{step_address}.config", changes)
                if step.get("file") is not None:
                    changes.append(
                        _change(
                            f"{step_address}.file",
                            "external_task",
                            "review",
                            "External Concourse task configuration is not expanded; review the "
                            "selected artifact and pull-request trust boundary.",
                        )
                    )
            if "put" in step:
                changes.append(
                    _change(
                        step_address,
                        "put",
                        "dangerous",
                        "Concourse put step mutates an external resource or publishes artifacts.",
                    )
                )
            if "set_pipeline" in step:
                changes.append(
                    _change(
                        step_address,
                        "set_pipeline",
                        "dangerous",
                        "Concourse set_pipeline step can create or replace pipeline configuration.",
                    )
                )
            if "load_var" in step:
                changes.append(
                    _change(
                        step_address,
                        "load_var",
                        "dangerous",
                        "Concourse load_var imports file content into runtime interpolation; "
                        "verify source trust and disclosure paths.",
                    )
                )
            if "get" in step:
                changes.append(
                    _change(
                        step_address,
                        "get",
                        "review",
                        "Concourse get step imports external artifacts into the build.",
                    )
                )
            if "try" in step:
                changes.append(
                    _change(
                        f"{step_address}.try",
                        "soft_fail",
                        "dangerous",
                        "Concourse try modifier ignores failure and can bypass a security gate.",
                    )
                )
                self._steps([step["try"]], f"{step_address}.try.steps", changes)
            for key in ("params", "vars", "instance_vars"):
                if step.get(key) is not None and _pipeline_contains_sensitive_input(step[key]):
                    changes.append(
                        _change(
                            f"{step_address}.{key}",
                            "secret_input",
                            "dangerous",
                            "Concourse step receives credential-like input; verify dynamic-var "
                            "resolution, scope, and log redaction.",
                        )
                    )
            for key in ("in_parallel", "do", "across"):
                nested = step.get(key)
                if nested is None:
                    continue
                changes.append(
                    _change(
                        f"{step_address}.{key}",
                        "orchestration",
                        "review",
                        "Concourse orchestration changes fan-out, ordering, and concurrency.",
                    )
                )
                if key == "in_parallel" and isinstance(nested, dict):
                    nested = nested.get("steps")
                if key != "across":
                    self._steps(nested, f"{step_address}.{key}.steps", changes)
            for key in ("timeout", "attempts", "tags"):
                if step.get(key) is not None:
                    changes.append(
                        _change(
                            f"{step_address}.{key}",
                            "execution_policy",
                            "review",
                            "Concourse modifier changes retries, duration, or worker selection.",
                        )
                    )
            for hook in ("on_success", "on_failure", "on_abort", "ensure"):
                if step.get(hook) is not None:
                    self._steps([step[hook]], f"{step_address}.{hook}", changes)

    def _task_config(
        self, config: dict[str, Any], address: str, changes: list[dict[str, Any]]
    ) -> None:
        image = config.get("image_resource")
        if image is not None:
            source = image.get("source", {}) if isinstance(image, dict) else {}
            pinned = isinstance(source, dict) and (
                bool(source.get("digest"))
                or "@sha256:" in str(source.get("repository", "")).lower()
            )
            changes.append(
                _change(
                    f"{address}.image_resource",
                    "image",
                    "review" if pinned else "dangerous",
                    "Concourse task image executes build code; pin a trusted digest and verify "
                    "the resource type and registry credentials.",
                )
            )
        if config.get("run") is not None:
            changes.append(
                _change(
                    f"{address}.run",
                    "command",
                    "dangerous",
                    "Concourse task run configuration executes arbitrary commands.",
                )
            )
        if config.get("params") is not None and _pipeline_contains_sensitive_input(
            config["params"]
        ):
            changes.append(
                _change(
                    f"{address}.params",
                    "secret_input",
                    "dangerous",
                    "Concourse task parameters contain credential-like values or references.",
                )
            )


class BambooAdapter(_PipelineAdapter):
    wrapper_key = "bamboo"
    tool_name = "Bamboo Specs"
    _RESERVED = {
        "version",
        "plan",
        "deployment",
        "plan-permissions",
        "deployment-permissions",
        "stages",
        "branches",
        "triggers",
        "notifications",
        "variables",
        "repositories",
        "release-naming",
        "environments",
        "docker",
        "other",
    }

    @property
    def adapter_name(self) -> str:
        return "bamboo"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        wrapped = input_data[self.wrapper_key]
        documents = wrapped.get("documents") if isinstance(wrapped, dict) else None
        documents = documents if isinstance(documents, list) else [wrapped]
        changes: list[dict[str, Any]] = []
        for index, document in enumerate(documents):
            address = f"documents[{index}]" if len(documents) > 1 else "spec"
            if not isinstance(document, dict):
                continue
            self._document(document, address, changes)
        if not changes:
            changes.append(
                _change(
                    "spec",
                    "unresolved",
                    "review",
                    "Bamboo Specs document has no statically analyzable plan or deployment.",
                )
            )
        return changes

    def _document(
        self, document: dict[str, Any], address: str, changes: list[dict[str, Any]]
    ) -> None:
        for key in ("plan", "deployment"):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        f"{address}.{key}",
                        key,
                        "dangerous" if key == "deployment" else "review",
                        "Bamboo deployment can mutate target environments."
                        if key == "deployment"
                        else "Bamboo plan defines executable build configuration.",
                    )
                )
        for key in ("plan-permissions", "deployment-permissions"):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "permissions",
                        "dangerous",
                        "Bamboo Specs changes who can view, edit, build, or deploy this entity.",
                    )
                )
        for key in ("triggers", "branches", "notifications", "release-naming"):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "trigger" if key == "triggers" else key.replace("-", "_"),
                        "review",
                        "Bamboo automation changes execution, release, or notification policy.",
                    )
                )
        for key in ("variables", "repositories"):
            if document.get(key) is not None:
                sensitive = _pipeline_contains_sensitive_input(document[key])
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "secret_input" if sensitive else key,
                        "dangerous" if sensitive else "review",
                        "Bamboo configuration crosses a repository or credential boundary; "
                        "verify linked-repository permissions and encrypted variables.",
                    )
                )
        if document.get("docker") is not None:
            changes.append(
                _change(
                    f"{address}.docker",
                    "container",
                    "dangerous",
                    "Bamboo Docker runner changes the build image, mounts, and host access.",
                )
            )
        environments = document.get("environments")
        environment_names = (
            {str(name) for name in environments} if isinstance(environments, list) else set()
        )
        for key, value in document.items():
            if key in self._RESERVED or key in environment_names or not isinstance(value, dict):
                continue
            self._job(value, f"{address}.{key}", changes)
        if isinstance(environments, list):
            for name in environments:
                config = document.get(str(name))
                if isinstance(config, dict):
                    self._job(config, f"{address}.environment.{name}", changes)
        changes.append(
            _change(
                f"{address}.effective_configuration",
                "effective_configuration",
                "review",
                "Bamboo execution also depends on linked repositories, agent capabilities, "
                "global variables, project permissions, and server-side plugins.",
            )
        )

    def _job(
        self, job: dict[str, Any], address: str, changes: list[dict[str, Any]]
    ) -> None:
        for key in ("tasks", "final-tasks"):
            tasks = job.get(key)
            if not isinstance(tasks, list):
                continue
            for index, task in enumerate(tasks):
                task_address = f"{address}.{key}[{index}]"
                if isinstance(task, str):
                    task_name = task
                elif isinstance(task, dict) and task:
                    task_name = str(next(iter(task)))
                else:
                    task_name = "unresolved"
                safe = task_name == "test-parser"
                risk = (
                    "safe"
                    if safe
                    else "review"
                    if task_name == "artifact-download"
                    else "dangerous"
                )
                changes.append(
                    _change(
                        task_address,
                        "task",
                        risk,
                        "Bamboo task records or retrieves build output without executing commands."
                        if safe
                        else f"Bamboo task '{task_name}' can execute code or mutate external "
                        "state.",
                    )
                )
                if _pipeline_contains_sensitive_input(task):
                    changes.append(
                        _change(
                            f"{task_address}.secrets",
                            "secret_input",
                            "dangerous",
                            "Bamboo task receives credential-like values; use encrypted or "
                            "server-managed variables and verify log redaction.",
                        )
                    )
        for key in ("artifacts", "requirements", "clean-working-dir", "docker"):
            if job.get(key) is not None:
                changes.append(
                    _change(
                        f"{address}.{key}",
                        key.replace("-", "_"),
                        "dangerous" if key in {"clean-working-dir", "docker"} else "review",
                        "Bamboo job setting changes agents, persistence, cleanup, or artifact "
                        "flow.",
                    )
                )


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


def analyze_azure_pipelines(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_pipeline(AzurePipelinesAdapter(), data, catalog=catalog)


def analyze_bitbucket_pipelines(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_pipeline(BitbucketPipelinesAdapter(), data, catalog=catalog)


def analyze_buildkite(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_pipeline(BuildkiteAdapter(), data, catalog=catalog)


def analyze_travis_ci(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_pipeline(TravisCIAdapter(), data, catalog=catalog)


def analyze_drone_ci(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_pipeline(DroneCIAdapter(), data, catalog=catalog)


def analyze_woodpecker_ci(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_pipeline(WoodpeckerCIAdapter(), data, catalog=catalog)


def analyze_concourse(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_pipeline(ConcourseAdapter(), data, catalog=catalog)


def analyze_bamboo(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_pipeline(BambooAdapter(), data, catalog=catalog)
