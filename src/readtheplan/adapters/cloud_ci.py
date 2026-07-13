from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class CloudCIInputError(ValueError):
    """Raised when a cloud-native build or pipeline document is invalid."""


_SENSITIVE_NAME = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:access[._-]?key|api[._-]?key|credential|passwd|password|"
    r"private[._-]?key|secret|token)(?=$|[^A-Za-z0-9])",
    re.IGNORECASE,
)


def parse_cloud_ci(source: str, ecosystem: str) -> dict[str, Any]:
    if not source.strip():
        raise CloudCIInputError("input is empty")
    wrappers = {
        "codebuild": "codebuild",
        "cloud-build": "cloud_build",
        "codepipeline": "codepipeline",
    }
    try:
        wrapper = wrappers[ecosystem]
    except KeyError as exc:
        raise CloudCIInputError(f"unsupported cloud CI ecosystem: {ecosystem}") from exc
    try:
        parsed = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise CloudCIInputError(str(exc)) from exc
    if not isinstance(parsed, dict):
        raise CloudCIInputError("configuration must be an object")
    return {wrapper: parsed}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {
        "Address": address,
        "Kind": kind,
        "Risk": risk,
        "Explanation": explanation,
    }


def _contains_sensitive(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            _SENSITIVE_NAME.search(str(key)) is not None or _contains_sensitive(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive(item) for item in value)
    text = str(value)
    return bool(
        _SENSITIVE_NAME.search(text)
        or re.search(
            r"(?:(?:\$\{?|\$\$)[^}\s]*(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY)|"
            r"secretmanager|parameter[-_]?store|kmsKeyName|secrets-manager)",
            text,
            re.IGNORECASE,
        )
    )


def _digest_pinned_image(value: Any) -> bool:
    return "@sha256:" in str(value).lower()


class _CloudCIAdapter(BaseAdapter):
    wrapper_key = ""
    tool_name = "Cloud CI"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        return isinstance(input_data.get(self.wrapper_key), dict)

    def normalize_change(self, raw_change: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw_change["Address"]),
            resource_type=f"{self.adapter_name.replace('-', '_')}_{raw_change['Kind']}",
            actions=("execute",),
            risk=str(raw_change["Risk"]),
            explanation=str(raw_change["Explanation"]),
        )


class CodeBuildAdapter(_CloudCIAdapter):
    wrapper_key = "codebuild"
    tool_name = "AWS CodeBuild"

    @property
    def adapter_name(self) -> str:
        return "codebuild"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        buildspec = input_data[self.wrapper_key]
        changes: list[dict[str, Any]] = []
        version = str(buildspec.get("version", ""))
        if version:
            changes.append(
                _change(
                    "buildspec.version",
                    "version",
                    "review" if version == "0.2" else "dangerous",
                    "CodeBuild buildspec 0.2 shares shell state across commands; older or "
                    "unknown versions can materially change command behavior.",
                )
            )
        self._run_as(buildspec.get("run-as"), "buildspec.run-as", changes)
        self._environment(buildspec.get("env"), "buildspec.env", changes)
        phases = buildspec.get("phases")
        if isinstance(phases, dict):
            for phase_name, raw_phase in phases.items():
                address = f"buildspec.phases.{phase_name}"
                if not isinstance(raw_phase, dict):
                    changes.append(
                        _change(address, "unresolved", "review", "Build phase is malformed.")
                    )
                    continue
                self._run_as(raw_phase.get("run-as"), f"{address}.run-as", changes)
                for command_key in ("commands", "finally"):
                    if raw_phase.get(command_key) is not None:
                        changes.append(
                            _change(
                                f"{address}.{command_key}",
                                "command",
                                "dangerous",
                                "CodeBuild phase executes arbitrary commands in the build "
                                "environment.",
                            )
                        )
                if raw_phase.get("on-failure") is not None:
                    policy = str(raw_phase["on-failure"]).upper()
                    changes.append(
                        _change(
                            f"{address}.on-failure",
                            "failure_policy",
                            "dangerous" if "CONTINUE" in policy else "review",
                            "CodeBuild failure policy can retry or continue after a failed "
                            "security or deployment command.",
                        )
                    )
                if raw_phase.get("runtime-versions") is not None:
                    changes.append(
                        _change(
                            f"{address}.runtime-versions",
                            "runtime",
                            "review",
                            "CodeBuild runtime selection changes the executable toolchain.",
                        )
                    )
        else:
            changes.append(
                _change(
                    "buildspec.phases",
                    "unresolved",
                    "review",
                    "CodeBuild buildspec has no statically analyzable phases.",
                )
            )
        for key, kind, risk, explanation in (
            (
                "batch",
                "batch",
                "review",
                "Batch configuration fans builds out and changes failure propagation.",
            ),
            (
                "artifacts",
                "artifact",
                "review",
                "CodeBuild publishes files to its configured artifact destination.",
            ),
            (
                "reports",
                "report",
                "safe",
                "CodeBuild report groups publish test or coverage results.",
            ),
            (
                "cache",
                "cache",
                "review",
                "CodeBuild cache persists files across otherwise isolated builds.",
            ),
            (
                "proxy",
                "proxy",
                "review",
                "CodeBuild proxy settings change log and artifact egress paths.",
            ),
        ):
            if buildspec.get(key) is not None:
                changes.append(_change(f"buildspec.{key}", kind, risk, explanation))
        changes.append(
            _change(
                "buildspec.effective_configuration",
                "effective_configuration",
                "review",
                "CodeBuild execution also depends on the project service role, source, build "
                "image, compute mode, VPC, webhooks, environment overrides, and artifact stores.",
            )
        )
        return changes

    def _run_as(
        self, value: Any, address: str, changes: list[dict[str, Any]]
    ) -> None:
        if value is None:
            return
        root = str(value).strip().lower() in {"root", "0"}
        changes.append(
            _change(
                address,
                "run_as",
                "dangerous" if root else "review",
                "CodeBuild changes the Linux identity used for build commands; root execution "
                "expands impact inside the build environment.",
            )
        )

    def _environment(
        self, value: Any, address: str, changes: list[dict[str, Any]]
    ) -> None:
        if not isinstance(value, dict):
            return
        variables = value.get("variables")
        if variables is not None:
            sensitive = _contains_sensitive(variables)
            changes.append(
                _change(
                    f"{address}.variables",
                    "secret_input" if sensitive else "environment",
                    "dangerous" if sensitive else "review",
                    "CodeBuild plaintext environment values enter every phase; sensitive "
                    "values should use Parameter Store or Secrets Manager.",
                )
            )
        for key in ("parameter-store", "secrets-manager"):
            if value.get(key) is not None:
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "secret_input",
                        "dangerous",
                        "CodeBuild resolves managed secrets into build environment variables; "
                        "verify service-role access, secret scope, and log handling.",
                    )
                )
        if value.get("exported-variables") is not None:
            changes.append(
                _change(
                    f"{address}.exported-variables",
                    "exported_environment",
                    "dangerous"
                    if _contains_sensitive(value["exported-variables"])
                    else "review",
                    "CodeBuild exports environment values to downstream CodePipeline actions.",
                )
            )
        if value.get("git-credential-helper") in {True, "yes", "true"}:
            changes.append(
                _change(
                    f"{address}.git-credential-helper",
                    "git_credentials",
                    "dangerous",
                    "CodeBuild exposes Git credentials to build commands through a helper.",
                )
            )
        if value.get("shell") is not None:
            changes.append(
                _change(
                    f"{address}.shell",
                    "shell",
                    "review",
                    "CodeBuild shell selection changes command parsing and execution semantics.",
                )
            )


class GoogleCloudBuildAdapter(_CloudCIAdapter):
    wrapper_key = "cloud_build"
    tool_name = "Google Cloud Build"

    @property
    def adapter_name(self) -> str:
        return "cloud-build"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        build = input_data[self.wrapper_key]
        changes: list[dict[str, Any]] = []
        steps = build.get("steps")
        if isinstance(steps, list):
            for index, step in enumerate(steps):
                address = f"build.steps[{index}]"
                if not isinstance(step, dict):
                    changes.append(
                        _change(address, "unresolved", "review", "Cloud Build step is malformed.")
                    )
                    continue
                image = step.get("name")
                if image is not None:
                    changes.append(
                        _change(
                            f"{address}.name",
                            "image",
                            "review" if _digest_pinned_image(image) else "dangerous",
                            "Cloud Build step image executes build code; pin a trusted digest "
                            "and verify the registry source.",
                        )
                    )
                if any(step.get(key) is not None for key in ("args", "script", "entrypoint")):
                    changes.append(
                        _change(
                            f"{address}.command",
                            "command",
                            "dangerous",
                            "Cloud Build step executes arbitrary commands in its container.",
                        )
                    )
                if step.get("secretEnv") is not None:
                    changes.append(
                        _change(
                            f"{address}.secretEnv",
                            "secret_input",
                            "dangerous",
                            "Cloud Build injects Secret Manager or KMS-backed values into this "
                            "step; verify service-account access and log redaction.",
                        )
                    )
                if step.get("env") is not None:
                    sensitive = _contains_sensitive(step["env"])
                    changes.append(
                        _change(
                            f"{address}.env",
                            "secret_input" if sensitive else "environment",
                            "dangerous" if sensitive else "review",
                            "Cloud Build environment values enter the step process.",
                        )
                    )
                if step.get("volumes") is not None:
                    changes.append(
                        _change(
                            f"{address}.volumes",
                            "volume",
                            "review",
                            "Cloud Build volume shares mutable files between build steps.",
                        )
                    )
                if step.get("allowFailure") is True or step.get("allowExitCodes"):
                    changes.append(
                        _change(
                            f"{address}.failure-policy",
                            "soft_fail",
                            "dangerous",
                            "Cloud Build step can succeed despite selected command failures.",
                        )
                    )
                for key in ("waitFor", "timeout", "dir"):
                    if step.get(key) is not None:
                        changes.append(
                            _change(
                                f"{address}.{key}",
                                "execution_policy",
                                "review",
                                "Cloud Build step changes ordering, duration, or workspace path.",
                            )
                        )
        else:
            changes.append(
                _change(
                    "build.steps",
                    "unresolved",
                    "review",
                    "Cloud Build configuration has no statically analyzable steps.",
                )
            )
        for key in ("availableSecrets", "secrets"):
            if build.get(key) is not None:
                changes.append(
                    _change(
                        f"build.{key}",
                        "secret_input",
                        "dangerous",
                        "Cloud Build configuration grants runtime access to encrypted secrets.",
                    )
                )
        if build.get("serviceAccount") is not None:
            changes.append(
                _change(
                    "build.serviceAccount",
                    "service_account",
                    "dangerous",
                    "Cloud Build service account controls permissions available to every step.",
                )
            )
        substitutions = build.get("substitutions")
        if substitutions is not None:
            sensitive = _contains_sensitive(substitutions)
            changes.append(
                _change(
                    "build.substitutions",
                    "secret_input" if sensitive else "substitution",
                    "dangerous" if sensitive else "review",
                    "Cloud Build substitutions are interpolated into step configuration.",
                )
            )
        options = build.get("options")
        if isinstance(options, dict) and (
            options.get("secretEnv") is not None
            or (
                options.get("env") is not None
                and _contains_sensitive(options["env"])
            )
        ):
            changes.append(
                _change(
                    "build.options.environment",
                    "secret_input",
                    "dangerous",
                    "Cloud Build global options inject credential-like environment values into "
                    "multiple steps.",
                )
            )
        for key, kind, risk, explanation in (
            (
                "images",
                "image_publish",
                "dangerous",
                "Cloud Build publishes container image references after successful execution.",
            ),
            (
                "artifacts",
                "artifact",
                "dangerous",
                "Cloud Build publishes build output to external artifact storage.",
            ),
            (
                "options",
                "options",
                "review",
                "Cloud Build options change workers, logging, verification, pools, and globals.",
            ),
            (
                "logsBucket",
                "logging",
                "review",
                "Cloud Build sends logs to a selected Cloud Storage bucket.",
            ),
            (
                "source",
                "source",
                "review",
                "Cloud Build imports source from an external repository or storage object.",
            ),
        ):
            if build.get(key) is not None:
                changes.append(_change(f"build.{key}", kind, risk, explanation))
        changes.append(
            _change(
                "build.effective_configuration",
                "effective_configuration",
                "review",
                "Cloud Build execution also depends on trigger substitutions, IAM, worker "
                "pools, organization policy, source provenance, and registry permissions.",
            )
        )
        return changes


class CodePipelineAdapter(_CloudCIAdapter):
    wrapper_key = "codepipeline"
    tool_name = "AWS CodePipeline"

    @property
    def adapter_name(self) -> str:
        return "codepipeline"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        wrapped = input_data.get(self.wrapper_key)
        return isinstance(wrapped, dict) and isinstance(wrapped.get("pipeline", wrapped), dict)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        wrapped = input_data[self.wrapper_key]
        pipeline = wrapped.get("pipeline", wrapped)
        changes: list[dict[str, Any]] = []
        if pipeline.get("roleArn") is not None:
            changes.append(
                _change(
                    "pipeline.roleArn",
                    "service_role",
                    "dangerous",
                    "CodePipeline service role controls access available to pipeline actions.",
                )
            )
        if pipeline.get("artifactStore") is not None or pipeline.get("artifactStores") is not None:
            changes.append(
                _change(
                    "pipeline.artifactStores",
                    "artifact_store",
                    "review",
                    "CodePipeline artifact stores move build inputs and outputs across stages; "
                    "verify bucket policy, encryption keys, regions, and retention.",
                )
            )
        stages = pipeline.get("stages")
        if isinstance(stages, list):
            for stage_index, stage in enumerate(stages):
                stage_address = f"pipeline.stages[{stage_index}]"
                if not isinstance(stage, dict):
                    changes.append(
                        _change(stage_address, "unresolved", "review", "Stage is malformed.")
                    )
                    continue
                actions = stage.get("actions")
                if not isinstance(actions, list):
                    continue
                for action_index, action in enumerate(actions):
                    self._action(
                        action,
                        f"{stage_address}.actions[{action_index}]",
                        changes,
                    )
        else:
            changes.append(
                _change(
                    "pipeline.stages",
                    "unresolved",
                    "review",
                    "CodePipeline definition has no statically analyzable stages.",
                )
            )
        for key in ("triggers", "variables"):
            if pipeline.get(key) is not None:
                changes.append(
                    _change(
                        f"pipeline.{key}",
                        "trigger" if key == "triggers" else "variable",
                        "review",
                        "CodePipeline configuration changes execution triggers or variables.",
                    )
                )
        for key in ("pipelineType", "executionMode"):
            if pipeline.get(key) is not None:
                changes.append(
                    _change(
                        f"pipeline.{key}",
                        "execution_policy",
                        "review",
                        "CodePipeline mode changes concurrency, supersession, or pricing behavior.",
                    )
                )
        changes.append(
            _change(
                "pipeline.effective_configuration",
                "effective_configuration",
                "review",
                "CodePipeline execution also depends on provider integrations, IAM roles, "
                "webhooks/EventBridge rules, artifact contents, KMS policies, and regions.",
            )
        )
        return changes

    def _action(
        self, action: Any, address: str, changes: list[dict[str, Any]]
    ) -> None:
        if not isinstance(action, dict):
            changes.append(_change(address, "unresolved", "review", "Action is malformed."))
            return
        action_type = action.get("actionTypeId")
        action_type = action_type if isinstance(action_type, dict) else {}
        category = str(action_type.get("category", "unknown")).lower()
        dangerous = category in {"build", "deploy", "invoke", "test"}
        changes.append(
            _change(
                address,
                f"{category}_action" if category else "action",
                "dangerous" if dangerous else "review",
                "CodePipeline action can execute code or mutate a deployment target."
                if dangerous
                else "CodePipeline action imports source or requires manual approval; review "
                "provider, owner, version, region, and artifact trust.",
            )
        )
        if action.get("roleArn") is not None:
            changes.append(
                _change(
                    f"{address}.roleArn",
                    "action_role",
                    "dangerous",
                    "Action-level IAM role controls permissions for this provider invocation.",
                )
            )
        configuration = action.get("configuration")
        if configuration is not None:
            sensitive = _contains_sensitive(configuration)
            mutating = category in {"build", "deploy", "invoke"}
            changes.append(
                _change(
                    f"{address}.configuration",
                    "secret_input" if sensitive else "action_configuration",
                    "dangerous" if sensitive or mutating else "review",
                    "CodePipeline provider configuration supplies runtime parameters and may "
                    "contain credential-like values or deployment capabilities.",
                )
            )
        if action.get("inputArtifacts") is not None or action.get("outputArtifacts") is not None:
            changes.append(
                _change(
                    f"{address}.artifacts",
                    "artifact_flow",
                    "review",
                    "CodePipeline action consumes or produces artifacts across a trust boundary.",
                )
            )
        for key in ("runOrder", "region", "namespace"):
            if action.get(key) is not None:
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "execution_policy",
                        "review",
                        "CodePipeline action changes ordering, region, or variable namespace.",
                    )
                )


def analyze_cloud_ci(
    adapter: _CloudCIAdapter, data: dict[str, Any], *, catalog=None
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


def analyze_codebuild(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_cloud_ci(CodeBuildAdapter(), data, catalog=catalog)


def analyze_google_cloud_build(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_cloud_ci(GoogleCloudBuildAdapter(), data, catalog=catalog)


def analyze_codepipeline(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return analyze_cloud_ci(CodePipelineAdapter(), data, catalog=catalog)
