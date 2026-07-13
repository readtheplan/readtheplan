from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class SpaceliftInputError(ValueError):
    """Raised when input is not recognizable Spacelift runtime configuration."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise SpaceliftInputError("Spacelift YAML mapping keys must be scalar") from exc
        if duplicate:
            raise SpaceliftInputError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)

_HOOK_KEYS = (
    "before_init",
    "after_init",
    "before_plan",
    "after_plan",
    "before_apply",
    "after_apply",
    "before_perform",
    "after_perform",
    "before_destroy",
    "after_destroy",
    "after_run",
)
_BLOCK_KEYS = {
    *_HOOK_KEYS,
    "environment",
    "project_root",
    "runner_image",
    "terraform_version",
    "opentofu_version",
    "terraform_workflow_tool",
    "git_sparse_checkout_paths",
    "terragrunt",
}
_TOP_LEVEL_KEYS = {
    "version",
    "stack_defaults",
    "stacks",
    "module_version",
    "test_defaults",
    "tests",
}
_SECRET_NAME = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)",
    re.I,
)
_EXACT_VERSION = re.compile(r"^v?\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?$")
_MODULE_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_IMAGE_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$", re.I)
_REMOTE = re.compile(r"^(?:https?|git|ssh|file)://|^[^/@\s]+@[^:\s]+:", re.I)


def parse_spacelift(source: str) -> dict[str, Any]:
    """Parse repo-level or single-stack Spacelift runtime YAML without executing it."""
    if not source.strip():
        raise SpaceliftInputError("input is empty")
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except SpaceliftInputError:
        raise
    except yaml.YAMLError as exc:
        raise SpaceliftInputError(f"invalid Spacelift YAML: {exc}") from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise SpaceliftInputError("input must contain exactly one configuration object")
    config = documents[0]
    repo_level = any(key in config for key in ("stack_defaults", "stacks", "tests"))
    single_stack = bool(set(config) & _BLOCK_KEYS)
    if not repo_level and not single_stack:
        raise SpaceliftInputError(
            "configuration must declare stack_defaults, stacks, tests, or runtime settings"
        )
    for key in ("stack_defaults", "stacks", "test_defaults"):
        if key in config and not isinstance(config[key], dict):
            raise SpaceliftInputError(f"{key} must be a mapping")
    if "tests" in config and not isinstance(config["tests"], list):
        raise SpaceliftInputError("tests must be a list")
    return {"spacelift": {"config": config, "repo_level": repo_level}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _external_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        bool(_REMOTE.match(normalized))
        or path.is_absolute()
        or ".." in path.parts
        or bool(re.match(r"^[A-Za-z]:/", normalized))
    )


def _embedded_credential(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _runtime_block_changes(block: dict[str, Any], prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for hook in _HOOK_KEYS:
        commands = block.get(hook)
        if commands is None:
            continue
        if not isinstance(commands, list) or not all(isinstance(item, str) for item in commands):
            changes.append(
                _change(
                    f"{prefix}.{hook}",
                    "invalid_hook_shape",
                    "dangerous",
                    f"Spacelift {hook} is not a list of command strings; runtime behavior "
                    "is ambiguous.",
                )
            )
            continue
        for index, _command in enumerate(commands):
            changes.append(
                _change(
                    f"{prefix}.{hook}[{index}]",
                    "workflow_hook",
                    "dangerous",
                    f"Spacelift executes a configured {hook} command in the worker; review the "
                    "command source, shell expansion, credentials, network/filesystem access, "
                    "failure behavior, and phase ordering. Command text is omitted from output.",
                )
            )

    environment = block.get("environment")
    if environment is not None and not isinstance(environment, dict):
        changes.append(
            _change(
                f"{prefix}.environment",
                "invalid_environment_shape",
                "dangerous",
                "Spacelift environment must be a mapping; runtime inputs are ambiguous.",
            )
        )
    for name, value in _mapping(environment).items():
        address = f"{prefix}.environment.{name}"
        secret = bool(_SECRET_NAME.search(str(name)))
        changes.append(
            _change(
                address,
                "literal_secret_environment" if secret else "runtime_environment",
                "dangerous" if secret else "review",
                "Spacelift runtime configuration supplies credential-like environment data; "
                "the value is omitted from analysis output. Prefer an attached secret context."
                if secret
                else "Spacelift runtime configuration overrides an environment variable ahead "
                "of attached contexts and stack settings; review its effect on the IaC workflow.",
            )
        )

    project_root = block.get("project_root")
    if project_root not in (None, ""):
        text = str(project_root)
        changes.append(
            _change(
                f"{prefix}.project_root",
                "project_root",
                "dangerous" if _external_path(text) else "review",
                "Spacelift selects a project root outside the repository boundary."
                if _external_path(text)
                else "Spacelift changes the repository subdirectory used as the workflow root; "
                "review monorepo ownership and affected infrastructure.",
            )
        )

    image = block.get("runner_image")
    if image not in (None, ""):
        text = str(image)
        pinned = bool(_IMAGE_DIGEST.search(text))
        risky = not pinned or _embedded_credential(text)
        changes.append(
            _change(
                f"{prefix}.runner_image",
                "runner_image",
                "dangerous" if risky else "review",
                "Spacelift uses a mutable or credential-bearing custom runner image; it can "
                "change every command's execution environment."
                if risky
                else "Spacelift uses a digest-pinned custom runner image; review its provenance, "
                "contents, privileges, and worker-pool trust.",
            )
        )

    for key in ("terraform_version", "opentofu_version"):
        version = block.get(key)
        if version not in (None, ""):
            exact = bool(_EXACT_VERSION.fullmatch(str(version)))
            changes.append(
                _change(
                    f"{prefix}.{key}",
                    "workflow_version",
                    "review" if exact else "dangerous",
                    f"Spacelift selects an exact {key.replace('_', ' ')} for runs."
                    if exact
                    else f"Spacelift {key.replace('_', ' ')} is not an exact version; the "
                    "workflow implementation may drift between runs.",
                )
            )

    workflow_tool = block.get("terraform_workflow_tool")
    if workflow_tool not in (None, ""):
        tool = str(workflow_tool).upper()
        risk = (
            "dangerous"
            if tool == "CUSTOM" or tool not in {"TERRAFORM_FOSS", "OPEN_TOFU"}
            else "review"
        )
        changes.append(
            _change(
                f"{prefix}.terraform_workflow_tool",
                "workflow_tool",
                risk,
                "Spacelift delegates the Terraform workflow to custom or unrecognized tooling; "
                "review the executable, provisioning, arguments, and trust boundary."
                if risk == "dangerous"
                else f"Spacelift selects {tool} as the Terraform-compatible workflow engine.",
            )
        )

    sparse_paths = block.get("git_sparse_checkout_paths")
    if sparse_paths is not None and not isinstance(sparse_paths, list):
        changes.append(
            _change(
                f"{prefix}.git_sparse_checkout_paths",
                "invalid_sparse_checkout",
                "dangerous",
                "Spacelift sparse checkout paths must be a list of repository-relative paths.",
            )
        )
    for index, raw_path in enumerate(_items(sparse_paths)):
        text = str(raw_path)
        invalid = _external_path(text) or any(char in text for char in "*?[")
        changes.append(
            _change(
                f"{prefix}.git_sparse_checkout_paths[{index}]",
                "sparse_checkout_path",
                "dangerous" if invalid else "review",
                "Spacelift sparse checkout uses a glob or non-confined path even though only "
                "repository-relative literal paths are supported."
                if invalid
                else "Spacelift limits checked-out repository content; review whether omitted "
                "policy, module, or ownership files change the effective workflow.",
            )
        )

    terragrunt = block.get("terragrunt")
    if terragrunt is not None and not isinstance(terragrunt, dict):
        changes.append(
            _change(
                f"{prefix}.terragrunt",
                "invalid_terragrunt_shape",
                "dangerous",
                "Spacelift Terragrunt settings must be a mapping and replace the whole "
                "stack configuration.",
            )
        )
    elif isinstance(terragrunt, dict):
        tool = str(terragrunt.get("terragrunt_tool") or "TERRAFORM_FOSS").upper()
        manual = tool == "MANUALLY_PROVISIONED"
        changes.append(
            _change(
                f"{prefix}.terragrunt",
                "terragrunt_configuration",
                "dangerous" if manual else "review",
                "Spacelift replaces all Terragrunt settings and delegates execution to a "
                "manually provisioned tool."
                if manual
                else "Spacelift replaces the complete Terragrunt setting block; review tool and "
                "version selection, sanitization, and state ownership.",
            )
        )
        if terragrunt.get("use_run_all"):
            changes.append(
                _change(
                    f"{prefix}.terragrunt.use_run_all",
                    "terragrunt_run_all",
                    "dangerous",
                    "Spacelift enables Terragrunt run-all, expanding one run across multiple "
                    "modules.",
                )
            )
        if terragrunt.get("use_state_management"):
            changes.append(
                _change(
                    f"{prefix}.terragrunt.use_state_management",
                    "managed_state",
                    "dangerous",
                    "Spacelift assumes management of Terraform/OpenTofu state for this "
                    "Terragrunt stack.",
                )
            )

    unknown = sorted(str(key) for key in set(block) - _BLOCK_KEYS)
    if unknown:
        changes.append(
            _change(
                f"{prefix}.unknown_settings",
                "unknown_runtime_settings",
                "review",
                "Spacelift runtime block contains settings outside the analyzed schema: "
                + ", ".join(unknown),
            )
        )
    return changes


def _config_changes(config: dict[str, Any], repo_level: bool) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if repo_level:
        version = str(config.get("version") or "1")
        if version != "2":
            changes.append(
                _change(
                    "spacelift.version",
                    "legacy_precedence",
                    "dangerous",
                    f"Spacelift runtime schema {version!r} does not use version 2 precedence; "
                    "effective defaults may differ from repository expectations.",
                )
            )
        module_version = config.get("module_version")
        if module_version not in (None, ""):
            exact = bool(_MODULE_VERSION.fullmatch(str(module_version)))
            changes.append(
                _change(
                    "spacelift.module_version",
                    "module_version",
                    "review" if exact else "dangerous",
                    "Spacelift pins the module release to an exact stable semantic version."
                    if exact
                    else "Spacelift module_version must be a stable major.minor.patch version; "
                    "pre-release, build, range, and floating forms are not supported.",
                )
            )
        changes.extend(
            _runtime_block_changes(_mapping(config.get("stack_defaults")), "stack_defaults")
        )
        for slug, raw_block in _mapping(config.get("stacks")).items():
            prefix = f"stacks.{slug}"
            if not isinstance(raw_block, dict):
                changes.append(
                    _change(
                        prefix,
                        "invalid_stack",
                        "dangerous",
                        "Spacelift stack settings must be a mapping.",
                    )
                )
                continue
            changes.append(
                _change(
                    prefix,
                    "stack_override",
                    "review",
                    "Stack-specific runtime configuration overrides repository defaults and "
                    "UI settings.",
                )
            )
            changes.extend(_runtime_block_changes(raw_block, prefix))
        changes.extend(
            _runtime_block_changes(_mapping(config.get("test_defaults")), "test_defaults")
        )
        for index, raw_test in enumerate(_items(config.get("tests"))):
            prefix = f"tests[{index}]"
            if not isinstance(raw_test, dict):
                changes.append(
                    _change(
                        prefix,
                        "invalid_module_test",
                        "dangerous",
                        "Spacelift module test must be a mapping.",
                    )
                )
                continue
            name = str(raw_test.get("name") or index)
            test_prefix = f"tests.{name}"
            changes.append(
                _change(
                    test_prefix,
                    "module_test",
                    "review",
                    "Spacelift defines a module test; review dependency ordering, "
                    "negative-test semantics, runtime overrides, and isolation.",
                )
            )
            changes.extend(_runtime_block_changes(raw_test, test_prefix))
        unknown = sorted(str(key) for key in set(config) - _TOP_LEVEL_KEYS)
        if unknown:
            changes.append(
                _change(
                    "spacelift.unknown_settings",
                    "unknown_top_level_settings",
                    "review",
                    "Spacelift configuration contains unrecognized top-level settings: "
                    + ", ".join(unknown),
                )
            )
    else:
        changes.append(
            _change(
                "runtime",
                "single_stack_runtime",
                "review",
                "Input is single-stack spacectl runtime configuration; its target stack and "
                "UI baseline are not present.",
            )
        )
        changes.extend(_runtime_block_changes(config, "runtime"))
    changes.append(
        _change(
            "spacelift.effective_configuration",
            "evaluation_boundary",
            "review",
            "Static analysis does not execute hooks, pull runner images, resolve YAML outside "
            "this document, combine contexts/UI/account defaults, contact Spacelift, inspect "
            "worker pools, or run IaC tools.",
        )
    )
    return changes


class SpaceliftAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "spacelift"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("spacelift")
        return isinstance(payload, dict) and isinstance(payload.get("config"), dict)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["spacelift"]
        return _config_changes(payload["config"], bool(payload.get("repo_level")))

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"spacelift_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_spacelift(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = SpaceliftAdapter().analyze(data, tool_name="Spacelift")
    summary = PlanSummary(
        path=Path("spacelift://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Spacelift")
    config = data["spacelift"]["config"]
    gate["adapter"] = "spacelift"
    gate["configuration_scope"] = (
        "repository" if data["spacelift"]["repo_level"] else "single-stack"
    )
    gate["stack_count"] = len(_mapping(config.get("stacks")))
    gate["total_changes"] = len(changes)
    return gate
