from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class TerraformConfigInputError(ValueError):
    """Raised when Terraform or Terragrunt HCL/JSON is invalid or unrecognizable."""


_TERRAFORM_KEYS = {
    "check",
    "data",
    "ephemeral",
    "import",
    "locals",
    "module",
    "moved",
    "output",
    "provider",
    "removed",
    "resource",
    "terraform",
    "variable",
}
_TERRAGRUNT_KEYS = {
    "catalog",
    "dependencies",
    "dependency",
    "engine",
    "errors",
    "exclude",
    "feature",
    "generate",
    "iam_role",
    "include",
    "inputs",
    "remote_state",
    "stack",
    "terraform",
    "terraform_binary",
    "unit",
}
_SECRET_KEY = re.compile(
    r"(?:^|_)(?:access_key|api_key|auth_token|client_secret|credential|credentials|"
    r"key_material|password|private_key|secret|secret_key|token)(?:$|_)",
    re.IGNORECASE,
)
_INSECURE_KEY = re.compile(
    r"(?:disable|insecure|skip).*(?:certificate|credentials|encryption|ssl|tls|validation|verify)",
    re.IGNORECASE,
)


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
        return value[0]
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    text = str(value).strip().strip("\"'")
    if text.startswith("${") and text.endswith("}"):
        return text[2:-1]
    return text


def _enabled(value: Any) -> bool:
    return value is True or _text(value).lower() in {"1", "true", "yes", "on"}


def _disabled(value: Any) -> bool:
    return value is False or _text(value).lower() in {"0", "false", "no", "off"}


def _blocks(value: Any, label_depth: int = 1) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    """Flatten python-hcl2 labeled blocks while retaining their labels."""
    results: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    raw_items = value if isinstance(value, list) else [value]
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        current: Any = item
        labels: list[str] = []
        for _ in range(label_depth):
            if not isinstance(current, dict) or len(current) != 1:
                break
            label, child = next(iter(current.items()))
            if not isinstance(child, dict):
                break
            labels.append(_text(label))
            current = child
        if isinstance(current, dict):
            results.append((tuple(labels), current))
    return results


def parse_terraform_config(source: str, ecosystem: str) -> dict[str, Any]:
    """Parse explicitly selected Terraform config or Terragrunt HCL/JSON."""
    if ecosystem not in {"terraform-config", "terragrunt"}:
        raise TerraformConfigInputError(f"unsupported ecosystem: {ecosystem}")
    if not source.strip():
        raise TerraformConfigInputError("input is empty")
    try:
        document: Any = json.loads(source)
    except json.JSONDecodeError:
        try:
            import hcl2
            from hcl2.utils import SerializationOptions

            document = hcl2.loads(
                source,
                serialization_options=SerializationOptions(
                    explicit_blocks=False,
                    strip_string_quotes=True,
                ),
            )
        except Exception as exc:
            raise TerraformConfigInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise TerraformConfigInputError("configuration must be an HCL or JSON object")
    recognized = _TERRAFORM_KEYS if ecosystem == "terraform-config" else _TERRAGRUNT_KEYS
    if not recognized & set(document):
        raise TerraformConfigInputError(f"input is not recognizable as {ecosystem}")
    if ecosystem == "terraform-config":
        terraform = _mapping(document.get("terraform"))
        if {"after_hook", "before_hook", "error_hook", "extra_arguments", "source"} & set(
            terraform
        ):
            raise TerraformConfigInputError("input is Terragrunt configuration, not Terraform")
    if ecosystem == "terragrunt" and set(document) <= {"terraform"}:
        terraform = _mapping(document.get("terraform"))
        terragrunt_fields = {
            "after_hook",
            "before_hook",
            "error_hook",
            "extra_arguments",
            "include_in_copy",
            "source",
        }
        if not terragrunt_fields & set(terraform):
            raise TerraformConfigInputError("input is Terraform configuration, not Terragrunt")
    return {"terraform_config": {"ecosystem": ecosystem, "document": document}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


class TerraformSourceAdapter(BaseAdapter):
    def __init__(self, ecosystem: str) -> None:
        self.ecosystem = ecosystem

    @property
    def adapter_name(self) -> str:
        return self.ecosystem

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("terraform_config")
        return (
            isinstance(config, dict)
            and config.get("ecosystem") == self.ecosystem
            and isinstance(config.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        document = input_data["terraform_config"]["document"]
        changes = (
            self._terraform(document)
            if self.ecosystem == "terraform-config"
            else self._terragrunt(document)
        )
        changes.extend(self._secret_fields(document, self.ecosystem))
        changes.extend(self._function_boundaries(document, self.ecosystem))
        changes.append(
            _change(
                f"{self.ecosystem}.effective_configuration",
                "effective_configuration",
                "review",
                f"Effective {self.ecosystem} behavior also depends on other files in the "
                "configuration directory, variable values, environment credentials, dependency "
                "locks, installed plugins, remote state, and runtime command arguments.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        prefix = "terraform_config" if self.ecosystem == "terraform-config" else "terragrunt"
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"{prefix}_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )

    def _terraform(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for index, (_, config) in enumerate(_blocks(document.get("terraform"), 0)):
            address = f"terraform[{index}]"
            changes.append(
                _change(
                    address,
                    "terraform_settings",
                    "review",
                    "Terraform settings control CLI compatibility, provider installation, and "
                    "state storage.",
                )
            )
            if not config.get("required_version"):
                changes.append(
                    _change(
                        f"{address}.required_version",
                        "unconstrained_cli",
                        "review",
                        "Terraform CLI version is not constrained in this artifact.",
                    )
                )
            for backend_index, (labels, backend) in enumerate(_blocks(config.get("backend"), 1)):
                kind = labels[0] if labels else "unknown"
                backend_address = f"{address}.backend[{backend_index}]"
                changes.append(
                    _change(
                        backend_address,
                        "state_backend",
                        "dangerous" if kind == "local" else "review",
                        f"Terraform stores sensitive state and coordinates locking through the "
                        f"{kind} backend.",
                    )
                )
                changes.extend(self._plaintext_urls(backend, backend_address))
            if config.get("cloud") is not None:
                changes.append(
                    _change(
                        f"{address}.cloud",
                        "remote_execution",
                        "dangerous",
                        "Terraform delegates state and potentially plan/apply execution to HCP "
                        "Terraform or Terraform Enterprise.",
                    )
                )
            required = _mapping(config.get("required_providers"))
            for name, provider in required.items():
                provider_config = _mapping(provider)
                provider_address = f"{address}.required_providers.{name}"
                changes.append(
                    _change(
                        provider_address,
                        "provider_dependency",
                        "review",
                        "Terraform installs and executes a provider plugin from the configured "
                        "source.",
                    )
                )
                version = _text(provider_config.get("version", ""))
                if not version:
                    changes.append(
                        _change(
                            f"{provider_address}.version",
                            "unpinned_dependency",
                            "dangerous",
                            "Terraform provider has no version constraint in this artifact.",
                        )
                    )
                elif not self._version_bounded(version):
                    changes.append(
                        _change(
                            f"{provider_address}.version",
                            "open_version_constraint",
                            "review",
                            "Terraform provider constraint has no visible upper or exact bound.",
                        )
                    )
        changes.extend(self._providers(document))
        changes.extend(self._modules(document))
        changes.extend(self._managed_blocks(document, "resource"))
        changes.extend(self._managed_blocks(document, "ephemeral"))
        changes.extend(self._data_sources(document))
        for key, kind, risk, explanation in (
            ("import", "import", "review", "Terraform imports existing infrastructure into state."),
            ("moved", "state_move", "review", "Terraform remaps resource addresses in state."),
            (
                "check",
                "continuous_check",
                "review",
                "Terraform evaluates assertions and may query external data during plan or apply.",
            ),
        ):
            if document.get(key) is not None:
                changes.append(_change(key, kind, risk, explanation))
        for index, (_, removed) in enumerate(_blocks(document.get("removed"), 0)):
            lifecycle = _mapping(removed.get("lifecycle"))
            destroys = _enabled(lifecycle.get("destroy"))
            changes.append(
                _change(
                    f"removed[{index}]",
                    "state_removal",
                    "irreversible" if destroys else "dangerous",
                    "Terraform destroys the removed resource before removing it from state."
                    if destroys
                    else "Terraform stops managing the removed resource and removes it from state.",
                )
            )
        changes.extend(self._outputs_and_variables(document))
        return changes

    def _providers(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for index, (labels, config) in enumerate(_blocks(document.get("provider"), 1)):
            name = labels[0] if labels else "unknown"
            address = f"provider.{name}[{index}]"
            changes.append(
                _change(
                    address,
                    "provider_configuration",
                    "review",
                    "Terraform provider configuration controls external API identity, region, "
                    "endpoints, and behavior.",
                )
            )
            for key, value in config.items():
                if _INSECURE_KEY.search(str(key)) and _enabled(value):
                    changes.append(
                        _change(
                            f"{address}.{key}",
                            "insecure_provider",
                            "dangerous",
                            "Terraform provider disables a credential, certificate, encryption, "
                            "or validation safeguard.",
                        )
                    )
            changes.extend(self._plaintext_urls(config, address))
        return changes

    def _modules(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for index, (labels, config) in enumerate(_blocks(document.get("module"), 1)):
            name = labels[0] if labels else f"module_{index}"
            address = f"module.{name}"
            source = _text(config.get("source", ""))
            remote = bool(source) and not source.startswith(("./", "../"))
            changes.append(
                _change(
                    address,
                    "module_source",
                    "dangerous" if remote else "review",
                    "Terraform loads configuration from a remote module source."
                    if remote
                    else "Terraform composes configuration from a local module source.",
                )
            )
            if remote and not self._source_pinned(source, config.get("version")):
                changes.append(
                    _change(
                        f"{address}.version",
                        "unpinned_module",
                        "dangerous",
                        "Remote Terraform module source is not pinned to a visible immutable "
                        "version or revision.",
                    )
                )
            if config.get("providers") is not None:
                changes.append(
                    _change(
                        f"{address}.providers",
                        "provider_mapping",
                        "review",
                        "Terraform passes explicit provider identities into the child module.",
                    )
                )
            if config.get("count") is not None or config.get("for_each") is not None:
                changes.append(
                    _change(
                        f"{address}.multiplicity",
                        "dynamic_multiplicity",
                        "review",
                        "Module instance count is computed from expressions or collections.",
                    )
                )
        return changes

    def _managed_blocks(self, document: dict[str, Any], block: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for index, (labels, config) in enumerate(_blocks(document.get(block), 2)):
            resource_type = labels[0] if labels else "unknown"
            name = labels[1] if len(labels) > 1 else str(index)
            address = f"{block}.{resource_type}.{name}"
            changes.append(
                _change(
                    address,
                    "managed_resource" if block == "resource" else "ephemeral_resource",
                    "review",
                    f"Terraform configures {resource_type} through provider-defined behavior.",
                )
            )
            for provisioner_index, (provisioner_labels, _) in enumerate(
                _blocks(config.get("provisioner"), 1)
            ):
                kind = provisioner_labels[0] if provisioner_labels else "unknown"
                changes.append(
                    _change(
                        f"{address}.provisioner[{provisioner_index}]",
                        "provisioner_execution",
                        "dangerous",
                        f"Terraform {kind} provisioner executes commands or transfers files "
                        "outside the provider resource model.",
                    )
                )
            if config.get("connection") is not None:
                changes.append(
                    _change(
                        f"{address}.connection",
                        "remote_connection",
                        "dangerous",
                        "Terraform establishes a credentialed SSH or WinRM connection for "
                        "provisioning.",
                    )
                )
            lifecycle = _mapping(config.get("lifecycle"))
            if (
                lifecycle.get("ignore_changes") == "all"
                or _text(lifecycle.get("ignore_changes", "")) == "all"
            ):
                changes.append(
                    _change(
                        f"{address}.lifecycle.ignore_changes",
                        "ignored_drift",
                        "dangerous",
                        "Terraform ignores all out-of-band changes to this resource.",
                    )
                )
            if lifecycle.get("replace_triggered_by") is not None or _enabled(
                lifecycle.get("create_before_destroy")
            ):
                changes.append(
                    _change(
                        f"{address}.lifecycle.replacement",
                        "replacement_lifecycle",
                        "review",
                        "Terraform lifecycle settings can trigger replacement or temporarily "
                        "duplicate infrastructure.",
                    )
                )
            if config.get("count") is not None or config.get("for_each") is not None:
                changes.append(
                    _change(
                        f"{address}.multiplicity",
                        "dynamic_multiplicity",
                        "review",
                        "Resource instance count is computed from expressions or collections.",
                    )
                )
            if config.get("depends_on") is not None:
                changes.append(
                    _change(
                        f"{address}.depends_on",
                        "explicit_dependency",
                        "review",
                        "Terraform overrides dependency inference with an explicit dependency.",
                    )
                )
            changes.extend(self._static_exposure(config, address))
        return changes

    def _data_sources(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for index, (labels, config) in enumerate(_blocks(document.get("data"), 2)):
            data_type = labels[0] if labels else "unknown"
            name = labels[1] if len(labels) > 1 else str(index)
            address = f"data.{data_type}.{name}"
            risk = "dangerous" if data_type in {"external", "terraform_remote_state"} else "review"
            changes.append(
                _change(
                    address,
                    "external_program" if data_type == "external" else "data_source",
                    risk,
                    "Terraform reads another configuration's sensitive state outputs."
                    if data_type == "terraform_remote_state"
                    else (
                        "Terraform executes an external program to produce data."
                        if data_type == "external"
                        else "Terraform queries external provider data during evaluation."
                    ),
                )
            )
            changes.extend(self._plaintext_urls(config, address))
        return changes

    def _outputs_and_variables(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for key in ("variable", "output"):
            for index, (labels, config) in enumerate(_blocks(document.get(key), 1)):
                name = labels[0] if labels else str(index)
                address = f"{key}.{name}"
                if _SECRET_KEY.search(name) and not _enabled(config.get("sensitive")):
                    changes.append(
                        _change(
                            address,
                            "sensitive_value",
                            "dangerous",
                            f"Terraform {key} appears credential-bearing but is not marked "
                            "sensitive.",
                        )
                    )
                if key == "variable" and _SECRET_KEY.search(name) and config.get("default"):
                    changes.append(
                        _change(
                            f"{address}.default",
                            "secret_material",
                            "dangerous",
                            "Terraform variable embeds a credential-like default value.",
                        )
                    )
        return changes

    def _terragrunt(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        terraform = _mapping(document.get("terraform"))
        if terraform:
            changes.append(
                _change(
                    "terraform",
                    "terraform_orchestration",
                    "review",
                    "Terragrunt controls source acquisition and OpenTofu/Terraform invocation.",
                )
            )
            source = _text(terraform.get("source", ""))
            if source:
                remote = not source.startswith(("./", "../"))
                changes.append(
                    _change(
                        "terraform.source",
                        "module_source",
                        "dangerous" if remote else "review",
                        "Terragrunt downloads and executes a remote root module."
                        if remote
                        else "Terragrunt copies a local Terraform module into its working tree.",
                    )
                )
                if remote and not self._source_pinned(source, None):
                    changes.append(
                        _change(
                            "terraform.source.version",
                            "unpinned_module",
                            "dangerous",
                            "Terragrunt remote source lacks a visible immutable ref or registry "
                            "version.",
                        )
                    )
            for hook_kind in ("before_hook", "after_hook", "error_hook"):
                for index, (labels, hook) in enumerate(_blocks(terraform.get(hook_kind), 1)):
                    name = labels[0] if labels else str(index)
                    changes.append(
                        _change(
                            f"terraform.{hook_kind}.{name}",
                            "hook_execution",
                            "dangerous",
                            f"Terragrunt {hook_kind} executes a local command around "
                            "OpenTofu/Terraform operations.",
                        )
                    )
                    if _enabled(hook.get("run_on_error")):
                        changes.append(
                            _change(
                                f"terraform.{hook_kind}.{name}.run_on_error",
                                "error_path_execution",
                                "dangerous",
                                "Terragrunt hook executes even after another hook or Terraform "
                                "operation fails.",
                            )
                        )
            for index, (labels, arguments) in enumerate(
                _blocks(terraform.get("extra_arguments"), 1)
            ):
                name = labels[0] if labels else str(index)
                address = f"terraform.extra_arguments.{name}"
                changes.append(
                    _change(
                        address,
                        "cli_arguments",
                        "review",
                        "Terragrunt injects CLI arguments, variable files, or environment values "
                        "into OpenTofu/Terraform.",
                    )
                )
                flattened = " ".join(str(value) for value in _items(arguments.get("arguments")))
                if any(
                    token in flattened
                    for token in ("-auto-approve", "-destroy", "-lock=false", "-target")
                ):
                    changes.append(
                        _change(
                            f"{address}.arguments",
                            "unsafe_cli_arguments",
                            "dangerous",
                            "Terragrunt injects approval-bypassing, destructive, unlocked, or "
                            "targeted Terraform arguments.",
                        )
                    )
        changes.extend(self._terragrunt_state(document))
        for index, (labels, include) in enumerate(_blocks(document.get("include"), 1)):
            name = labels[0] if labels else str(index)
            changes.append(
                _change(
                    f"include.{name}",
                    "configuration_include",
                    "review",
                    "Terragrunt merges configuration from another HCL file.",
                )
            )
            if _enabled(include.get("expose")):
                changes.append(
                    _change(
                        f"include.{name}.expose",
                        "exposed_include",
                        "review",
                        "Included Terragrunt configuration is exposed to expressions in this unit.",
                    )
                )
        changes.extend(self._terragrunt_dependencies(document))
        for index, (labels, generated) in enumerate(_blocks(document.get("generate"), 1)):
            name = labels[0] if labels else str(index)
            address = f"generate.{name}"
            changes.append(
                _change(
                    address,
                    "generated_configuration",
                    "dangerous",
                    "Terragrunt writes generated Terraform configuration into the working tree.",
                )
            )
            if "overwrite" in _text(generated.get("if_exists", "")):
                changes.append(
                    _change(
                        f"{address}.if_exists",
                        "configuration_overwrite",
                        "dangerous",
                        "Terragrunt overwrites an existing generated or user-managed file.",
                    )
                )
        if document.get("inputs") is not None:
            changes.append(
                _change(
                    "inputs",
                    "module_inputs",
                    "review",
                    "Terragrunt supplies values to the root module as Terraform variables.",
                )
            )
            changes.extend(self._static_exposure(_mapping(document.get("inputs")), "inputs"))
        for key in (
            "iam_role",
            "iam_web_identity_token",
            "iam_assume_role_duration",
            "iam_assume_role_session_name",
        ):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        key,
                        "assumed_identity",
                        "dangerous",
                        "Terragrunt assumes or configures an external cloud identity before "
                        "running Terraform.",
                    )
                )
        if document.get("terraform_binary") is not None:
            changes.append(
                _change(
                    "terraform_binary",
                    "executable_override",
                    "dangerous",
                    "Terragrunt invokes a non-default OpenTofu/Terraform executable.",
                )
            )
        for key, kind, risk, explanation in (
            (
                "engine",
                "iac_engine",
                "dangerous",
                "Terragrunt delegates execution to a configured IaC engine.",
            ),
            (
                "errors",
                "error_handling",
                "review",
                "Terragrunt retries or ignores matching operational errors.",
            ),
            (
                "exclude",
                "unit_exclusion",
                "review",
                "Terragrunt conditionally excludes this unit from run queues.",
            ),
            (
                "feature",
                "feature_flag",
                "review",
                "Terragrunt changes behavior through a feature flag.",
            ),
            ("unit", "stack_unit", "review", "Terragrunt generates or orchestrates a stack unit."),
            ("stack", "stack_definition", "review", "Terragrunt defines a multi-unit stack."),
            (
                "catalog",
                "catalog_source",
                "dangerous",
                "Terragrunt retrieves configuration through a catalog source.",
            ),
        ):
            if document.get(key) is not None:
                changes.append(_change(key, kind, risk, explanation))
        return changes

    def _terragrunt_state(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        state = _mapping(document.get("remote_state"))
        if not state:
            return []
        backend = _text(state.get("backend", "unknown"))
        changes = [
            _change(
                "remote_state",
                "state_backend",
                "dangerous" if backend == "local" else "review",
                f"Terragrunt configures the {backend} backend for sensitive Terraform state.",
            )
        ]
        if state.get("generate") is not None:
            changes.append(
                _change(
                    "remote_state.generate",
                    "generated_backend",
                    "dangerous",
                    "Terragrunt generates backend configuration in the Terraform working tree.",
                )
            )
        if state.get("encryption") is not None:
            changes.append(
                _change(
                    "remote_state.encryption",
                    "state_encryption",
                    "review",
                    "Terragrunt configures state or lockfile encryption and key providers.",
                )
            )
        changes.extend(self._plaintext_urls(state, "remote_state"))
        return changes

    def _terragrunt_dependencies(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for index, (labels, dependency) in enumerate(_blocks(document.get("dependency"), 1)):
            name = labels[0] if labels else str(index)
            address = f"dependency.{name}"
            changes.append(
                _change(
                    address,
                    "dependency_outputs",
                    "review",
                    "Terragrunt reads outputs and ordering information from another unit.",
                )
            )
            if dependency.get("mock_outputs") is not None or _enabled(
                dependency.get("skip_outputs")
            ):
                changes.append(
                    _change(
                        f"{address}.mock_outputs",
                        "mocked_dependency",
                        "dangerous",
                        "Terragrunt substitutes mocked or skipped dependency outputs into "
                        "Terraform evaluation.",
                    )
                )
        if document.get("dependencies") is not None:
            changes.append(
                _change(
                    "dependencies",
                    "dependency_order",
                    "review",
                    "Terragrunt adds explicit unit ordering dependencies without output reads.",
                )
            )
        return changes

    def _source_pinned(self, source: str, version: Any) -> bool:
        if version not in {None, ""}:
            return True
        lowered = source.lower()
        if "?ref=" in lowered:
            ref = lowered.split("?ref=", 1)[1].split("&", 1)[0]
            return ref not in {"", "head", "main", "master", "latest"}
        if lowered.startswith("tfr://"):
            return "?version=" in lowered
        return False

    def _version_bounded(self, version: str) -> bool:
        return (
            "<" in version
            or "~>" in version
            or re.fullmatch(r"=?\s*v?\d+(?:\.\d+)*", version.strip()) is not None
        )

    def _static_exposure(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                child_address = f"{address}.{key}"
                lowered_key = str(key).lower()
                text = str(child).lower()
                if "cidr" in lowered_key and any(
                    cidr in text for cidr in ("0.0.0.0/0", "::/0")
                ):
                    changes.append(
                        _change(
                            child_address,
                            "public_exposure",
                            "dangerous",
                            "Terraform configuration grants access from every IPv4 or IPv6 "
                            "address.",
                        )
                    )
                encryption_flag = lowered_key in {
                    "encrypted",
                    "encryption_enabled",
                    "enable_encryption",
                } or lowered_key.endswith(("_encrypted", "_encryption_enabled"))
                if encryption_flag and _disabled(child):
                    changes.append(
                        _change(
                            child_address,
                            "disabled_encryption",
                            "dangerous",
                            "Terraform configuration explicitly disables encryption.",
                        )
                    )
                if lowered_key in {"privileged", "public", "publicly_accessible"} and _enabled(
                    child
                ):
                    changes.append(
                        _change(
                            child_address,
                            "privileged_or_public",
                            "dangerous",
                            "Terraform configuration explicitly enables privileged or public "
                            "operation.",
                        )
                    )
                changes.extend(self._static_exposure(child, child_address))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                changes.extend(self._static_exposure(child, f"{address}[{index}]"))
        return changes

    def _plaintext_urls(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                child_address = f"{address}.{key}"
                if isinstance(child, str) and child.lower().startswith("http://"):
                    changes.append(
                        _change(
                            child_address,
                            "plaintext_endpoint",
                            "dangerous",
                            "Infrastructure configuration sends API, state, or credential-bearing "
                            "traffic over plaintext HTTP.",
                        )
                    )
                else:
                    changes.extend(self._plaintext_urls(child, child_address))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                changes.extend(self._plaintext_urls(child, f"{address}[{index}]"))
        return changes

    def _secret_fields(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                child_address = f"{address}.{key}"
                if _SECRET_KEY.search(str(key)) and child is not None and child != "":
                    changes.append(
                        _change(
                            child_address,
                            "secret_material",
                            "dangerous",
                            "Infrastructure configuration contains or references credential "
                            "material.",
                        )
                    )
                else:
                    changes.extend(self._secret_fields(child, child_address))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                changes.extend(self._secret_fields(child, f"{address}[{index}]"))
        return changes

    def _function_boundaries(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                changes.extend(self._function_boundaries(child, f"{address}.{key}"))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                changes.extend(self._function_boundaries(child, f"{address}[{index}]"))
        elif isinstance(value, str):
            lowered = value.lower()
            for function, kind, risk, explanation in (
                (
                    "run_cmd(",
                    "configuration_command",
                    "dangerous",
                    "Terragrunt executes a command while evaluating configuration.",
                ),
                (
                    "sops_decrypt_file(",
                    "secret_decryption",
                    "dangerous",
                    "Terragrunt decrypts secret material while evaluating configuration.",
                ),
                (
                    "read_terragrunt_config(",
                    "dynamic_config_read",
                    "review",
                    "Terragrunt evaluates and imports another configuration file.",
                ),
                (
                    "get_env(",
                    "environment_input",
                    "review",
                    "Configuration behavior depends on an environment variable.",
                ),
            ):
                if function in lowered:
                    changes.append(_change(address, kind, risk, explanation))
        return changes


class TerraformConfigAdapter(TerraformSourceAdapter):
    def __init__(self) -> None:
        super().__init__("terraform-config")


class TerragruntAdapter(TerraformSourceAdapter):
    def __init__(self) -> None:
        super().__init__("terragrunt")


def analyze_terraform_config(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    config = data.get("terraform_config")
    ecosystem = str(config.get("ecosystem")) if isinstance(config, dict) else "terraform-config"
    adapter: TerraformSourceAdapter = (
        TerraformConfigAdapter() if ecosystem == "terraform-config" else TerragruntAdapter()
    )
    changes = adapter.analyze(data, tool_name=ecosystem)
    summary = PlanSummary(
        path=Path(f"{ecosystem}://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name=ecosystem)
    gate["adapter"] = ecosystem
    gate["total_changes"] = len(changes)
    return gate
