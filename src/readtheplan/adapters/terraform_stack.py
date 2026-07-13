from __future__ import annotations

import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import parse_qs, urlsplit

import hcl2
from hcl2.utils import SerializationOptions

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class TerraformStackInputError(ValueError):
    """Raised when input is not a Terraform Stack configuration artifact."""


_COMPONENT_BLOCKS = {
    "component",
    "locals",
    "output",
    "provider",
    "removed",
    "required_providers",
    "stack",
    "variable",
}
_DEPLOYMENT_BLOCKS = {
    "deployment",
    "deployment_auto_approve",
    "deployment_group",
    "identity_token",
    "locals",
    "publish_output",
    "store",
    "upstream_input",
}
_SECRET_NAME = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)",
    re.IGNORECASE,
)
_EXACT_VERSION = re.compile(r"^=?\s*v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_EXPRESSION = re.compile(r"^\$\{.*\}$", re.DOTALL)
_EVALUATION = re.compile(
    r"\$\{|\b(?:env|file|filebase64|fileset|plantimestamp|timestamp|terraform\.applying)\s*\(",
    re.IGNORECASE,
)


def _strip_internal(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _strip_internal(child)
            for key, child in value.items()
            if key != "__is_block__"
        }
    if isinstance(value, list):
        return [_strip_internal(child) for child in value]
    return value


def _text(value: Any) -> str:
    return str(value).strip().strip("\"'")


def _is_literal(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return not _EXPRESSION.match(value.strip())
    return isinstance(value, (bool, int, float))


def _enabled(value: Any) -> bool:
    return value is True or _text(value).lower() in {"1", "true", "yes", "on"}


def _blocks(
    document: dict[str, Any], block_name: str, label_depth: int = 1
) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    raw = document.get(block_name)
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else [raw]
    result: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    seen: set[tuple[str, ...]] = set()
    for item in items:
        if not isinstance(item, dict):
            raise TerraformStackInputError(f"{block_name} blocks must contain objects")
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
        if len(labels) != label_depth or not isinstance(current, dict):
            raise TerraformStackInputError(
                f"{block_name} blocks must have {label_depth} label(s) and an object body"
            )
        label_tuple = tuple(labels)
        if label_depth and label_tuple in seen:
            raise TerraformStackInputError(
                f"duplicate {block_name} block: {'.'.join(label_tuple)}"
            )
        seen.add(label_tuple)
        result.append((label_tuple, current))
    return result


def parse_terraform_stack(source: str, filename: str | None = None) -> dict[str, Any]:
    """Parse a Terraform Stack HCL artifact without evaluating Terraform."""
    if not source.strip():
        raise TerraformStackInputError("input is empty")
    name = (filename or "").casefold()
    if name and not name.endswith((".tfcomponent.hcl", ".tfdeploy.hcl")):
        raise TerraformStackInputError(
            "Terraform Stack input must end in .tfcomponent.hcl or .tfdeploy.hcl"
        )
    source = source.replace("\r\n", "\n").replace("\r", "\n")
    try:
        document = hcl2.loads(
            source,
            serialization_options=SerializationOptions(
                explicit_blocks=False,
                strip_string_quotes=True,
            ),
        )
    except Exception as exc:
        raise TerraformStackInputError(f"invalid Terraform Stack HCL: {exc}") from exc
    document = _strip_internal(document)
    if not isinstance(document, dict):
        raise TerraformStackInputError("Terraform Stack configuration must be an HCL object")

    if name.endswith(".tfcomponent.hcl"):
        artifact_type = "component"
    elif name.endswith(".tfdeploy.hcl"):
        artifact_type = "deployment"
    else:
        component_only = set(document) - {"locals"}
        deployment_only = component_only & (_DEPLOYMENT_BLOCKS - _COMPONENT_BLOCKS)
        component_matches = component_only & (_COMPONENT_BLOCKS - _DEPLOYMENT_BLOCKS)
        if deployment_only and not component_matches:
            artifact_type = "deployment"
        elif component_matches and not deployment_only:
            artifact_type = "component"
        else:
            raise TerraformStackInputError(
                "cannot infer Terraform Stack artifact type; provide a Stack filename"
            )
    allowed = _COMPONENT_BLOCKS if artifact_type == "component" else _DEPLOYMENT_BLOCKS
    recognized = set(document) & allowed
    incompatible = set(document) & (
        _DEPLOYMENT_BLOCKS if artifact_type == "component" else _COMPONENT_BLOCKS
    ) - {"locals"}
    if incompatible:
        names = ", ".join(sorted(incompatible))
        raise TerraformStackInputError(
            f"{artifact_type} configuration contains incompatible block(s): {names}"
        )
    unknown = set(document) - allowed
    if unknown:
        names = ", ".join(sorted(unknown))
        raise TerraformStackInputError(
            f"{artifact_type} configuration contains unknown top-level block(s): {names}"
        )
    if not recognized - {"locals"}:
        raise TerraformStackInputError(
            f"input is not recognizable as a Terraform Stack {artifact_type} configuration"
        )
    return {
        "terraform_stack": {
            "artifact_type": artifact_type,
            "document": document,
            "filename": filename or f"stack.tf{artifact_type}.hcl",
        }
    }


def _change(address: str, kind: str, risk: str, explanation: str, action: str = "configure"):
    return {
        "Address": address,
        "Kind": kind,
        "Risk": risk,
        "Explanation": explanation,
        "Action": action,
    }


def _source_changes(address: str, source: Any, version: Any) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if not source:
        return [
            _change(
                f"{address}.source",
                "missing_source",
                "dangerous",
                "The Stack block has no statically visible source, so its code provenance "
                "cannot be verified.",
            )
        ]
    text = _text(source)
    if _EXPRESSION.match(text):
        return [
            _change(
                f"{address}.source",
                "dynamic_source",
                "review",
                "The source is computed at runtime; verify the resolved module and trust boundary.",
            )
        ]
    if text.startswith(("./", "../", ".\\", "..\\")):
        path = PureWindowsPath(text) if "\\" in text else PurePosixPath(text)
        if ".." in path.parts:
            changes.append(
                _change(
                    f"{address}.source",
                    "parent_source",
                    "review",
                    "The local source traverses outside this Stack directory; review the "
                    "resolved code boundary.",
                )
            )
        return changes

    remote = text.startswith(("git::", "git@", "ssh://", "http://", "https://"))
    if remote:
        candidate = text.removeprefix("git::")
        query = parse_qs(urlsplit(candidate).query)
        ref = query.get("ref", [None])[0]
        if not ref:
            changes.append(
                _change(
                    f"{address}.source",
                    "floating_source",
                    "dangerous",
                    "The remote source has no ref pin and may resolve to different code over time.",
                )
            )
        elif not _COMMIT.fullmatch(ref):
            changes.append(
                _change(
                    f"{address}.source",
                    "mutable_source_ref",
                    "review",
                    "The remote source ref is not an immutable commit digest; verify tag or "
                    "branch protection.",
                )
            )
        return changes

    if not version:
        changes.append(
            _change(
                f"{address}.version",
                "unconstrained_source",
                "dangerous",
                "The registry source has no version constraint and may select unexpected code.",
            )
        )
    elif not _EXACT_VERSION.fullmatch(_text(version)):
        changes.append(
            _change(
                f"{address}.version",
                "floating_source_version",
                "review",
                "The registry version constraint permits more than one release; review "
                "dependency lock behavior.",
            )
        )
    return changes


def _secret_map_changes(address: str, value: Any) -> list[dict[str, str]]:
    if not isinstance(value, dict):
        return []
    changes: list[dict[str, str]] = []
    for key, child in value.items():
        child_address = f"{address}.{key}"
        if _SECRET_NAME.search(str(key)) and _is_literal(child):
            changes.append(
                _change(
                    child_address,
                    "literal_secret",
                    "dangerous",
                    f"Credential-like field {key!r} has a literal value; use a sensitive "
                    "variable or trusted store.",
                )
            )
        if isinstance(child, dict):
            changes.extend(_secret_map_changes(child_address, child))
        elif isinstance(child, list):
            for index, item in enumerate(child):
                if isinstance(item, dict):
                    changes.extend(_secret_map_changes(f"{child_address}[{index}]", item))
    return changes


def _component_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for labels, body in _blocks(document, "component"):
        name = labels[0]
        address = f"component.{name}"
        changes.extend(_source_changes(address, body.get("source"), body.get("version")))
        changes.extend(_secret_map_changes(f"{address}.inputs", body.get("inputs")))
        if "for_each" in body:
            changes.append(
                _change(
                    f"{address}.for_each",
                    "component_fanout",
                    "review",
                    "Component for_each can fan one declaration across multiple infrastructure "
                    "instances.",
                )
            )
    for labels, body in _blocks(document, "stack"):
        name = labels[0]
        address = f"stack.{name}"
        changes.extend(_source_changes(address, body.get("source"), body.get("version")))
        changes.extend(_secret_map_changes(f"{address}.inputs", body.get("inputs")))

    required = document.get("required_providers")
    required_items = required if isinstance(required, list) else [required]
    for block in required_items:
        if block is None:
            continue
        if not isinstance(block, dict):
            raise TerraformStackInputError("required_providers must contain an object")
        for name, requirement in block.items():
            if not isinstance(requirement, dict):
                raise TerraformStackInputError(f"provider requirement {name!r} must be an object")
            changes.extend(
                _source_changes(
                    f"required_providers.{name}",
                    requirement.get("source"),
                    requirement.get("version"),
                )
            )
    for labels, body in _blocks(document, "provider", 2):
        provider, alias = labels
        address = f"provider.{provider}.{alias}"
        changes.extend(_secret_map_changes(f"{address}.config", body.get("config")))
        changes.append(
            _change(
                address,
                "provider_identity_boundary",
                "review",
                "Stack provider configuration can assume cloud identity and receives "
                "credentials at runtime; verify least privilege.",
            )
        )
        if "for_each" in body:
            changes.append(
                _change(
                    f"{address}.for_each",
                    "provider_fanout",
                    "review",
                    "Provider for_each creates multiple credential and account/region trust "
                    "boundaries.",
                )
            )
    for index, (_labels, body) in enumerate(_blocks(document, "removed", 0)):
        changes.append(
            _change(
                f"removed[{index}]",
                "removed_component",
                "irreversible",
                "The removed block destroys infrastructure managed by the referenced component; "
                "confirm recovery, retention, and provider availability.",
                "delete",
            )
        )
        if "for_each" in body:
            changes.append(
                _change(
                    f"removed[{index}].for_each",
                    "removed_component_fanout",
                    "irreversible",
                    "The removed block can destroy multiple component instances through for_each.",
                    "delete",
                )
            )
    for labels, body in _blocks(document, "variable"):
        name = labels[0]
        if _SECRET_NAME.search(name) and _is_literal(body.get("default")):
            changes.append(
                _change(
                    f"variable.{name}.default",
                    "secret_default",
                    "dangerous",
                    f"Sensitive-looking variable {name!r} has a literal default in source.",
                )
            )
        if _SECRET_NAME.search(name) and not _enabled(body.get("sensitive")):
            changes.append(
                _change(
                    f"variable.{name}.sensitive",
                    "unmarked_sensitive_input",
                    "dangerous",
                    f"Sensitive-looking variable {name!r} is not marked sensitive.",
                )
            )
    for labels, body in _blocks(document, "output"):
        name = labels[0]
        if _SECRET_NAME.search(name) and not _enabled(body.get("sensitive")):
            changes.append(
                _change(
                    f"output.{name}",
                    "exposed_sensitive_output",
                    "dangerous",
                    f"Sensitive-looking output {name!r} is not marked sensitive.",
                )
            )
    return changes


def _deployment_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    deployments = _blocks(document, "deployment")
    if len(deployments) > 1:
        changes.append(
            _change(
                "deployments",
                "deployment_fanout",
                "review",
                f"This file declares {len(deployments)} isolated Stack deployments.",
            )
        )
    for labels, body in deployments:
        name = labels[0]
        address = f"deployment.{name}"
        changes.extend(_secret_map_changes(f"{address}.inputs", body.get("inputs")))
        changes.append(
            _change(
                address,
                "isolated_deployment",
                "review",
                "Each Stack deployment has isolated state and can apply the component graph to "
                "a distinct environment.",
            )
        )
        if _enabled(body.get("destroy")):
            changes.append(
                _change(
                    f"{address}.destroy",
                    "deployment_destroy",
                    "irreversible",
                    "This deployment is configured for destruction; confirm recovery, "
                    "retention, and state safeguards.",
                    "delete",
                )
            )
        if _enabled(body.get("import")):
            changes.append(
                _change(
                    f"{address}.import",
                    "deployment_import",
                    "review",
                    "This deployment imports existing infrastructure into Stack state; verify "
                    "identity and ownership mappings.",
                    "import",
                )
            )
    for labels, body in _blocks(document, "deployment_auto_approve"):
        name = labels[0]
        checks = _blocks(body, "check", 0)
        unconditional = not checks or any(
            _enabled(check.get("condition")) or check.get("condition") is None
            for _check_labels, check in checks
        )
        changes.append(
            _change(
                f"deployment_auto_approve.{name}",
                "automatic_approval",
                "dangerous" if unconditional else "review",
                "This rule automatically approves deployments without a meaningful condition."
                if unconditional
                else "This rule can bypass manual approval when its runtime condition matches; "
                "verify the condition and scope.",
                "approve",
            )
        )
    for labels, body in _blocks(document, "deployment_group"):
        name = labels[0]
        if body.get("auto_approve_checks") not in (None, [], {}):
            changes.append(
                _change(
                    f"deployment_group.{name}.auto_approve_checks",
                    "group_auto_approval",
                    "dangerous",
                    "The deployment group attaches automatic approval checks to every member "
                    "deployment.",
                    "approve",
                )
            )
    for labels, body in _blocks(document, "identity_token"):
        name = labels[0]
        audience = body.get("audience")
        changes.append(
            _change(
                f"identity_token.{name}",
                "oidc_identity",
                "dangerous" if audience in (None, "", [], {}) else "review",
                "The identity token has no statically visible audience restriction."
                if audience in (None, "", [], {})
                else "HCP Terraform will issue a workload identity token for this audience; "
                "verify relying-party scope and trust policy.",
            )
        )
    for labels, body in _blocks(document, "store", 2):
        kind, name = labels
        changes.extend(_secret_map_changes(f"store.{name}.{kind}", body))
        changes.append(
            _change(
                f"store.{name}.{kind}",
                "external_store",
                "review",
                "This Stack reads an external variable or secret store; verify access scope, "
                "identity, and rotation controls.",
            )
        )
    for labels, body in _blocks(document, "publish_output"):
        name = labels[0]
        changes.append(
            _change(
                f"publish_output.{name}",
                "cross_stack_output",
                "dangerous" if _SECRET_NAME.search(name) else "review",
                "A sensitive-looking output is published across the Stack boundary."
                if _SECRET_NAME.search(name)
                else "This output is published for consumption outside the Stack; verify "
                "consumers and data classification.",
                "publish",
            )
        )
    for labels, _body in _blocks(document, "upstream_input"):
        name = labels[0]
        changes.append(
            _change(
                f"upstream_input.{name}",
                "cross_stack_input",
                "review",
                "This input depends on another Stack's published output; verify producer trust, "
                "compatibility, and failure behavior.",
                "consume",
            )
        )
    return changes


def terraform_stack_changes(payload: dict[str, Any]) -> list[dict[str, str]]:
    document = payload["document"]
    artifact_type = payload["artifact_type"]
    changes = (
        _component_changes(document)
        if artifact_type == "component"
        else _deployment_changes(document)
    )
    if _EVALUATION.search(str(document)):
        changes.append(
            _change(
                "stack.expressions",
                "runtime_evaluation",
                "review",
                "Stack expressions are resolved by Terraform at runtime; this static gate does "
                "not read files, environment values, or HCP runtime context.",
            )
        )
    changes.append(
        _change(
            "stack.effective_configuration",
            "evaluation_boundary",
            "review",
            "Static analysis covers one Stack HCL file. It does not merge sibling files, "
            "initialize providers/modules, resolve variables or upstream outputs, inspect "
            "remote code/state, contact HCP Terraform, or execute plans/applies.",
        )
    )
    return changes


class TerraformStackAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "terraform-stack"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("terraform_stack")
        return (
            isinstance(payload, dict)
            and payload.get("artifact_type") in {"component", "deployment"}
            and isinstance(payload.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        return terraform_stack_changes(input_data["terraform_stack"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw.get("Address") or "terraform-stack"),
            resource_type=f"terraform_stack_{raw.get('Kind') or 'unknown'}",
            actions=(str(raw.get("Action") or "configure"),),
            risk=str(raw.get("Risk") or "review"),
            explanation=str(raw.get("Explanation") or "Terraform Stack change requires review."),
        )


def analyze_terraform_stack(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = TerraformStackAdapter().analyze(data, tool_name="Terraform Stacks")
    summary = PlanSummary(
        path=Path("terraform-stack://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Terraform Stacks")
    gate["adapter"] = "terraform-stack"
    gate["artifact_type"] = data["terraform_stack"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
