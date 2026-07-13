from __future__ import annotations

import json
import re
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class TerraformStateInputError(ValueError):
    """Raised when input is not a supported Terraform/OpenTofu state representation."""


_SECRET_KEY = re.compile(
    r"(?:^|[-_.:])(?:api[-_.]?key|auth|credential|password|passwd|private[-_.]?key|"
    r"secret|token|passphrase)(?:$|[-_.:])",
    re.IGNORECASE,
)
_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_SENSITIVE = "<sensitive>"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TerraformStateInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _change(
    address: str,
    kind: str,
    risk: str,
    explanation: str,
    *,
    resource_type: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    change: dict[str, Any] = {
        "Address": address,
        "Kind": kind,
        "Risk": risk,
        "Explanation": explanation,
    }
    if resource_type:
        change["ResourceType"] = resource_type
    if metadata is not None:
        change["_metadata"] = metadata
    return change


def parse_terraform_state(source: str) -> dict[str, Any]:
    """Parse stable ``show -json`` state or a raw v4 snapshot without executing a CLI."""
    if not source.strip():
        raise TerraformStateInputError("input is empty")
    try:
        document = json.loads(source, object_pairs_hook=_unique_object)
    except TerraformStateInputError:
        raise
    except json.JSONDecodeError as exc:
        raise TerraformStateInputError(
            f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(document, dict):
        raise TerraformStateInputError("state input must be a JSON object")
    if "resource_changes" in document or "planned_values" in document:
        raise TerraformStateInputError("input is a plan representation, not a state representation")

    if "format_version" in document or "values" in document:
        format_version = document.get("format_version")
        if not isinstance(format_version, str) or not re.fullmatch(
            r"1(?:\.[0-9]+)?", format_version
        ):
            raise TerraformStateInputError(
                f"unsupported terraform show JSON format version: {format_version!r}"
            )
        values = document.get("values")
        if not isinstance(values, dict):
            raise TerraformStateInputError("show JSON state must contain a values mapping")
        root = values.get("root_module")
        outputs = values.get("outputs", {})
        if root is not None and not isinstance(root, dict):
            raise TerraformStateInputError("values.root_module must be a mapping")
        if not isinstance(outputs, dict):
            raise TerraformStateInputError("values.outputs must be a mapping")
        _validate_terraform_version(document.get("terraform_version"))
        return {"terraform_state": {"artifact": "show-json", "document": document}}

    if "version" in document or "resources" in document:
        if document.get("version") != 4:
            raise TerraformStateInputError(
                f"unsupported raw state snapshot version: {document.get('version')!r}"
            )
        if not isinstance(document.get("serial"), int) or document["serial"] < 0:
            raise TerraformStateInputError("raw state serial must be a non-negative integer")
        lineage = document.get("lineage")
        if not isinstance(lineage, str):
            raise TerraformStateInputError("raw state lineage must be a UUID string")
        try:
            uuid.UUID(lineage)
        except ValueError as exc:
            raise TerraformStateInputError("raw state lineage must be a UUID string") from exc
        if not isinstance(document.get("resources", []), list):
            raise TerraformStateInputError("raw state resources must be a list")
        if not isinstance(document.get("outputs", {}), dict):
            raise TerraformStateInputError("raw state outputs must be a mapping")
        _validate_terraform_version(document.get("terraform_version"))
        return {"terraform_state": {"artifact": "raw-v4", "document": document}}

    raise TerraformStateInputError(
        "input is not terraform show -json state output or a raw v4 state snapshot"
    )


def _validate_terraform_version(value: Any) -> None:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise TerraformStateInputError("terraform_version must be an exact semantic version")


def _walk_leaves(
    value: Any,
    path: tuple[str | int, ...] = (),
) -> Iterator[tuple[tuple[str | int, ...], Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _walk_leaves(item, (*path, str(key)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_leaves(item, (*path, index))
    else:
        yield path, value


def _sensitivity_at(mask: Any, path: tuple[str | int, ...]) -> bool:
    current = mask
    for component in path:
        if current is True:
            return True
        if isinstance(current, dict):
            current = current.get(str(component), False)
        elif isinstance(current, list) and isinstance(component, int) and component < len(current):
            current = current[component]
        else:
            return False
    return current is True


def _redact_mask(value: Any, mask: Any) -> Any:
    if mask is True:
        return _SENSITIVE
    if isinstance(value, dict):
        mask_map = mask if isinstance(mask, dict) else {}
        return {
            str(key): _redact_mask(item, mask_map.get(str(key), False))
            for key, item in value.items()
        }
    if isinstance(value, list):
        mask_list = mask if isinstance(mask, list) else []
        return [
            _redact_mask(item, mask_list[index] if index < len(mask_list) else False)
            for index, item in enumerate(value)
        ]
    return value


def _raw_sensitive_paths(value: Any) -> list[tuple[str | int, ...]]:
    if not isinstance(value, list):
        return []
    result: list[tuple[str | int, ...]] = []
    for path in value:
        if isinstance(path, list) and all(isinstance(item, (str, int)) for item in path):
            result.append(tuple(path))
    return result


def _path_is_sensitive(
    path: tuple[str | int, ...],
    sensitive_paths: list[tuple[str | int, ...]],
) -> bool:
    return any(path[: len(candidate)] == candidate for candidate in sensitive_paths)


def _redact_paths(
    value: Any,
    sensitive_paths: list[tuple[str | int, ...]],
    path: tuple[str | int, ...] = (),
) -> Any:
    if _path_is_sensitive(path, sensitive_paths):
        return _SENSITIVE
    if isinstance(value, dict):
        return {
            str(key): _redact_paths(item, sensitive_paths, (*path, str(key)))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _redact_paths(item, sensitive_paths, (*path, index))
            for index, item in enumerate(value)
        ]
    return value


def _secret_like(path: tuple[str | int, ...]) -> bool:
    return any(isinstance(part, str) and _SECRET_KEY.search(part) for part in path)


def _redact_secret_like(value: Any, path: tuple[str | int, ...] = ()) -> Any:
    if path and _secret_like(path):
        return _SENSITIVE
    if isinstance(value, dict):
        return {
            str(key): _redact_secret_like(item, (*path, str(key)))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _redact_secret_like(item, (*path, index))
            for index, item in enumerate(value)
        ]
    return value


def _unmarked_secret_count(values: Any, sensitive: Any) -> int:
    return sum(
        1
        for path, value in _walk_leaves(values)
        if value not in (None, "") and _secret_like(path) and not _sensitivity_at(sensitive, path)
    )


def _unmarked_raw_secret_count(
    values: Any,
    sensitive_paths: list[tuple[str | int, ...]],
) -> int:
    return sum(
        1
        for path, value in _walk_leaves(values)
        if value not in (None, "")
        and _secret_like(path)
        and not _path_is_sensitive(path, sensitive_paths)
    )


def _has_sensitive(mask: Any) -> bool:
    if mask is True:
        return True
    if isinstance(mask, dict):
        return any(_has_sensitive(value) for value in mask.values())
    if isinstance(mask, list):
        return any(_has_sensitive(value) for value in mask)
    return False


def _current_posture_changes(
    address: str,
    resource_type: str,
    values: dict[str, Any],
) -> list[dict[str, Any]]:
    if resource_type not in {"aws_db_instance", "aws_rds_cluster"}:
        return []
    findings: list[dict[str, Any]] = []
    if values.get("publicly_accessible") is True:
        findings.append(
            _change(
                f"{address}.publicly_accessible",
                "public_database",
                "dangerous",
                "State shows an internet-addressable RDS database; verify network paths, "
                "security groups, authentication, and the intended exposure boundary.",
            )
        )
    if values.get("storage_encrypted") is False:
        findings.append(
            _change(
                f"{address}.storage_encrypted",
                "unencrypted_database_storage",
                "dangerous",
                "State shows RDS storage encryption disabled; verify data classification, "
                "snapshot exposure, and migration requirements.",
            )
        )
    if values.get("deletion_protection") is False:
        findings.append(
            _change(
                f"{address}.deletion_protection",
                "database_deletion_protection",
                "review",
                "State shows database deletion protection disabled; verify backup, restore, and "
                "approval controls before destructive operations.",
            )
        )
    return findings


def _output_changes(outputs: dict[str, Any], *, raw: bool) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for name, value in outputs.items():
        output = _mapping(value)
        sensitive = output.get("sensitive") is True
        changes.append(
            _change(
                f"terraform_state.outputs.{name}",
                "sensitive_output" if sensitive else "output",
                "review",
                "State contains an output marked sensitive; its plaintext value is intentionally "
                "omitted, but anyone with state access can read it."
                if sensitive
                else "State contains a root output; its value is intentionally omitted from the "
                "report and should be reviewed for intended disclosure.",
            )
        )
        if (
            _SECRET_KEY.search(str(name))
            and not sensitive
            and output.get("value") not in (None, "")
        ):
            changes.append(
                _change(
                    f"terraform_state.outputs.{name}.sensitivity",
                    "unmarked_sensitive_output",
                    "dangerous",
                    "A secret-like output is stored without the sensitive marker. The value is "
                    "intentionally omitted from this report.",
                )
            )
        if raw and "value" not in output:
            changes.append(
                _change(
                    f"terraform_state.outputs.{name}.value",
                    "malformed_output",
                    "dangerous",
                    "Raw state output metadata is missing its value field.",
                )
            )
    return changes


def _show_modules(module: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(module, dict):
        return
    resources = module.get("resources", [])
    if isinstance(resources, list):
        for resource in resources:
            if isinstance(resource, dict):
                yield resource
    children = module.get("child_modules", [])
    if isinstance(children, list):
        for child in children:
            yield from _show_modules(child)


def _show_resource_changes(document: dict[str, Any]) -> list[dict[str, Any]]:
    root = _mapping(_mapping(document.get("values")).get("root_module"))
    changes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for resource in _show_modules(root):
        address = str(resource.get("address", "")).strip()
        resource_type = str(resource.get("type", "")).strip()
        if not address or not resource_type:
            changes.append(
                _change(
                    "terraform_state.resources.<malformed>",
                    "malformed_resource",
                    "dangerous",
                    "State resource is missing its opaque address or provider resource type.",
                )
            )
            continue
        if address in seen:
            changes.append(
                _change(
                    address,
                    "duplicate_resource_binding",
                    "dangerous",
                    "The state representation repeats a resource address, violating the expected "
                    "one-to-one binding between configuration and remote objects.",
                )
            )
        seen.add(address)
        values = _mapping(resource.get("values"))
        mask = resource.get("sensitive_values", {})
        mode = str(resource.get("mode", "managed"))
        changes.append(
            _change(
                address,
                "data_source" if mode == "data" else "managed_resource",
                "review",
                "State records the current cached attributes for this data source."
                if mode == "data"
                else "State binds this managed resource address to a remote object; current "
                "attributes are evaluated by resource-aware rules without being serialized.",
                resource_type=resource_type,
                metadata={
                    "before": {},
                    "after": _redact_secret_like(_redact_mask(values, mask)),
                },
            )
        )
        changes.extend(_current_posture_changes(address, resource_type, values))
        unmarked = _unmarked_secret_count(values, mask)
        if unmarked:
            changes.append(
                _change(
                    f"{address}.sensitive_values",
                    "unmarked_sensitive_attribute",
                    "dangerous",
                    f"State contains {unmarked} non-empty secret-like attribute(s) outside the "
                    "sensitivity mask; values are intentionally omitted.",
                )
            )
        if _has_sensitive(mask):
            changes.append(
                _change(
                    f"{address}.sensitive_values",
                    "sensitive_attributes",
                    "review",
                    "State marks one or more resource attributes sensitive. They are redacted "
                    "before analysis, but remain plaintext to anyone who can read the state.",
                )
            )
    return changes


def _raw_address(resource: dict[str, Any], instance: dict[str, Any]) -> str:
    module = str(resource.get("module", "")).strip()
    mode = str(resource.get("mode", "managed"))
    prefix = "data." if mode == "data" else ""
    address = f"{prefix}{resource.get('type', '<unknown>')}.{resource.get('name', '<unknown>')}"
    if module:
        address = f"{module}.{address}"
    if "index_key" in instance:
        address += f"[{json.dumps(instance['index_key'], ensure_ascii=True)}]"
    return address


def _raw_resource_changes(document: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_resource in document.get("resources", []):
        if not isinstance(raw_resource, dict):
            changes.append(
                _change(
                    "terraform_state.resources.<malformed>",
                    "malformed_resource",
                    "dangerous",
                    "Raw state resources must be mapping objects.",
                )
            )
            continue
        resource = _mapping(raw_resource)
        resource_type = str(resource.get("type", "")).strip()
        instances = resource.get("instances", [])
        if not resource_type or not isinstance(instances, list):
            changes.append(
                _change(
                    "terraform_state.resources.<malformed>",
                    "malformed_resource",
                    "dangerous",
                    "Raw state resource is missing its type or instance list.",
                )
            )
            continue
        for raw_instance in instances:
            if not isinstance(raw_instance, dict):
                changes.append(
                    _change(
                        f"terraform_state.resources.{resource_type}",
                        "malformed_instance",
                        "dangerous",
                        "Raw state resource contains a non-mapping instance.",
                    )
                )
                continue
            instance = _mapping(raw_instance)
            address = _raw_address(resource, instance)
            if address in seen:
                changes.append(
                    _change(
                        address,
                        "duplicate_resource_binding",
                        "dangerous",
                        "Raw state repeats a resource instance address, making the remote-object "
                        "binding ambiguous.",
                    )
                )
            seen.add(address)
            attributes = _mapping(instance.get("attributes"))
            sensitive_paths = _raw_sensitive_paths(instance.get("sensitive_attributes", []))
            changes.append(
                _change(
                    address,
                    "data_source" if resource.get("mode") == "data" else "managed_resource",
                    "review",
                    "Raw state records this current resource instance; attributes are evaluated "
                    "by resource-aware rules without being serialized.",
                    resource_type=resource_type,
                    metadata={
                        "before": {},
                        "after": _redact_secret_like(
                            _redact_paths(attributes, sensitive_paths)
                        ),
                    },
                )
            )
            changes.extend(_current_posture_changes(address, resource_type, attributes))
            unmarked = _unmarked_raw_secret_count(attributes, sensitive_paths)
            if unmarked:
                changes.append(
                    _change(
                        f"{address}.sensitive_attributes",
                        "unmarked_sensitive_attribute",
                        "dangerous",
                        f"Raw state contains {unmarked} non-empty secret-like attribute(s) not "
                        "listed as sensitive; values are intentionally omitted.",
                    )
                )
            if sensitive_paths:
                changes.append(
                    _change(
                        f"{address}.sensitive_attributes",
                        "sensitive_attributes",
                        "review",
                        "Raw state marks one or more attribute paths sensitive. They are redacted "
                        "before analysis but remain present in the snapshot.",
                    )
                )
            if instance.get("status") == "tainted":
                changes.append(
                    _change(
                        f"{address}.status",
                        "tainted_instance",
                        "dangerous",
                        "Resource instance is tainted and Terraform/OpenTofu will normally plan to "
                        "replace it on the next operation.",
                    )
                )
            if instance.get("deposed") not in (None, ""):
                changes.append(
                    _change(
                        f"{address}.deposed",
                        "deposed_instance",
                        "dangerous",
                        "State retains a deposed resource object from replacement; verify cleanup, "
                        "ownership, and recovery before further operations.",
                    )
                )
    return changes


def _check_changes(checks: Any) -> list[dict[str, Any]]:
    if not isinstance(checks, list):
        return []
    changes: list[dict[str, Any]] = []
    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            continue
        address = _mapping(check.get("address"))
        display = str(address.get("to_display") or f"check.{index}")
        statuses = [str(check.get("status", "unknown"))]
        instances = check.get("instances", [])
        if isinstance(instances, list):
            statuses.extend(
                str(instance.get("status", "unknown"))
                for instance in instances
                if isinstance(instance, dict)
            )
        if any(status in {"error", "fail"} for status in statuses):
            changes.append(
                _change(
                    f"terraform_state.checks.{display}",
                    "failed_check",
                    "dangerous",
                    "A saved precondition, postcondition, or output check failed or errored. "
                    "Problem messages are intentionally omitted because they may contain data.",
                )
            )
        elif any(status == "unknown" for status in statuses):
            changes.append(
                _change(
                    f"terraform_state.checks.{display}",
                    "unknown_check",
                    "review",
                    "A saved check result is unknown and does not prove the condition passed.",
                )
            )
    return changes


class TerraformStateAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "terraform-state"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("terraform_state")
        return (
            isinstance(payload, dict)
            and payload.get("artifact") in {"show-json", "raw-v4"}
            and isinstance(payload.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["terraform_state"]
        artifact = payload["artifact"]
        document = _mapping(payload["document"])
        changes = [
            _change(
                "terraform_state.snapshot",
                "state_snapshot",
                "review",
                "Terraform/OpenTofu state contains infrastructure identities and cached values, "
                "including sensitive values in plaintext. Treat the input and all derived "
                "artifacts as secrets even though this report omits values.",
            )
        ]
        if artifact == "show-json":
            outputs = _mapping(_mapping(document.get("values")).get("outputs"))
            changes.extend(_output_changes(outputs, raw=False))
            changes.extend(_show_resource_changes(document))
            changes.extend(_check_changes(document.get("checks")))
        else:
            changes.append(
                _change(
                    "terraform_state.raw_format",
                    "unstable_raw_format",
                    "review",
                    "Raw state v4 is an internal format subject to change. Prefer `terraform show "
                    "-json` or `tofu show -json` for a stable read-only integration.",
                )
            )
            changes.extend(_output_changes(_mapping(document.get("outputs")), raw=True))
            changes.extend(_raw_resource_changes(document))
        changes.append(
            _change(
                "terraform_state.effective_state",
                "state_boundary",
                "review",
                "Static state analysis cannot prove backend encryption, locking, access control, "
                "audit logging, freshness, provider schema compatibility, configuration parity, "
                "remote-object drift, or one-to-one identity outside this snapshot. It never "
                "modifies state or contacts providers.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=str(raw.get("ResourceType") or f"terraform_state_{raw['Kind']}"),
            actions=("inspect",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_terraform_state(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    payload = _mapping(data.get("terraform_state"))
    artifact = str(payload.get("artifact", "unknown"))
    document = _mapping(payload.get("document"))
    changes = TerraformStateAdapter().analyze(data, tool_name="Terraform/OpenTofu state")
    summary = PlanSummary(
        path=Path("terraform-state://"),
        terraform_version=str(document.get("terraform_version", "")) or None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(
        summary,
        catalog=catalog,
        tool_name="Terraform/OpenTofu state",
    )
    gate["adapter"] = "terraform-state"
    gate["artifact"] = artifact
    gate["serial"] = document.get("serial") if artifact == "raw-v4" else None
    gate["resource_count"] = sum(
        change.resource_type
        not in {
            "terraform_state_state_snapshot",
            "terraform_state_state_boundary",
            "terraform_state_unstable_raw_format",
        }
        and not change.resource_type.startswith("terraform_state_")
        for change in changes
    )
    gate["output_count"] = len(
        _mapping(
            document.get("outputs")
            if artifact == "raw-v4"
            else _mapping(document.get("values")).get("outputs")
        )
    )
    gate["total_changes"] = len(changes)
    return gate
