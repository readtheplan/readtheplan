from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_TYPE_MAP = {
    "aws:cloudwatch:LogGroup": "aws_cloudwatch_log_group",
    "aws:cloudwatch/logGroup:LogGroup": "aws_cloudwatch_log_group",
    "aws:ec2:Instance": "aws_instance",
    "aws:ec2/instance:Instance": "aws_instance",
    "aws:ec2:SecurityGroup": "aws_security_group",
    "aws:ec2/securityGroup:SecurityGroup": "aws_security_group",
    "aws:ec2:SecurityGroupRule": "aws_security_group_rule",
    "aws:ec2/securityGroupRule:SecurityGroupRule": "aws_security_group_rule",
    "aws:ecs:Service": "aws_ecs_service",
    "aws:ecs/service:Service": "aws_ecs_service",
    "aws:eks:Cluster": "aws_eks_cluster",
    "aws:eks/cluster:Cluster": "aws_eks_cluster",
    "aws:iam:Policy": "aws_iam_policy",
    "aws:iam/policy:Policy": "aws_iam_policy",
    "aws:iam:Role": "aws_iam_role",
    "aws:iam/role:Role": "aws_iam_role",
    "aws:kms:Key": "aws_kms_key",
    "aws:kms/key:Key": "aws_kms_key",
    "aws:lambda:Function": "aws_lambda_function",
    "aws:lambda/function:Function": "aws_lambda_function",
    "aws:rds:Cluster": "aws_rds_cluster",
    "aws:rds/cluster:Cluster": "aws_rds_cluster",
    "aws:rds:Instance": "aws_db_instance",
    "aws:rds/instance:Instance": "aws_db_instance",
    "aws:s3:Bucket": "aws_s3_bucket",
    "aws:s3/bucket:Bucket": "aws_s3_bucket",
    "azure-native:storage:StorageAccount": "azurerm_storage_account",
    "gcp:storage:Bucket": "google_storage_bucket",
    "gcp:storage/bucket:Bucket": "google_storage_bucket",
}

_REPLACEMENT_OPS = {
    "create-replacement",
    "delete-replaced",
    "discard-replaced",
    "import-replacement",
    "read-replacement",
    "remove-pending-replace",
    "replace",
}
_SAFE_OPS = {"read", "refresh", "same"}
_REVIEW_OPS = {"diff", "discard", "import"}


class PulumiPreviewError(ValueError):
    """Raised when Pulumi preview text is not valid digest JSON or JSON events."""


def parse_pulumi_preview(source: str) -> dict[str, Any]:
    """Parse a Pulumi preview digest, event array, or JSONL event stream."""
    try:
        data = json.loads(source)
    except json.JSONDecodeError:
        events: list[Any] = []
        for line_number, line in enumerate(source.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise PulumiPreviewError(
                    f"invalid JSON event on line {line_number}: {exc.msg}"
                ) from exc
        if not events:
            raise PulumiPreviewError("preview input is empty")
        data = events

    if isinstance(data, list):
        return {"events": data}
    if not isinstance(data, dict):
        raise PulumiPreviewError("preview input must be a JSON object or event stream")
    return data


def _snake_case(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()


def _resource_type_from_urn(urn: str) -> str:
    parts = urn.split("::")
    return parts[-2] if len(parts) >= 3 else ""


def _normalize_properties(value: Any) -> Any:
    if isinstance(value, dict):
        return {_snake_case(str(key)): _normalize_properties(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_properties(item) for item in value]
    return value


def _state(step: dict[str, Any], digest_key: str, event_key: str) -> dict[str, Any]:
    value = step.get(digest_key, step.get(event_key, {}))
    return value if isinstance(value, dict) else {}


class PulumiAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "pulumi"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        if isinstance(input_data.get("steps"), list):
            return True
        events = input_data.get("events")
        return isinstance(events, list) and any(
            isinstance(event, dict) and "resourcePreEvent" in event for event in events
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        steps = input_data.get("steps")
        if not isinstance(steps, list):
            steps = self._steps_from_events(input_data.get("events", []))

        changes: list[dict[str, Any]] = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            urn = str(step.get("urn", ""))
            old_state = _state(step, "oldState", "old")
            new_state = _state(step, "newState", "new")
            resource_type = str(
                step.get("type")
                or new_state.get("type")
                or old_state.get("type")
                or _resource_type_from_urn(urn)
            )
            if resource_type == "pulumi:pulumi:Stack":
                continue
            changes.append(
                {
                    "op": str(step.get("op", "unknown")).lower().replace("_", "-"),
                    "urn": urn,
                    "type": resource_type,
                    "diffReasons": step.get("diffReasons", step.get("diffs", [])),
                    "replaceReasons": step.get("replaceReasons", step.get("keys", [])),
                    "_metadata": {
                        "before": _normalize_properties(old_state.get("inputs", {})),
                        "after": _normalize_properties(new_state.get("inputs", {})),
                    },
                }
            )
        return changes

    def _steps_from_events(self, events: Any) -> list[dict[str, Any]]:
        if not isinstance(events, list):
            return []
        steps: list[dict[str, Any]] = []
        for event in events:
            if not isinstance(event, dict):
                continue
            resource_event = event.get("resourcePreEvent")
            if not isinstance(resource_event, dict):
                continue
            metadata = resource_event.get("metadata")
            if isinstance(metadata, dict):
                steps.append(metadata)
        return steps

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        op = str(raw.get("op", "unknown"))
        risk = "review"
        actions = ("unknown",)
        explanation = f"Pulumi operation '{op}' requires review."

        if op == "create":
            risk = "safe"
            actions = ("create",)
            explanation = "Pulumi will create this resource."
        elif op == "update":
            actions = ("update",)
            explanation = "Pulumi will update this resource in place."
        elif op == "delete":
            risk = "irreversible"
            actions = ("delete",)
            explanation = "Pulumi will delete this resource."
        elif op in _REPLACEMENT_OPS:
            risk = "dangerous"
            actions = ("delete", "create")
            explanation = f"Pulumi will perform replacement operation '{op}'."
        elif op in _SAFE_OPS:
            risk = "safe"
            actions = ("read",) if op != "same" else ("no-op",)
            explanation = f"Pulumi operation '{op}' does not change desired infrastructure."
        elif op in _REVIEW_OPS:
            actions = ("update",)
            explanation = (
                f"Pulumi operation '{op}' changes state ownership or computes a diff; "
                "review it before applying."
            )

        resource_type = self._normalize_resource_type(str(raw.get("type", "")))
        urn = str(raw.get("urn", ""))
        address = urn or resource_type or "<unknown>"
        return ResourceChange(
            address=address,
            resource_type=resource_type,
            actions=actions,
            risk=risk,
            explanation=explanation,
        )

    def _normalize_resource_type(self, pulumi_type: str) -> str:
        if pulumi_type in _TYPE_MAP:
            return _TYPE_MAP[pulumi_type]
        if not pulumi_type:
            return "unknown"

        provider, _, remainder = pulumi_type.partition(":")
        token = remainder.rsplit(":", 1)[-1] if remainder else pulumi_type
        normalized_token = _snake_case(token)
        prefixes = {
            "aws": "aws",
            "aws-native": "aws",
            "azure": "azurerm",
            "azure-native": "azurerm",
            "gcp": "google",
            "kubernetes": "kubernetes",
        }
        prefix = prefixes.get(provider, _snake_case(provider))
        return "_".join(part for part in (prefix, normalized_token) if part)


def analyze_pulumi(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = PulumiAdapter().analyze(data, tool_name="Pulumi")
    summary = PlanSummary(
        path=Path("pulumi://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Pulumi")
    gate["adapter"] = "pulumi"
    gate["total_changes"] = len(changes)
    return gate
