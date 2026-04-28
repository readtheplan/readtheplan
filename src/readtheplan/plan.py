from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class PlanError(ValueError):
    """Raised when a Terraform plan JSON file cannot be analyzed."""


@dataclass(frozen=True)
class ResourceChange:
    address: str
    resource_type: str
    actions: tuple[str, ...]
    risk: str


@dataclass(frozen=True)
class PlanSummary:
    path: Path
    terraform_version: str | None
    resource_changes: tuple[ResourceChange, ...]

    @property
    def action_counts(self) -> Counter[str]:
        counts: Counter[str] = Counter()
        for change in self.resource_changes:
            key = "/".join(change.actions) if change.actions else "unknown"
            counts[key] += 1
        return counts

    @property
    def risk_counts(self) -> Counter[str]:
        return Counter(change.risk for change in self.resource_changes)


def load_plan(path: str | Path) -> dict[str, Any]:
    plan_path = Path(path)
    if not plan_path.exists():
        raise PlanError(f"plan file does not exist: {plan_path}")
    if plan_path.is_dir():
        raise PlanError(f"plan path is a directory, not a file: {plan_path}")

    try:
        raw = plan_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlanError(f"cannot read plan file {plan_path}: {exc}") from exc

    if not raw.strip():
        raise PlanError(f"plan file is empty: {plan_path}")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PlanError(
            f"invalid JSON in {plan_path}: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise PlanError(f"Terraform plan JSON must be an object: {plan_path}")

    return data


def analyze_plan_file(path: str | Path) -> PlanSummary:
    plan_path = Path(path)
    data = load_plan(plan_path)
    resource_changes = data.get("resource_changes", [])
    if resource_changes is None:
        resource_changes = []
    if not isinstance(resource_changes, list):
        raise PlanError("Terraform plan field 'resource_changes' must be a list")

    changes = tuple(_resource_change(item) for item in resource_changes)
    terraform_version = data.get("terraform_version")
    if terraform_version is not None and not isinstance(terraform_version, str):
        terraform_version = str(terraform_version)

    return PlanSummary(
        path=plan_path,
        terraform_version=terraform_version,
        resource_changes=changes,
    )


def _resource_change(item: Any) -> ResourceChange:
    if not isinstance(item, dict):
        return ResourceChange(
            address="<unknown>",
            resource_type="<unknown>",
            actions=("unknown",),
            risk="review",
        )

    address = _string(item.get("address"), "<unknown>")
    resource_type = _string(item.get("type"), "<unknown>")
    change = item.get("change") if isinstance(item.get("change"), dict) else {}
    actions = change.get("actions", ["unknown"])
    if not isinstance(actions, list):
        actions = ["unknown"]

    action_tuple = tuple(_string(action, "unknown") for action in actions)
    return ResourceChange(
        address=address,
        resource_type=resource_type,
        actions=action_tuple,
        risk=_risk_for_actions(action_tuple),
    )


def _risk_for_actions(actions: tuple[str, ...]) -> str:
    action_set = set(actions)
    if "delete" in action_set and "create" in action_set:
        return "dangerous"
    if "delete" in action_set:
        return "irreversible"
    if "update" in action_set:
        return "review"
    if action_set <= {"no-op", "read"}:
        return "safe"
    if "create" in action_set:
        return "safe"
    return "review"


def _string(value: Any, default: str) -> str:
    if value is None:
        return default
    return str(value)
