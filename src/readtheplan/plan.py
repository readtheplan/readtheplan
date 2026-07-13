from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from readtheplan.rules import RuleResult, action_explanation, apply_resource_rules


class PlanError(ValueError):
    """Raised when a Terraform plan JSON file cannot be analyzed."""


@dataclass(frozen=True)
class ResourceChange:
    address: str
    resource_type: str
    actions: tuple[str, ...]
    risk: str
    explanation: str
    #: Provenance of the winning rule — "builtin" or the plugin name that
    #: produced this change's risk classification.
    source: str = "builtin"

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "type": self.resource_type,
            "actions": list(self.actions),
            "risk": self.risk,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class PlanSummary:
    path: Path
    terraform_version: str | None
    resource_changes: tuple[ResourceChange, ...]
    format_version: str | None = None
    plan_findings: tuple[ResourceChange, ...] = ()

    @property
    def all_changes(self) -> tuple[ResourceChange, ...]:
        """Return resource operations plus plan-level safety findings."""
        return self.resource_changes + self.plan_findings

    @property
    def action_counts(self) -> Counter[str]:
        counts: Counter[str] = Counter()
        for change in self.resource_changes:
            key = "/".join(change.actions) if change.actions else "unknown"
            counts[key] += 1
        return counts

    @property
    def risk_counts(self) -> Counter[str]:
        return Counter(change.risk for change in self.all_changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "terraform_version": self.terraform_version,
            "format_version": self.format_version,
            "resource_change_count": len(self.resource_changes),
            "plan_finding_count": len(self.plan_findings),
            "actions": dict(sorted(self.action_counts.items())),
            "risks": dict(sorted(self.risk_counts.items())),
            "changes": [change.to_dict() for change in self.resource_changes],
            "plan_findings": [finding.to_dict() for finding in self.plan_findings],
        }


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


def analyze_plan_file(path: str | Path | dict, *, use_rules: bool = True, _original_path: Path | None = None) -> PlanSummary:  # noqa: E501
    if isinstance(path, dict):
        data = path
        plan_path = _original_path or Path("<inline>")
    else:
        plan_path = Path(path)
        data = load_plan(plan_path)
    format_version = _plan_format_version(data.get("format_version"))
    resource_changes = data.get("resource_changes", [])
    if resource_changes is None:
        resource_changes = []
    if not isinstance(resource_changes, list):
        raise PlanError("Terraform plan field 'resource_changes' must be a list")

    changes = tuple(
        _resource_change(item, use_rules=use_rules) for item in resource_changes
    )
    terraform_version = data.get("terraform_version")
    if terraform_version is not None and not isinstance(terraform_version, str):
        raise PlanError("Terraform plan field 'terraform_version' must be a string")

    return PlanSummary(
        path=plan_path,
        terraform_version=terraform_version,
        resource_changes=changes,
        format_version=format_version,
        plan_findings=tuple(_plan_findings(data)),
    )


def analyze(
    plan: str | Path | dict[str, Any],
    *,
    use_rules: bool = True,
) -> PlanSummary:
    """Analyze a Terraform plan and return typed results.

    This is the primary public API. Accepts either a file path (string or
    ``Path``) or a pre-parsed plan dictionary (e.g. from ``json.loads``).

    Args:
        plan: Path to a ``terraform show -json`` output file, or a
            pre-parsed plan JSON dictionary.
        use_rules: When True (default), applies the built-in resource-aware
            risk rules in addition to the action-based baseline.

    Returns:
        A :class:`PlanSummary` with full typed access to resource changes,
        action counts, and risk counts.

    Example:
        >>> from readtheplan import analyze
        >>> summary = analyze("plan.json")
        >>> summary.risk_counts
        Counter({'safe': 1, 'review': 2, 'dangerous': 1})

        >>> changes = summary.resource_changes
        >>> for c in changes:
        ...     print(f"{c.address}: {c.risk}")
    """
    return analyze_plan_file(plan, use_rules=use_rules)


def _resource_change(item: Any, *, use_rules: bool = True) -> ResourceChange:
    if not isinstance(item, dict):
        return ResourceChange(
            address="<unknown>",
            resource_type="<unknown>",
            actions=("unknown",),
            risk="review",
            explanation=(
                "Terraform resource change metadata is malformed; human review is required."
            ),
        )

    address = _identifier(item.get("address"), "<unknown>")
    resource_type = _identifier(item.get("type"), "<unknown>")
    change = item.get("change") if isinstance(item.get("change"), dict) else {}
    actions = change.get("actions", ["unknown"])
    if not isinstance(actions, list):
        actions = ["unknown"]

    action_tuple = tuple(_identifier(action, "unknown") for action in actions)
    baseline = RuleResult(
        risk=_risk_for_actions(action_tuple),
        explanation=action_explanation(action_tuple),
    )
    result = (
        apply_resource_rules(
            resource_type=resource_type,
            actions=action_tuple,
            change=change,
            baseline=baseline,
        )
        if use_rules
        else baseline
    )
    return ResourceChange(
        address=address,
        resource_type=resource_type,
        actions=action_tuple,
        risk=result.risk,
        explanation=result.explanation,
        source=result.source,
    )


def _risk_for_actions(actions: tuple[str, ...]) -> str:
    if not actions:
        return "review"
    action_set = set(actions)
    if "delete" in action_set and "create" in action_set:
        return "dangerous"
    if "delete" in action_set:
        return "irreversible"
    if "update" in action_set:
        return "review"
    if "forget" in action_set:
        return "dangerous"
    if action_set <= {"no-op", "read"}:
        return "safe"
    # Only allow "create" to produce "safe" when all actions are known.
    # Unknown/malformed actions (e.g. ["create","bogus"]) must be "review"
    # per ADR 0003 — don't classify garbage as safe.
    KNOWN_ACTIONS = {"no-op", "read", "create", "update", "delete", "forget"}
    if "create" in action_set and action_set <= KNOWN_ACTIONS:
        return "safe"
    return "review"


_FORMAT_VERSION = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)(?:\.\d+)?$")
_SECRET_NAME = re.compile(
    r"(?:^|[._-])(?:api[_-]?key|credential|password|private[_-]?key|secret|token)"
    r"(?:$|[._-])",
    re.IGNORECASE,
)


def _plan_format_version(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PlanError("Terraform plan field 'format_version' must be a string")
    match = _FORMAT_VERSION.fullmatch(value.strip())
    if match is None:
        raise PlanError("Terraform plan field 'format_version' is malformed")
    major = int(match.group("major"))
    minor = int(match.group("minor"))
    if major >= 2 or (major == 0 and minor < 1):
        raise PlanError("Terraform plan format version is not supported")
    return value.strip()


def _optional_bool(document: dict[str, Any], key: str) -> bool | None:
    value = document.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise PlanError(f"Terraform plan field {key!r} must be a boolean")
    return value


def _optional_list(document: dict[str, Any], key: str) -> list[Any]:
    value = document.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise PlanError(f"Terraform plan field {key!r} must be a list")
    return value


def _optional_mapping(document: dict[str, Any], key: str) -> dict[str, Any]:
    value = document.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PlanError(f"Terraform plan field {key!r} must be an object")
    return value


def _identifier(value: Any, default: str) -> str:
    text = value.strip() if isinstance(value, str) else default
    text = text or default
    if len(text) <= 512:
        return text
    return text[:509] + "..."


def _finding(
    address: str,
    finding_type: str,
    actions: tuple[str, ...],
    risk: str,
    explanation: str,
) -> ResourceChange:
    return ResourceChange(
        address=address,
        resource_type=finding_type,
        actions=actions,
        risk=risk,
        explanation=explanation,
    )


def _change_actions(value: Any) -> tuple[str, ...]:
    change = value if isinstance(value, dict) else {}
    actions = change.get("actions")
    if not isinstance(actions, list) or not actions:
        return ("unknown",)
    return tuple(_identifier(action, "unknown") for action in actions)


def _mask_has_true(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_mask_has_true(item) for item in value.values())
    if isinstance(value, list):
        return any(_mask_has_true(item) for item in value)
    return False


def _integrity_findings(document: dict[str, Any]) -> list[ResourceChange]:
    findings: list[ResourceChange] = []
    if _optional_bool(document, "errored") is True:
        findings.append(
            _finding(
                "terraform.plan.errored",
                "terraform_plan_errored",
                ("error",),
                "dangerous",
                "Planning failed. The partial actions shown before the error are not an "
                "applyable or authoritative execution plan; resolve the diagnostics and create "
                "a new plan before approval.",
            )
        )
    if _optional_bool(document, "applyable") is False:
        findings.append(
            _finding(
                "terraform.plan.applyable",
                "terraform_plan_not_applyable",
                ("not-applyable",),
                "dangerous",
                "Terraform marks this plan as not applyable. Automation must not approve or "
                "apply it even if the visible resource operations appear safe.",
            )
        )
    if _optional_bool(document, "complete") is False:
        findings.append(
            _finding(
                "terraform.plan.complete",
                "terraform_plan_incomplete",
                ("incomplete",),
                "review",
                "Terraform marks this plan as incomplete. Applying it will require at least one "
                "additional plan/apply round before the actual state is expected to converge.",
            )
        )
    return findings


def _deferred_findings(document: dict[str, Any]) -> list[ResourceChange]:
    findings: list[ResourceChange] = []
    for index, item in enumerate(_optional_list(document, "deferred_changes")):
        resource = item.get("resource_change") if isinstance(item, dict) else None
        resource = resource if isinstance(resource, dict) else {}
        address = _identifier(
            resource.get("address"), f"terraform.deferred_changes[{index}]"
        )
        resource_type = _identifier(resource.get("type"), "unknown")
        change = resource.get("change") if isinstance(resource.get("change"), dict) else {}
        findings.append(
            _finding(
                address,
                "terraform_deferred_change",
                _change_actions(change),
                "dangerous",
                f"Terraform deferred planning for a {resource_type} object, so this plan does "
                "not contain the final operation or outcome. Require a converged follow-up plan "
                "before treating the change set as complete.",
            )
        )
    return findings


def _drift_findings(document: dict[str, Any]) -> list[ResourceChange]:
    findings: list[ResourceChange] = []
    for index, item in enumerate(_optional_list(document, "resource_drift")):
        resource = item if isinstance(item, dict) else {}
        address = _identifier(resource.get("address"), f"terraform.resource_drift[{index}]")
        resource_type = _identifier(resource.get("type"), "unknown")
        change = resource.get("change") if isinstance(resource.get("change"), dict) else {}
        actions = _change_actions(change)
        risk = "dangerous" if "delete" in actions else "review"
        findings.append(
            _finding(
                address,
                "terraform_resource_drift",
                actions,
                risk,
                f"Terraform detected out-of-band drift for a {resource_type} object. Confirm "
                "whether the external change was authorized and whether it altered the proposed "
                "plan before approval.",
            )
        )
    return findings


def _output_findings(document: dict[str, Any]) -> list[ResourceChange]:
    findings: list[ResourceChange] = []
    for name, item in _optional_mapping(document, "output_changes").items():
        output = item if isinstance(item, dict) else {}
        change = output.get("change") if isinstance(output.get("change"), dict) else output
        actions = _change_actions(change)
        before_sensitive = _mask_has_true(change.get("before_sensitive"))
        after_sensitive = _mask_has_true(change.get("after_sensitive"))
        exposes_sensitive = before_sensitive and not after_sensitive and "delete" not in actions
        secret_like_unmarked = (
            bool(_SECRET_NAME.search(str(name)))
            and not after_sensitive
            and "delete" not in actions
        )
        dangerous = exposes_sensitive or secret_like_unmarked
        findings.append(
            _finding(
                f"output.{_identifier(name, 'unknown')}",
                "terraform_output_sensitive_exposure"
                if dangerous
                else "terraform_output_change",
                actions,
                "dangerous" if dangerous else "review",
                "A root output with a secret-like name or prior sensitive marking becomes "
                "non-sensitive; prevent plaintext disclosure in CLI output, state consumers, "
                "logs, and CI artifacts."
                if dangerous
                else "Terraform plans to change a root output. Review downstream automation, "
                "remote-state consumers, compatibility, and whether the sensitivity marker is "
                "appropriate.",
            )
        )
    return findings


def _check_findings(document: dict[str, Any]) -> list[ResourceChange]:
    findings: list[ResourceChange] = []
    for index, item in enumerate(_optional_list(document, "checks")):
        check = item if isinstance(item, dict) else {}
        static_address = check.get("address") if isinstance(check.get("address"), dict) else {}
        instances = check.get("instances")
        candidates = instances if isinstance(instances, list) and instances else [check]
        for instance_index, candidate in enumerate(candidates):
            candidate = candidate if isinstance(candidate, dict) else {}
            dynamic_address = (
                candidate.get("address")
                if isinstance(candidate.get("address"), dict)
                else {}
            )
            address = _identifier(
                dynamic_address.get("to_display") or static_address.get("to_display"),
                f"terraform.checks[{index}].instances[{instance_index}]",
            )
            status = candidate.get("status")
            if status not in {"fail", "error", "unknown"}:
                continue
            risk = "dangerous" if status in {"fail", "error"} else "review"
            findings.append(
                _finding(
                    address,
                    f"terraform_check_{status}",
                    (str(status),),
                    risk,
                    "A Terraform precondition, postcondition, check, or output condition failed "
                    "or errored. Resolve the condition and generate a clean plan before approval."
                    if risk == "dangerous"
                    else "A Terraform check cannot be decided until apply. Review the condition, "
                    "its data sources, and the failure behavior before approving the plan.",
                )
            )
    return findings


def _action_invocation_findings(document: dict[str, Any]) -> list[ResourceChange]:
    findings: list[ResourceChange] = []
    for index, item in enumerate(_optional_list(document, "action_invocations")):
        action = item if isinstance(item, dict) else {}
        address = _identifier(
            action.get("address"), f"terraform.action_invocations[{index}]"
        )
        action_type = _identifier(action.get("type"), "provider-defined")
        trigger = action.get("lifecycle_action_trigger")
        trigger_context = (
            " from a resource lifecycle trigger"
            if isinstance(trigger, dict)
            else " from a direct invocation"
        )
        findings.append(
            _finding(
                address,
                "terraform_action_invocation",
                ("invoke",),
                "dangerous",
                f"Terraform will invoke the {action_type} provider action{trigger_context}. "
                "Provider actions can perform day-two operations outside resource state and may "
                "have no undo; review provider code, target identity, redacted configuration, "
                "side effects, authorization, and recovery before apply.",
            )
        )
    return findings


def _plan_findings(document: dict[str, Any]) -> list[ResourceChange]:
    findings = _integrity_findings(document)
    findings.extend(_deferred_findings(document))
    findings.extend(_drift_findings(document))
    findings.extend(_output_findings(document))
    findings.extend(_check_findings(document))
    findings.extend(_action_invocation_findings(document))
    return findings
