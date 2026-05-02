from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from readtheplan.attestation import (
    PlanReadAttestation,
    build_plan_read_attestation,
)
from readtheplan.controls import ControlCatalog, ControlEntry
from readtheplan.plan import PlanSummary, ResourceChange

EVIDENCE_SCHEMA = "rtp-evidence-v1"
_PLAN_SOURCE = "terraform-show-json"


class EvidenceError(ValueError):
    """Raised on schema-violating evidence inputs."""


@dataclass(frozen=True)
class Reviewer:
    id: str
    kind: str = "human"


@dataclass(frozen=True)
class EvidenceEnvelope:
    schema: str
    generated_at: str
    plan_sha256: str
    plan_source: str
    framework: Mapping[str, Any]
    agent_attestation: Mapping[str, Any]
    reviewer: Mapping[str, Any] | None
    summary: Mapping[str, Any]
    changes: Sequence[Mapping[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the rtp-evidence-v1 JSON shape."""

        return {
            "schema": self.schema,
            "generated_at": self.generated_at,
            "plan": {
                "source": self.plan_source,
                "sha256": self.plan_sha256,
            },
            "framework": dict(self.framework),
            "agent_attestation": dict(self.agent_attestation),
            "reviewer": dict(self.reviewer) if self.reviewer is not None else None,
            "summary": dict(self.summary),
            "changes": [dict(change) for change in self.changes],
        }


def build_evidence(
    *,
    plan_summary: PlanSummary,
    plan_json: str | bytes,
    catalog: ControlCatalog,
    agent_id: str,
    reviewer: Reviewer | None = None,
    run_id: str | None = None,
    generated_at: datetime | None = None,
) -> EvidenceEnvelope:
    """Produce an evidence envelope."""

    if not agent_id.strip():
        raise EvidenceError("agent_id must be non-empty")

    timestamp = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    try:
        attestation = build_plan_read_attestation(
            agent_id=agent_id,
            plan_json=plan_json,
            read_at=timestamp,
            source=_PLAN_SOURCE,
            run_id=run_id,
        )
    except ValueError as exc:
        raise EvidenceError(str(exc)) from exc

    reviewer_payload = _reviewer_to_dict(reviewer)
    changes = tuple(
        _change_to_dict(change, catalog) for change in plan_summary.resource_changes
    )
    controls_touched = sorted(
        {
            control["id"]
            for change in changes
            for control in change["controls"]
            if isinstance(control["id"], str)
        }
    )

    return EvidenceEnvelope(
        schema=EVIDENCE_SCHEMA,
        generated_at=_format_timestamp(timestamp),
        plan_sha256=attestation.plan_sha256,
        plan_source=attestation.source,
        framework={
            "name": catalog.framework,
            "version": catalog.framework_version,
            "schema_version": catalog.schema_version,
        },
        agent_attestation=_attestation_to_dict(attestation),
        reviewer=reviewer_payload,
        summary={
            "resource_change_count": len(plan_summary.resource_changes),
            "actions": dict(sorted(plan_summary.action_counts.items())),
            "risks": dict(sorted(plan_summary.risk_counts.items())),
            "controls_touched": controls_touched,
        },
        changes=changes,
    )


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _attestation_to_dict(attestation: PlanReadAttestation) -> dict[str, Any]:
    return {
        "agent": attestation.agent_id,
        "read_at": attestation.read_at,
        "plan_sha256": attestation.plan_sha256,
        "source": attestation.source,
        "run_id": attestation.run_id,
        "signature": attestation.signature,
    }


def _reviewer_to_dict(reviewer: Reviewer | None) -> dict[str, str] | None:
    if reviewer is None:
        return None
    if not reviewer.id.strip():
        raise EvidenceError("reviewer id must be non-empty")
    if reviewer.kind not in {"human", "agent"}:
        raise EvidenceError("reviewer kind must be 'human' or 'agent'")
    return {
        "id": reviewer.id,
        "kind": reviewer.kind,
    }


def _change_to_dict(
    change: ResourceChange,
    catalog: ControlCatalog,
) -> dict[str, Any]:
    return {
        "address": change.address,
        "type": change.resource_type,
        "actions": list(change.actions),
        "risk": change.risk,
        "explanation": change.explanation,
        "controls": [
            _control_to_dict(control)
            for control in catalog.controls_for(
                resource_type=change.resource_type,
                actions=change.actions,
            )
        ],
    }


def _control_to_dict(control: ControlEntry) -> dict[str, str]:
    return {
        "id": control.id,
        "title": control.title,
        "rationale": control.rationale,
    }
