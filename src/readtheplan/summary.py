from __future__ import annotations

from readtheplan.controls import ControlCatalog, ControlEntry
from readtheplan.plan import PlanSummary


def summary_to_dict(
    summary: PlanSummary,
    catalog: ControlCatalog | None = None,
) -> dict[str, object]:
    payload = summary.to_dict()
    if catalog is None:
        return payload

    payload["framework"] = {
        "name": catalog.framework,
        "version": catalog.framework_version,
        "schema_version": catalog.schema_version,
    }
    for change, change_payload in zip(summary.resource_changes, payload["changes"]):
        change_payload["controls"] = [
            control_to_dict(control)
            for control in catalog.controls_for(
                resource_type=change.resource_type,
                actions=change.actions,
            )
        ]
    return payload


def control_to_dict(control: ControlEntry) -> dict[str, str]:
    return {
        "id": control.id,
        "title": control.title,
        "rationale": control.rationale,
    }
