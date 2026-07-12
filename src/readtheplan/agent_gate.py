from __future__ import annotations

from collections import Counter
from typing import Any

from readtheplan.controls import ControlCatalog
from readtheplan.evolution import EvolutionEngine
from readtheplan.plan import PlanSummary, ResourceChange
from readtheplan.rules import RISK_ORDER

SCHEMA = "rtp-agent-gate-v1"
SCHEMA_KERNEL = "rtp-kernel-v1"

_RISK_TIERS = ("safe", "review", "dangerous", "irreversible")

_CHECK_HUMAN_APPROVAL = "rtp.check.human_approval"
_CHECK_SECURITY_REVIEW = "rtp.check.security_review"
_CHECK_CHANGE_RECORD = "rtp.check.change_record"
_CHECK_EVIDENCE_PACKET = "rtp.check.evidence_packet"
_CHECK_RECOVERY_PLAN = "rtp.check.recovery_plan"
_CHECK_PEER_REVIEW = "rtp.check.peer_review"
_CHECK_CHANGE_EVIDENCE = "rtp.check.change_evidence"


def agent_gate_to_dict(
    summary: PlanSummary,
    catalog: ControlCatalog | None = None,
    *,
    tool_name: str = "Terraform",
    mode: str = "kernel",
    evolution_engine: EvolutionEngine | None = None,
) -> dict[str, Any]:
    """Build the deterministic local agent gate contract.

    ``tool_name`` controls the user-facing label in reason strings,
    auditor summaries, and evidence checklists.  Use ``"CloudFormation"``,
    ``"Pulumi"``, etc. for non-Terraform adapters so the output reads
    naturally for each IaC tool.

    ``mode`` controls evolution behavior:
      - ``"kernel"`` (default): basic gate, no evolution recording
      - ``"self-improving"``: gate + evolution recording + rule suggestion
    """

    risk = _max_risk(summary)
    decision = _decision_for_risk(risk)
    required_checks = _required_checks(summary, catalog, decision)
    counts = _risk_counts(summary.risk_counts)
    reason = _reason(summary, decision, risk, counts, tool_name=tool_name)

    # Compliance score: 100 - weighted penalties based on risk
    compliance_score = _compute_compliance_score(summary, counts)

    output: dict[str, Any] = {
        "schema": SCHEMA_KERNEL if mode == "self-improving" else SCHEMA,
        "decision": decision,
        "risk": risk,
        "compliance_score": compliance_score,
        "required_checks": required_checks,
        "allowed_next_actions": _allowed_next_actions(decision),
        "prohibited_next_actions": _prohibited_next_actions(decision),
        "reason": reason,
        "pr_comment": _pr_comment(summary, decision, risk, reason, required_checks),
        "evidence_checklist": _evidence_checklist(
            summary, decision, catalog, tool_name=tool_name
        ),
        "auditor_summary": _auditor_summary(
            summary, decision, risk, counts, tool_name=tool_name
        ),
        "risk_counts": counts,
        "mode": mode,
    }

    # Stage 2-4: Self-improving evolution loop
    if mode == "self-improving" and evolution_engine is not None:
        plan_hash = _compute_plan_hash(summary)
        resource_changes = [
            {
                "address": c.address,
                "resource_type": c.resource_type,
                "actions": list(c.actions),
                "risk": c.risk,
                "explanation": c.explanation,
            }
            for c in summary.resource_changes
        ]

        evolution_result = evolution_engine.run_full_evolution_loop(
            plan_hash=plan_hash,
            decision=decision,
            compliance_score=compliance_score,
            mode=mode,
            plan_summary={
                "path": str(summary.path),
                "terraform_version": summary.terraform_version,
                "change_count": len(summary.resource_changes),
            },
            resource_changes=resource_changes,
        )

        output["evolution"] = {
            "run_id": evolution_result["run_id"],
            "patterns_detected": evolution_result["patterns_detected"],
            "patterns": evolution_result["patterns"],
            "suggested_rules": evolution_result["suggested_rules"],
        }

        if evolution_result["suggested_rules"]:
            output["evolution"]["kernel_instruction"] = _kernel_instruction(
                evolution_result
            )
            output["evolution"]["handoff_protocol"] = _handoff_protocol(
                evolution_result
            )

    return output


def _compute_compliance_score(
    summary: PlanSummary,
    counts: dict[str, int],
) -> float:
    """Compute a compliance score (0-100) based on resource risk profile.

    Starts at 100 and deducts points for each risky resource:
    - -5 per review-tier resource
    - -15 per dangerous-tier resource
    - -30 per irreversible-tier resource
    """
    score = 100.0
    score -= counts.get("review", 0) * 5
    score -= counts.get("dangerous", 0) * 15
    score -= counts.get("irreversible", 0) * 30
    return max(0.0, min(100.0, score))


def _compute_plan_hash(summary: PlanSummary) -> str:
    """Compute the ADR 0014 content identity for a plan summary."""
    import hashlib
    import json

    changes = [
        {
            "address": change.address,
            "type": change.resource_type,
            "actions": list(change.actions),
        }
        for change in sorted(
            summary.resource_changes,
            key=lambda change: (
                change.address,
                change.resource_type,
                change.actions,
            ),
        )
    ]
    payload = {
        "schema": "rtp-plan-hash-v2",
        "terraform_version": summary.terraform_version,
        "changes": changes,
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _kernel_instruction(evolution_result: dict) -> str:
    """Generate a concise instruction for downstream agents."""
    rules = evolution_result.get("suggested_rules", [])
    if not rules:
        return "No rule suggestions. Gate decision stands."

    parts = []
    for r in rules:
        parts.append(f"{r['status']}: {r['pattern_hash']} (score {r['score']:.0f})")
    return "Suggested rules: " + "; ".join(parts)


def _handoff_protocol(evolution_result: dict) -> list[dict]:
    """Generate structured handoff protocol for multi-agent systems."""
    rules = evolution_result.get("suggested_rules", [])
    steps = []
    for r in rules:
        if r["status"] == "auto-merge":
            steps.append({
                "action": "merge", "rule": r["pattern_hash"],
                "reason": "high confidence",
            })
        elif r["status"] == "pr-ready":
            steps.append({
                "action": "create_pr", "rule": r["pattern_hash"],
                "reason": "medium confidence",
            })
        else:
            steps.append({
                "action": "review", "rule": r["pattern_hash"],
                "reason": "low confidence",
            })
    return steps


def _max_risk(summary: PlanSummary) -> str:
    if not summary.resource_changes:
        return "safe"
    return max(
        (change.risk for change in summary.resource_changes),
        key=lambda risk: RISK_ORDER.get(risk, RISK_ORDER["review"]),
    )


def _decision_for_risk(risk: str) -> str:
    if risk in {"dangerous", "irreversible"}:
        return "block"
    if risk == "review" or risk not in RISK_ORDER:
        return "warn"
    return "proceed"


def _required_checks(
    summary: PlanSummary,
    catalog: ControlCatalog | None,
    decision: str,
) -> list[str]:
    checks: list[str] = []
    if decision == "block":
        checks.extend(
            [
                _CHECK_HUMAN_APPROVAL,
                _CHECK_SECURITY_REVIEW,
                _CHECK_CHANGE_RECORD,
                _CHECK_EVIDENCE_PACKET,
            ]
        )
        if any(change.risk == "irreversible" for change in summary.resource_changes):
            checks.append(_CHECK_RECOVERY_PLAN)
    elif decision == "warn":
        checks.extend([_CHECK_PEER_REVIEW, _CHECK_CHANGE_EVIDENCE])

    checks.extend(_control_check_ids(summary, catalog))
    return _dedupe_sorted(checks)


def _control_check_ids(
    summary: PlanSummary,
    catalog: ControlCatalog | None,
) -> list[str]:
    if catalog is None:
        return []

    checks: list[str] = []
    for change in summary.resource_changes:
        for control in catalog.controls_for(
            resource_type=change.resource_type,
            actions=change.actions,
        ):
            checks.append(f"rtp.control.{catalog.framework}.{control.id}")
    return checks


def _allowed_next_actions(decision: str) -> list[str]:
    if decision == "block":
        return [
            "post_pr_comment",
            "request_human_review",
            "collect_evidence",
            "open_change_record",
        ]
    if decision == "warn":
        return [
            "request_review",
            "post_pr_comment",
            "collect_evidence",
            "open_change_record",
        ]
    return ["continue", "post_summary"]


def _prohibited_next_actions(decision: str) -> list[str]:
    if decision == "block":
        return ["merge", "apply", "auto_approve", "auto_apply"]
    if decision == "warn":
        return ["merge_without_review", "apply_without_review", "auto_approve"]
    return ["auto_apply_without_policy"]


def _reason(
    summary: PlanSummary,
    decision: str,
    risk: str,
    counts: dict[str, int],
    *,
    tool_name: str = "Terraform",
) -> str:
    if not summary.resource_changes:
        return f"No {tool_name} changes were found; the agent may continue."
    if decision == "block":
        flagged = counts["dangerous"] + counts["irreversible"]
        return (
            f"Block because {flagged} {tool_name} change(s) are dangerous or "
            f"irreversible; human approval, change evidence, and security review "
            f"are required before merge or apply."
        )
    if decision == "warn":
        return (
            f"Warn because the highest {tool_name} risk tier is {risk}; reviewer "
            f"approval and change evidence are required before merge or apply."
        )
    return f"Proceed because all {tool_name} changes are safe-tier."


def _pr_comment(
    summary: PlanSummary,
    decision: str,
    risk: str,
    reason: str,
    required_checks: list[str],
) -> str:
    lines = [
        f"**readtheplan agent gate:** {decision.upper()}",
        "",
        reason,
        "",
        f"- Highest risk: `{risk}`",
        f"- Analyzed changes: `{len(summary.resource_changes)}`",
        (
            "- Required checks: "
            f"`{', '.join(required_checks) if required_checks else 'none'}`"
        ),
    ]
    flagged = _flagged_changes(summary)
    if flagged:
        lines.append("- Flagged resources:")
        lines.extend(
            f"  - `{change.address}` `{change.risk}`: {change.explanation}"
            for change in flagged[:5]
        )
        remaining = len(flagged) - 5
        if remaining > 0:
            lines.append(f"  - ...and {remaining} more")
    return "\n".join(lines)


def _evidence_checklist(
    summary: PlanSummary,
    decision: str,
    catalog: ControlCatalog | None,
    *,
    tool_name: str = "Terraform",
) -> list[str]:
    checklist = [
        f"Record the local {tool_name} input path or CI artifact reference.",
        "Attach the readtheplan JSON summary or PR comment to the change record.",
    ]
    if decision in {"warn", "block"}:
        checklist.append("Record reviewer identity, timestamp, and approval decision.")
        checklist.append("Document mitigation or rollback notes for review-tier changes.")
    if decision == "block":
        checklist.append(
            "Capture explicit human approval before merge, apply, or auto-approval."
        )
        checklist.append(
            "Document recovery, backup, or restore evidence for dangerous or "
            "irreversible changes."
        )
    if catalog is not None:
        checklist.append(
            f"Map touched controls from the {catalog.framework} catalog into "
            "the evidence package."
        )
    return checklist


def _auditor_summary(
    summary: PlanSummary,
    decision: str,
    risk: str,
    counts: dict[str, int],
    *,
    tool_name: str = "Terraform",
) -> str:
    return (
        f"readtheplan evaluated {len(summary.resource_changes)} {tool_name} change(s). "
        f"The agent gate decision is {decision} with maximum risk {risk}. "
        f"Risk counts: safe={counts['safe']}, review={counts['review']}, "
        f"dangerous={counts['dangerous']}, irreversible={counts['irreversible']}."
    )


def _risk_counts(counts: Counter[str]) -> dict[str, int]:
    out = {tier: int(counts.get(tier, 0)) for tier in _RISK_TIERS}
    for risk in sorted(set(counts) - set(_RISK_TIERS)):
        out[risk] = int(counts[risk])
    return out


def _flagged_changes(summary: PlanSummary) -> list[ResourceChange]:
    return [
        change
        for change in summary.resource_changes
        if change.risk in {"review", "dangerous", "irreversible"}
    ]


def _dedupe_sorted(values: list[str]) -> list[str]:
    return sorted(set(values))
