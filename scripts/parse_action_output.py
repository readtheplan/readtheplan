#!/usr/bin/env python3
"""Parse readtheplan JSON output and emit GitHub Actions workflow commands.

Usage:
    python scripts/parse_action_output.py <output.json> <GITHUB_OUTPUT> <GITHUB_STEP_SUMMARY> <count_file>

Inputs:
    sys.argv[1] — path to readtheplan --format json output
    sys.argv[2] — path to GITHUB_OUTPUT file
    sys.argv[3] — path to GITHUB_STEP_SUMMARY file
    sys.argv[4] — path to write resource_change_count
"""  # noqa: E501
from __future__ import annotations

import json
import sys
from pathlib import Path

MAX_GITHUB_OUTPUT_BYTES = 900 * 1024


def _markdown_cell(value):
    text = str(value).replace("\n", " ").replace("|", "\\|")
    return text if len(text) <= 240 else text[:237] + "..."


def main():
    output_path = Path(sys.argv[1])
    github_output = Path(sys.argv[2])
    step_summary = Path(sys.argv[3])
    count_path = Path(sys.argv[4])

    raw = output_path.read_text(encoding="utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"::error::readtheplan emitted invalid JSON: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if not isinstance(payload, dict):
        print("::error::readtheplan JSON output must be an object", file=sys.stderr)
        raise SystemExit(1)

    is_agent_gate = payload.get("schema") == "rtp-agent-gate-v1"
    if is_agent_gate:
        expected_types = {
            "risk_counts": dict,
            "pr_comment": str,
        }
    else:
        expected_types = {
            "resource_change_count": int,
            "actions": dict,
            "risks": dict,
            "changes": list,
        }

    for key, expected_type in expected_types.items():
        value = payload.get(key)
        if not isinstance(value, expected_type):
            actual = type(value).__name__
            print(
                f"::error::readtheplan JSON field {key!r} must be "
                f"{expected_type.__name__}, got {actual}",
                file=sys.stderr,
            )
            raise SystemExit(1)

    if is_agent_gate:
        resource_change_count = payload.get("total_changes")
        if resource_change_count is None:
            resource_change_count = sum(payload["risk_counts"].values())
        if not isinstance(resource_change_count, int):
            print(
                "::error::readtheplan agent gate total_changes must be an integer",
                file=sys.stderr,
            )
            raise SystemExit(1)
        action_values: dict[str, int] = {}
        risk_values = payload["risk_counts"]
        changes: list[dict[str, object]] = []
        gate_comment = payload["pr_comment"]
    else:
        resource_change_count = payload["resource_change_count"]
        plan_finding_count = payload.get("plan_finding_count", 0)
        plan_findings = payload.get("plan_findings", [])
        if not isinstance(plan_finding_count, int) or not isinstance(plan_findings, list):
            print(
                "::error::readtheplan plan finding fields must be an integer and list",
                file=sys.stderr,
            )
            raise SystemExit(1)
        action_values = payload["actions"]
        risk_values = payload["risks"]
        changes = payload["changes"]
        gate_comment = None

    action_counts = json.dumps(action_values, sort_keys=True, separators=(",", ":"))
    risk_counts = json.dumps(risk_values, sort_keys=True, separators=(",", ":"))
    summary_json = json.dumps(payload, indent=2, sort_keys=True)

    with github_output.open("a", encoding="utf-8") as output:
        if len(summary_json.encode("utf-8")) > MAX_GITHUB_OUTPUT_BYTES:
            size_kib = len(summary_json.encode("utf-8")) // 1024
            print(
                "::warning::readtheplan summary-json is "
                f"{size_kib} KiB, which is too large for safe GitHub output use. "
                "Skipping summary-json; use the step summary or upload the JSON as an artifact.",
            )
            output.write("summary-json=\n")
        else:
            output.write("summary-json<<READTHEPLAN_JSON\n")
            output.write(summary_json)
            output.write("\nREADTHEPLAN_JSON\n")
        output.write(f"resource-change-count={resource_change_count}\n")
        output.write(f"action-counts={action_counts}\n")
        output.write(f"risk-counts={risk_counts}\n")

    with step_summary.open("a", encoding="utf-8") as summary:
        if gate_comment is not None:
            summary.write(gate_comment)
            summary.write("\n")
        else:
            summary.write("## readtheplan\n\n")
            summary.write(f"- Resource changes: {resource_change_count}\n")
            summary.write(f"- Plan-level findings: {plan_finding_count}\n")
            summary.write(f"- Actions: `{action_counts}`\n")
            summary.write(f"- Risks: `{risk_counts}`\n")
        if changes:
            summary.write("\n### Changes\n\n")
            summary.write("| Risk | Actions | Resource | Type | Explanation |\n")
            summary.write("| --- | --- | --- | --- | --- |\n")
            for change in changes[:20]:
                actions = "/".join(str(action) for action in change.get("actions", []))
                summary.write(
                    "| "
                    + " | ".join(
                        [
                            _markdown_cell(change.get("risk", "")),
                            _markdown_cell(actions),
                            _markdown_cell(change.get("address", "")),
                            _markdown_cell(change.get("type", "")),
                            _markdown_cell(change.get("explanation", "")),
                        ]
                    )
                    + " |\n"
                )
            remaining = len(changes) - 20
            if remaining > 0:
                summary.write(f"\n_{remaining} additional changes omitted from summary._\n")
        if gate_comment is None and plan_findings:
            summary.write("\n### Plan-level findings\n\n")
            summary.write("| Risk | Signal | Address | Explanation |\n")
            summary.write("| --- | --- | --- | --- |\n")
            for finding in plan_findings[:20]:
                summary.write(
                    "| "
                    + " | ".join(
                        [
                            _markdown_cell(finding.get("risk", "")),
                            _markdown_cell(finding.get("type", "")),
                            _markdown_cell(finding.get("address", "")),
                            _markdown_cell(finding.get("explanation", "")),
                        ]
                    )
                    + " |\n"
                )
            remaining = len(plan_findings) - 20
            if remaining > 0:
                summary.write(
                    f"\n_{remaining} additional plan-level findings omitted from summary._\n"
                )

    finding_suffix = (
        f" and {plan_finding_count} plan-level findings"
        if not is_agent_gate
        else ""
    )
    print(
        f"::notice::readtheplan analyzed {resource_change_count} resource changes"
        f"{finding_suffix}"
    )
    for risk in ("dangerous", "irreversible"):
        count = int(risk_values.get(risk, 0))
        if count:
            print(f"::warning::readtheplan found {count} {risk} changes")

    count_path.write_text(str(resource_change_count), encoding="utf-8")


if __name__ == "__main__":
    main()
