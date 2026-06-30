#!/usr/bin/env python3
"""Run the readtheplan demo scenarios and print a formatted report."""
import json
import sys
from pathlib import Path

from readtheplan.plan import analyze_plan_file

SCENARIOS = [
    ("01-safe-add-s3-bucket.json", "safe", "Adding a new S3 bucket"),
    ("02-review-update-s3-tags.json", "review", "Updating S3 bucket tags in-place"),
    ("03-dangerous-replace-ec2.json", "dangerous", "Replacing EC2 instance (user_data change)"),
    ("04-irreversible-delete-rds.json", "irreversible", "Deleting a production RDS database"),
]

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"


def risk_icon(risk: str) -> str:
    return {"safe": "🟢", "review": "🟡", "dangerous": "🟠", "irreversible": "🔴"}.get(risk, "⚪")


def gate_label(risk: str) -> str:
    return {"safe": "PROCEED", "review": "WARN", "dangerous": "WARN", "irreversible": "BLOCK"}.get(risk, "UNKNOWN")  # noqa: E501


def main() -> int:
    print("=" * 72)
    print("  READTHEPLAN DEMO — Terraform Plan Risk Analysis")
    print("=" * 72)

    all_pass = True
    results = []

    for filename, expected_risk, description in SCENARIOS:
        path = SCENARIO_DIR / filename
        summary = analyze_plan_file(str(path))

        for rc in summary.resource_changes:
            passed = rc.risk == expected_risk
            if not passed:
                all_pass = False

            results.append({
                "file": filename,
                "description": description,
                "resource": rc.address,
                "type": rc.resource_type,
                "actions": rc.actions,
                "risk": rc.risk,
                "expected": expected_risk,
                "passed": passed,
                "explanation": rc.explanation,
            })

    # Print per-scenario
    for r in results:
        icon = risk_icon(r["risk"])
        gate = gate_label(r["risk"])
        status = "✓" if r["passed"] else "✗"
        print(f"\n  {status} {r['file']}")
        print(f"     {r['description']}")
        print(f"     Resource:    {r['resource']} ({r['type']})")
        print(f"     Actions:     {', '.join(r['actions'])}")
        print(f"     Risk:        {icon} {r['risk'].upper()} → gate: {gate}")
        print(f"     Explanation: {r['explanation']}")

    # Summary
    print(f"\n{'=' * 72}")
    risk_counts = {}
    for r in results:
        risk_counts[r["risk"]] = risk_counts.get(r["risk"], 0) + 1
    for risk in ("safe", "review", "dangerous", "irreversible"):
        count = risk_counts.get(risk, 0)
        if count:
            print(f"  {risk_icon(risk)} {risk.upper():12} {count} scenario(s)")

    print(f"\n  Verdict: {'ALL SCENARIOS PASS ✓' if all_pass else 'MISMATCHES FOUND ✗'}")
    print(f"{'=' * 72}")

    # JSON output for programmatic use
    json_path = SCENARIO_DIR.parent / "demo-results.json"
    json_path.write_text(json.dumps(results, indent=2) + "\n")
    print(f"\n  Results written to: {json_path}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
