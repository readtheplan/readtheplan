from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence, TextIO

from readtheplan.attestation import (
    ATTESTATION_HEADER,
    build_plan_read_attestation,
)
from readtheplan.plan import PlanError, PlanSummary, analyze_plan_file
from readtheplan.rules import load_rule_overrides


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="readtheplan",
        description="Read and summarize Terraform plan JSON.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a Terraform plan JSON file.",
    )
    analyze.add_argument(
        "--format",
        choices=("text", "markdown", "json"),
        default="text",
        help="Output format. 'text' and 'markdown' both emit Markdown. Defaults to text.",
    )
    analyze.add_argument(
        "--no-rules",
        action="store_true",
        help="Disable resource-aware rules and use the action-only classifier.",
    )
    analyze.add_argument(
        "--rules-file",
        help="Optional JSON/YAML organization rule override file.",
    )
    analyze.add_argument("plan_file", help="Path to Terraform plan JSON.")
    analyze.set_defaults(func=_analyze)

    attest = subparsers.add_parser(
        "attest",
        help="Emit an AI-agent plan-read attestation header for a Terraform plan JSON file.",
    )
    attest.add_argument("--agent-id", required=True, help="Compact agent identifier.")
    attest.add_argument("--run-id", help="Optional local or CI run identifier.")
    attest.add_argument("plan_file", help="Path to Terraform plan JSON.")
    attest.set_defaults(func=_attest)

    return parser


def _analyze(args: argparse.Namespace) -> int:
    try:
        overrides = load_rule_overrides(args.rules_file) if args.rules_file else ()
        summary = analyze_plan_file(
            args.plan_file,
            use_rules=not args.no_rules,
            rule_overrides=overrides,
        )
    except (PlanError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        json.dump(summary.to_dict(), sys.stdout, indent=2)
        print()
    else:
        _print_summary(summary, sys.stdout)
    return 0


def _attest(args: argparse.Namespace) -> int:
    try:
        analyze_plan_file(args.plan_file)
        plan_json = Path(args.plan_file).read_bytes()
        attestation = build_plan_read_attestation(
            agent_id=args.agent_id,
            plan_json=plan_json,
            run_id=args.run_id,
        )
    except (OSError, PlanError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"{ATTESTATION_HEADER}: {attestation.to_header_value()}")
    return 0


def _print_summary(summary: PlanSummary, stream: TextIO) -> None:
    print(f"# readtheplan summary: {summary.path}", file=stream)
    if summary.terraform_version:
        print(f"Terraform version: {summary.terraform_version}", file=stream)

    print(f"Resource changes: {len(summary.resource_changes)}", file=stream)
    print(f"Plan risk: {summary.risk_level}", file=stream)
    if not summary.resource_changes:
        print("No resource changes found.", file=stream)
        return

    print("", file=stream)
    print("## Actions", file=stream)
    for action, count in sorted(summary.action_counts.items()):
        print(f"- {action}: {count}", file=stream)

    print("", file=stream)
    print("## Risk", file=stream)
    for risk, count in sorted(summary.risk_counts.items()):
        print(f"- {risk}: {count}", file=stream)

    print("", file=stream)
    print("## Changes", file=stream)
    print("| Risk | Rule | Actions | Resource | Type | Explanation |", file=stream)
    print("| --- | --- | --- | --- | --- | --- |", file=stream)
    for change in summary.resource_changes:
        actions = "/".join(change.actions)
        print(
            (
                f"| {change.risk} | {change.rule_id} | {actions} | {change.address} | "
                f"{change.resource_type} | {change.explanation} |"
            ),
            file=stream,
        )


if __name__ == "__main__":
    raise SystemExit(main())
