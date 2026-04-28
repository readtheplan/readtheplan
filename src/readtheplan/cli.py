from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence, TextIO

from readtheplan.plan import PlanError, PlanSummary, analyze_plan_file


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
        choices=("text", "json"),
        default="text",
        help="Output format. Defaults to text.",
    )
    analyze.add_argument("plan_file", help="Path to Terraform plan JSON.")
    analyze.set_defaults(func=_analyze)

    return parser


def _analyze(args: argparse.Namespace) -> int:
    try:
        summary = analyze_plan_file(args.plan_file)
    except PlanError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        json.dump(summary.to_dict(), sys.stdout, indent=2)
        print()
    else:
        _print_summary(summary, sys.stdout)
    return 0


def _print_summary(summary: PlanSummary, stream: TextIO) -> None:
    print(f"# readtheplan summary: {summary.path}", file=stream)
    if summary.terraform_version:
        print(f"Terraform version: {summary.terraform_version}", file=stream)

    print(f"Resource changes: {len(summary.resource_changes)}", file=stream)
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
    print("| Risk | Actions | Resource | Type |", file=stream)
    print("| --- | --- | --- | --- |", file=stream)
    for change in summary.resource_changes:
        actions = "/".join(change.actions)
        print(
            f"| {change.risk} | {actions} | {change.address} | {change.resource_type} |",
            file=stream,
        )


if __name__ == "__main__":
    raise SystemExit(main())
