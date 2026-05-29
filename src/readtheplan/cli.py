from __future__ import annotations

import argparse
import json
import sys
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Callable, Sequence, TextIO, cast

from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.controls import (
    CatalogSchemaError,
    ControlCatalog,
    FrameworkNotFoundError,
    available_frameworks,
    load_catalog,
)
from readtheplan.evidence import EvidenceError, Reviewer, build_evidence
from readtheplan.overlays import (
    Overlay,
    OverlayError,
    apply_overlay_to_catalog,
    apply_overlay_to_change,
    load_overlay,
)
from readtheplan.plan import PlanError, PlanSummary, analyze_plan_file, load_plan
from readtheplan.signing import (
    SigningError,
    VerificationError,
    sign_envelope,
    verify_envelope,
)
from readtheplan.summary import summary_to_dict


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    func = cast("Callable[[argparse.Namespace], int]", args.func)
    return func(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="readtheplan",
        description="Read and summarize Terraform plan JSON.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_package_version()}",
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
    analyze.add_argument(
        "--no-rules",
        action="store_true",
        help="Disable resource-aware rules and use the action-only classifier.",
    )
    analyze.add_argument(
        "--rules-file",
        action="append",
        default=[],
        metavar="PATH",
        help="Apply overlay YAML on top of built-in rules. Repeatable.",
    )
    analyze.add_argument(
        "--framework",
        help=(
            "Annotate each change with control IDs from the named framework "
            f"catalog. Currently available: {_framework_help_list()}."
        ),
    )
    analyze.add_argument(
        "--evidence",
        metavar="PATH",
        help="Write rtp-evidence-v1 JSON envelope to PATH. Use - for stdout.",
    )
    analyze.add_argument(
        "--agent-id",
        default=_default_agent_id(),
        help="Agent ID for evidence attestation.",
    )
    analyze.add_argument(
        "--reviewer-id",
        help="Optional reviewer identifier for evidence output.",
    )
    analyze.add_argument(
        "--reviewer-kind",
        choices=("human", "agent"),
        default="human",
        help="Reviewer kind for evidence output. Defaults to human.",
    )
    analyze.add_argument(
        "--run-id",
        help="Optional CI run identifier for evidence attestation.",
    )
    analyze.add_argument(
        "--sign",
        action="store_true",
        help="Sign the evidence envelope using sigstore keyless signing.",
    )
    analyze.add_argument(
        "--oidc-issuer",
        help="OIDC issuer for sigstore signing. Defaults to sigstore public.",
    )
    analyze.add_argument(
        "--rekor-url",
        help="Rekor transparency log URL. Defaults to sigstore public.",
    )
    analyze.add_argument("plan_file", help="Path to Terraform plan JSON.")
    analyze.set_defaults(func=_analyze)

    agent_gate = subparsers.add_parser(
        "agent-gate",
        help="Emit the local coding-agent gate decision for a Terraform plan JSON file.",
    )
    agent_gate.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    agent_gate.add_argument("plan_file", help="Path to Terraform plan JSON.")
    agent_gate.set_defaults(func=_agent_gate)

    cloudformation = subparsers.add_parser(
        "cloudformation",
        help="Emit the agent-gate decision for a CloudFormation Change Set or template diff.",
    )
    cloudformation.add_argument(
        "--framework",
        help=(
            "Include required check IDs from the named framework catalog. "
            f"Currently available: {_framework_help_list()}."
        ),
    )
    cloudformation.add_argument(
        "input_file", help="Path to CloudFormation Change Set JSON or template diff."
    )
    cloudformation.set_defaults(func=_cloudformation_gate)

    verify = subparsers.add_parser(
        "verify",
        help="Verify a signed rtp-evidence-v1 envelope.",
    )
    verify.add_argument(
        "--rekor-url",
        help="Rekor transparency log URL. Defaults to sigstore public.",
    )
    verify.add_argument(
        "--certificate-identity",
        help="Expected certificate identity (e.g., https://github.com/readtheplan/readtheplan/.github/workflows/release.yml@refs/tags/v0.3.0). When set, verification fails if the signer does not match.",
    )
    verify.add_argument(
        "--certificate-oidc-issuer",
        help="Expected OIDC issuer (e.g., https://token.actions.githubusercontent.com). Required when --certificate-identity is set.",
    )
    verify.add_argument("envelope", help="Path to evidence envelope JSON.")
    verify.set_defaults(func=_verify)

    mcp = subparsers.add_parser(
        "mcp",
        help="Start the experimental local MCP stdio server.",
    )
    mcp.set_defaults(func=_mcp)

    return parser


def _framework_help_list() -> str:
    frameworks = available_frameworks()
    if not frameworks:
        return "none packaged"
    return ", ".join(frameworks)


def _default_agent_id() -> str:
    try:
        package_version = version("readtheplan")
    except PackageNotFoundError:
        package_version = "unknown"
    return f"readtheplan@{package_version}"


def _package_version() -> str:
    try:
        pkg_version = version("readtheplan")
    except PackageNotFoundError:
        pkg_version = "unknown"

    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short=7", "HEAD"],
            capture_output=True, text=True, timeout=5,
            cwd=Path(__file__).resolve().parent.parent,
        )
        if commit.returncode == 0 and commit.stdout.strip():
            return f"{pkg_version} (git:{commit.stdout.strip()})"
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return pkg_version


def _analyze(args: argparse.Namespace) -> int:
    if args.sign and not args.evidence:
        print("Error: --sign requires --evidence", file=sys.stderr)
        return 1
    if args.evidence and not args.framework:
        print("Error: --evidence requires --framework", file=sys.stderr)
        return 1

    try:
        overlay_items = tuple(load_overlay(path) for path in args.rules_file)
    except OverlayError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    catalog: ControlCatalog | None = None
    if args.framework:
        try:
            catalog = load_catalog(args.framework)
            for overlay in overlay_items:
                catalog = apply_overlay_to_catalog(catalog, overlay)
        except (CatalogSchemaError, FrameworkNotFoundError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    try:
        plan_data = load_plan(args.plan_file)
        summary = analyze_plan_file(plan_data, use_rules=not args.no_rules, _original_path=Path(args.plan_file))
        if overlay_items:
            summary = _apply_overlays_to_summary(
                summary,
                overlay_items,
                plan_account_id=_plan_account_id(args.plan_file, plan_data=plan_data),
            )
    except PlanError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.evidence:
        assert catalog is not None
        try:
            evidence = build_evidence(
                plan_summary=summary,
                plan_json=json.dumps(plan_data).encode(),
                catalog=catalog,
                agent_id=args.agent_id,
                reviewer=(
                    Reviewer(id=args.reviewer_id, kind=args.reviewer_kind)
                    if args.reviewer_id
                    else None
                ),
                run_id=args.run_id,
            )
            evidence_payload = (
                sign_envelope(
                    evidence,
                    oidc_issuer=args.oidc_issuer,
                    rekor_url=args.rekor_url,
                )
                if args.sign
                else evidence.to_dict()
            )
        except SigningError as exc:
            print(f"Error: sign failed: {exc}", file=sys.stderr)
            return 1
        except (EvidenceError, OSError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        if args.evidence == "-":
            json.dump(evidence_payload, sys.stdout, indent=2)
            print()
            return 0

        try:
            Path(args.evidence).write_text(
                json.dumps(evidence_payload, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            print(
                f"Error: cannot write evidence file {args.evidence}: {exc}",
                file=sys.stderr,
            )
            return 1

    if args.format == "json":
        json.dump(_summary_to_dict(summary, catalog), sys.stdout, indent=2)
        print()
    else:
        _print_summary(summary, sys.stdout, catalog=catalog)
    return 0


def _agent_gate(args: argparse.Namespace) -> int:
    catalog: ControlCatalog | None = None
    if args.framework:
        try:
            catalog = load_catalog(args.framework)
        except (CatalogSchemaError, FrameworkNotFoundError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    try:
        summary = analyze_plan_file(args.plan_file, use_rules=True)
    except PlanError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    json.dump(agent_gate_to_dict(summary, catalog), sys.stdout, indent=2)
    print()
    return 0


def _cloudformation_gate(args: argparse.Namespace) -> int:
    """Emit the agent-gate contract for a CloudFormation Change Set / template diff."""
    from readtheplan.adapters import detect_adapter
    from readtheplan.adapters.cloudformation import analyze_cloudformation

    try:
        data = json.loads(Path(args.input_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error: cannot read {args.input_file}: {exc}", file=sys.stderr)
        return 1

    if not isinstance(data, dict):
        print("Error: input must be a JSON object", file=sys.stderr)
        return 1

    adapter = detect_adapter(data)
    if adapter is None or adapter.adapter_name != "cloudformation":
        print(f"Error: input not recognized as a supported IaC format (detected: {adapter.adapter_name if adapter else 'none'})", file=sys.stderr)
        return 1

    catalog: ControlCatalog | None = None
    if args.framework:
        try:
            catalog = load_catalog(args.framework)
        except (CatalogSchemaError, FrameworkNotFoundError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    gate = analyze_cloudformation(data, catalog=catalog)
    json.dump(gate, sys.stdout, indent=2)
    print()
    return 0


def _verify(args: argparse.Namespace) -> int:
    try:
        envelope_bytes = Path(args.envelope).read_bytes()
    except OSError as exc:
        print(
            f"Error: cannot read envelope file {args.envelope}: {exc}", file=sys.stderr
        )
        return 1

    try:
        result = verify_envelope(envelope_bytes, rekor_url=args.rekor_url)
    except VerificationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if result.ok:
        print(
            "OK "
            f"identity={result.identity} "
            f"issuer={result.oidc_issuer} "
            f"rekor_uuid={result.rekor_uuid}"
        )
        return 0

    print(f"FAIL {result.reason}", file=sys.stderr)
    return 1


def _mcp(args: argparse.Namespace) -> int:
    try:
        from readtheplan.mcp_server import MissingMCPDependencyError, main as mcp_main

        mcp_main()
    except MissingMCPDependencyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


def _apply_overlays_to_summary(
    summary: PlanSummary,
    overlays: Sequence[Overlay],
    *,
    plan_account_id: str | None,
) -> PlanSummary:
    changes = []
    for change in summary.resource_changes:
        out = change
        for overlay in overlays:
            out = apply_overlay_to_change(
                out,
                overlay,
                plan_account_id=plan_account_id,
            )
        changes.append(out)

    return PlanSummary(
        path=summary.path,
        terraform_version=summary.terraform_version,
        resource_changes=tuple(changes),
    )


def _plan_account_id(plan_file: str | Path, plan_data: dict | None = None) -> str | None:
    data = plan_data if plan_data is not None else load_plan(plan_file)
    for key in ("account_id", "aws_account_id"):
        value = data.get(key)
        if value is not None:
            return str(value)

    variables = data.get("variables")
    if isinstance(variables, dict):
        for key in ("account_id", "aws_account_id"):
            raw = variables.get(key)
            if isinstance(raw, dict) and raw.get("value") is not None:
                return str(raw["value"])
    return None


def _summary_to_dict(
    summary: PlanSummary,
    catalog: ControlCatalog | None,
) -> dict[str, object]:
    return summary_to_dict(summary, catalog)


def _print_summary(
    summary: PlanSummary,
    stream: TextIO,
    *,
    catalog: ControlCatalog | None = None,
) -> None:
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
    if catalog is None:
        print("| Risk | Actions | Resource | Type | Explanation |", file=stream)
        print("| --- | --- | --- | --- | --- |", file=stream)
    else:
        print(
            "| Risk | Actions | Resource | Type | Explanation | Controls |", file=stream
        )
        print("| --- | --- | --- | --- | --- | --- |", file=stream)
    for change in summary.resource_changes:
        actions = "/".join(change.actions)
        row = (
            f"| {change.risk} | {actions} | {change.address} | "
            f"{change.resource_type} | {change.explanation}"
        )
        if catalog is not None:
            controls = catalog.controls_for(
                resource_type=change.resource_type,
                actions=change.actions,
            )
            row = f"{row} | {', '.join(control.id for control in controls)}"
        print(f"{row} |", file=stream)


if __name__ == "__main__":
    raise SystemExit(main())
