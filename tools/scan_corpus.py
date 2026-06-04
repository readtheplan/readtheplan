#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from readtheplan.controls import (  # noqa: E402
    CatalogSchemaError,
    ControlCatalog,
    FrameworkNotFoundError,
    load_catalog,
)
from readtheplan.overlays import (  # noqa: E402
    Overlay,
    OverlayError,
    apply_overlay_to_catalog,
    apply_overlay_to_change,
    load_overlay,
)
from readtheplan.plan import PlanError, PlanSummary, analyze_plan_file, load_plan  # noqa: E402
from readtheplan.summary import summary_to_dict  # noqa: E402

SCHEMA_VERSION = "readtheplan-corpus-scan-v0"
FEEDBACK_SCHEMA_VERSION = "readtheplan-feedback-v0"
RISK_ORDER = {"safe": 0, "review": 1, "dangerous": 2, "irreversible": 3}
SENSITIVE_KEYS = {
    "access_key",
    "account_id",
    "authorization",
    "client_secret",
    "private_key",
    "secret_key",
    "password",
    "token",
    "user_data",
}
SENSITIVE_KEY_FRAGMENTS = ("password", "secret", "token", "private_key")
REDACTION_PATTERNS = (
    (re.compile(r"(?<!\d)\d{12}(?!\d)"), "000000000000"),
    (
        re.compile(r"arn:aws[a-zA-Z-]*:[^\s\"']+"),
        "arn:aws:redacted:region:000000000000:resource/redacted",
    ),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "0.0.0.0"),
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.include_raw_plan and args.redact:
        print(
            "Error: --include-raw-plan and --redact are mutually exclusive",
            file=sys.stderr,
        )
        return 1

    try:
        overlays = tuple(load_overlay(path) for path in args.rules_file)
        catalog = _load_catalog(args.framework, overlays)
        plan_paths = resolve_plan_paths(
            [Path(path) for path in args.paths],
            run_terraform=args.run_terraform,
            output_dir=Path(args.output_dir),
            refresh=args.refresh,
            terraform_args=args.terraform_arg,
        )
        if not plan_paths:
            print("Error: no Terraform plan JSON files found", file=sys.stderr)
            return 1
        if args.redact:
            print(
                "Warning: redaction is best-effort; review plan.redacted.json before sharing.",
                file=sys.stderr,
            )

        for plan_path in plan_paths:
            bundle = write_bundle(
                plan_path,
                output_dir=Path(args.output_dir),
                framework=args.framework,
                rules_files=args.rules_file,
                overlays=overlays,
                catalog=catalog,
                include_raw_plan=args.include_raw_plan,
                redact=args.redact,
            )
            print(bundle)
    except (CatalogSchemaError, FrameworkNotFoundError, OverlayError, PlanError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create local readtheplan scan bundles for corpus feedback.",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Terraform plan JSON files or directories to scan.",
    )
    parser.add_argument(
        "--output-dir",
        default="corpus-scans",
        help="Directory for generated scan bundles. Defaults to corpus-scans/.",
    )
    parser.add_argument(
        "--framework",
        help="Optional packaged compliance framework name, such as soc2.",
    )
    parser.add_argument(
        "--rules-file",
        action="append",
        default=[],
        metavar="PATH",
        help="Apply local readtheplan overlay YAML. Repeatable.",
    )
    raw_group = parser.add_mutually_exclusive_group()
    raw_group.add_argument(
        "--no-raw-plan",
        action="store_true",
        help="Do not copy raw Terraform plan JSON into bundles. This is the default.",
    )
    raw_group.add_argument(
        "--include-raw-plan",
        action="store_true",
        help="Copy unmodified plan.json into each bundle. Use only for private output.",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="Write a minimized, redacted plan.redacted.json copy for public-safe review.",
    )
    parser.add_argument(
        "--run-terraform",
        action="store_true",
        help="For Terraform module directories without plan.json files, run terraform init/plan/show locally.",
    )
    parser.add_argument(
        "--refresh",
        choices=("true", "false"),
        help="Pass -refresh=true or -refresh=false to terraform plan when --run-terraform is used.",
    )
    parser.add_argument(
        "--terraform-arg",
        action="append",
        default=[],
        metavar="ARG",
        help="Extra argument passed to terraform plan when --run-terraform is used. Repeatable.",
    )
    return parser


def resolve_plan_paths(
    paths: Sequence[Path],
    *,
    run_terraform: bool = False,
    output_dir: Path | None = None,
    refresh: str | None = None,
    terraform_args: Sequence[str] = (),
) -> list[Path]:
    plan_paths: list[Path] = []
    for path in paths:
        if path.is_file():
            if path.suffix == ".json":
                plan_paths.append(path)
            continue

        if not path.is_dir():
            raise PlanError(f"scan path does not exist: {path}")

        discovered = find_plan_files(path)
        if discovered:
            plan_paths.extend(discovered)
            continue

        if run_terraform:
            if output_dir is None:
                raise PlanError("--run-terraform requires an output directory")
            plan_paths.append(
                run_terraform_plan(
                    path,
                    output_dir=output_dir / "_terraform-plans" / _slug(path),
                    refresh=refresh,
                    terraform_args=terraform_args,
                )
            )

    return sorted(dict.fromkeys(plan_paths))


def find_plan_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix == ".json" else []
    return sorted(
        (item for item in path.rglob("plan.json") if item.is_file()),
        key=lambda item: (len(item.relative_to(path).parts), str(item)),
    )


def run_terraform_plan(
    module_dir: Path,
    *,
    output_dir: Path,
    refresh: str | None = None,
    terraform_args: Sequence[str] = (),
) -> Path:
    terraform = shutil.which("terraform")
    if terraform is None:
        raise PlanError("terraform is required for --run-terraform but was not found")

    output_dir.mkdir(parents=True, exist_ok=True)
    binary_plan = output_dir / "tfplan"
    json_plan = output_dir / "plan.json"

    subprocess.run([terraform, "init", "-input=false"], cwd=module_dir, check=True)
    plan_command = [terraform, "plan", "-input=false", f"-out={binary_plan}"]
    if refresh is not None:
        plan_command.append(f"-refresh={refresh}")
    plan_command.extend(terraform_args)
    subprocess.run(plan_command, cwd=module_dir, check=True)
    with json_plan.open("w", encoding="utf-8") as stream:
        subprocess.run(
            [terraform, "show", "-json", str(binary_plan)],
            cwd=module_dir,
            check=True,
            stdout=stream,
        )
    return json_plan


def write_bundle(
    plan_path: Path,
    *,
    output_dir: Path,
    framework: str | None = None,
    rules_files: Sequence[str] = (),
    overlays: Sequence[Overlay] = (),
    catalog: ControlCatalog | None = None,
    include_raw_plan: bool = False,
    redact: bool = False,
) -> Path:
    plan_bytes = plan_path.read_bytes()
    plan_sha = _sha256(plan_bytes)
    scan_id = f"{_slug(plan_path.parent)}-{plan_sha[:12]}"
    bundle_dir = output_dir / scan_id
    bundle_dir.mkdir(parents=True, exist_ok=True)

    summary = analyze_plan_file(plan_path)
    if overlays:
        summary = _apply_overlays_to_summary(
            summary,
            overlays,
            plan_account_id=_plan_account_id(plan_path),
        )
    payload = summary_to_dict(summary, catalog)

    (bundle_dir / "readtheplan.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )
    (bundle_dir / "readtheplan.md").write_text(
        render_markdown(summary, catalog=catalog),
        encoding="utf-8",
    )

    raw_plan_included = False
    redacted_plan_included = False
    if include_raw_plan:
        shutil.copyfile(plan_path, bundle_dir / "plan.json")
        raw_plan_included = True
    elif redact:
        redacted = minimize_and_redact_plan(load_plan(plan_path))
        (bundle_dir / "plan.redacted.json").write_text(
            json.dumps(redacted, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        redacted_plan_included = True

    readtheplan_risk = _overall_risk(summary)
    (bundle_dir / "metadata.json").write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "scan_id": scan_id,
                "generated_at": _utc_now(),
                "source_path": plan_path.name,
                "source_path_redacted": True,
                "source_kind": "terraform_plan_json",
                "readtheplan_version": _readtheplan_version(),
                "framework": framework,
                "rules_files": [str(path) for path in rules_files],
                "plan_sha256": f"sha256:{plan_sha}",
                "terraform_version": summary.terraform_version,
                "resource_change_count": len(summary.resource_changes),
                "action_counts": dict(sorted(summary.action_counts.items())),
                "risk_counts": dict(sorted(summary.risk_counts.items())),
                "readtheplan_overall_risk": readtheplan_risk,
                "raw_plan_included": raw_plan_included,
                "redacted_plan_included": redacted_plan_included,
                "security_boundary": (
                    "Raw Terraform plan JSON is local/private by default. "
                    "Do not publish unredacted plan.json bundles."
                ),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (bundle_dir / "feedback.yaml").write_text(
        render_feedback_template(
            scan_id=scan_id,
            readtheplan_overall_risk=readtheplan_risk,
            summary=summary,
        ),
        encoding="utf-8",
    )
    return bundle_dir


def render_markdown(
    summary: PlanSummary,
    *,
    catalog: ControlCatalog | None = None,
) -> str:
    lines = [f"# readtheplan summary: {summary.path}"]
    if summary.terraform_version:
        lines.append(f"Terraform version: {summary.terraform_version}")
    lines.append(f"Resource changes: {len(summary.resource_changes)}")
    if not summary.resource_changes:
        lines.append("No resource changes found.")
        return "\n".join(lines) + "\n"

    lines.extend(["", "## Actions"])
    for action, count in sorted(summary.action_counts.items()):
        lines.append(f"- {action}: {count}")

    lines.extend(["", "## Risk"])
    for risk, count in sorted(summary.risk_counts.items()):
        lines.append(f"- {risk}: {count}")

    lines.extend(["", "## Changes"])
    if catalog is None:
        lines.extend(
            [
                "| Risk | Actions | Resource | Type | Explanation |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
    else:
        lines.extend(
            [
                "| Risk | Actions | Resource | Type | Explanation | Controls |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )

    for change in summary.resource_changes:
        row = (
            f"| {change.risk} | {'/'.join(change.actions)} | {change.address} | "
            f"{change.resource_type} | {change.explanation}"
        )
        if catalog is not None:
            controls = catalog.controls_for(
                resource_type=change.resource_type,
                actions=change.actions,
            )
            row = f"{row} | {', '.join(control.id for control in controls)}"
        lines.append(f"{row} |")
    return "\n".join(lines) + "\n"


def render_feedback_template(
    *,
    scan_id: str,
    readtheplan_overall_risk: str,
    summary: PlanSummary,
) -> str:
    lines = [
        f"schema_version: {FEEDBACK_SCHEMA_VERSION}",
        f"scan_id: {scan_id}",
        "reviewer:",
        "  id: \"\"",
        "  role: \"\"",
        "reviewed_at: \"\"",
        "overall_human_risk: \"\" # one of: safe, review, dangerous, irreversible",
        f"readtheplan_overall_risk: {readtheplan_overall_risk}",
        "notes: \"\"",
        "resource_feedback:",
    ]
    if not summary.resource_changes:
        lines.append("  []")
        return "\n".join(lines) + "\n"

    for change in summary.resource_changes:
        lines.extend(
            [
                f"  - address: {_yaml_quote(change.address)}",
                f"    resource_type: {_yaml_quote(change.resource_type)}",
                f"    readtheplan_risk: {change.risk}",
                "    human_risk: \"\" # one of: safe, review, dangerous, irreversible",
                (
                    "    issue_type: \"\" # one of: correct, underclassified, "
                    "overclassified, missed_resource, bad_explanation, "
                    "missing_compliance_mapping, false_positive, parser_bug, "
                    "output_usability"
                ),
                "    expected_reason: \"\"",
                "    suggested_rule: \"\"",
            ]
        )
    return "\n".join(lines) + "\n"


def minimize_and_redact_plan(plan: dict[str, Any]) -> dict[str, Any]:
    minimized: dict[str, Any] = {}
    if "terraform_version" in plan:
        minimized["terraform_version"] = _redact(plan["terraform_version"])

    resource_changes = plan.get("resource_changes")
    if isinstance(resource_changes, list):
        minimized["resource_changes"] = [
            _minimize_resource_change(item)
            for item in resource_changes
            if isinstance(item, dict)
        ]
    else:
        minimized["resource_changes"] = []
    return minimized


def _minimize_resource_change(item: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("address", "mode", "type", "name", "provider_name"):
        if key in item:
            out[key] = _redact(item[key])

    change = item.get("change")
    if isinstance(change, dict):
        out["change"] = {}
        actions = change.get("actions")
        out["change"]["actions"] = actions if isinstance(actions, list) else ["unknown"]
        sensitive_masks = {
            "before": change.get("before_sensitive"),
            "after": change.get("after_sensitive"),
        }
        for key in ("before", "after"):
            if key in change:
                out["change"][key] = _redact_with_sensitive_mask(
                    change[key],
                    sensitive_masks.get(key),
                )
        for key in ("after_unknown", "replace_paths"):
            if key in change:
                out["change"][key] = _redact(change[key])
    return out


def _redact_with_sensitive_mask(value: Any, mask: Any) -> Any:
    if mask is True:
        return "<redacted>"
    if isinstance(value, dict):
        mask_dict = mask if isinstance(mask, dict) else {}
        redacted: dict[str, Any] = {}
        for key, raw in value.items():
            key_text = str(key)
            redacted[key_text] = _redact_with_sensitive_mask(
                raw,
                mask_dict.get(key_text, mask_dict.get(key)),
            )
        return _redact(redacted)
    if isinstance(value, list):
        mask_list = mask if isinstance(mask, list) else []
        return [
            _redact_with_sensitive_mask(
                item,
                mask_list[idx] if idx < len(mask_list) else None,
            )
            for idx, item in enumerate(value)
        ]
    return _redact(value)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, raw in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if lowered in SENSITIVE_KEYS or any(
                fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS
            ):
                redacted[key_text] = "<redacted>"
            else:
                redacted[key_text] = _redact(raw)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        out = value
        for pattern, replacement in REDACTION_PATTERNS:
            out = pattern.sub(replacement, out)
        return out
    return copy.deepcopy(value)


def _load_catalog(
    framework: str | None,
    overlays: Sequence[Overlay],
) -> ControlCatalog | None:
    if framework is None:
        return None

    catalog = load_catalog(framework)
    for overlay in overlays:
        catalog = apply_overlay_to_catalog(catalog, overlay)
    return catalog


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


def _plan_account_id(plan_file: Path) -> str | None:
    data = load_plan(plan_file)
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


def _overall_risk(summary: PlanSummary) -> str:
    if not summary.resource_changes:
        return "safe"
    return max(
        (change.risk for change in summary.resource_changes),
        key=lambda risk: RISK_ORDER.get(risk, 1),
    )


def _slug(path: Path) -> str:
    value = path.name or "scan"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
    return slug or "scan"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _readtheplan_version() -> str:
    try:
        return version("readtheplan")
    except PackageNotFoundError:
        return "unknown"


def _yaml_quote(value: str) -> str:
    return json.dumps(value)


if __name__ == "__main__":
    raise SystemExit(main())
