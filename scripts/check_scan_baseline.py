#!/usr/bin/env python3
"""Fail when a readtheplan project scan regresses beyond a reviewed baseline."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

RISKS = ("safe", "review", "dangerous", "irreversible")


def _load_object(raw: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def evaluate(baseline: dict[str, Any], result: dict[str, Any]) -> list[str]:
    if baseline.get("schema") != "readtheplan-scan-baseline-v1":
        raise ValueError("baseline schema must be readtheplan-scan-baseline-v1")
    if result.get("adapter") != "project-scan":
        raise ValueError("scan result adapter must be project-scan")

    limits = baseline.get("maximum_risk_counts")
    actual_counts = result.get("risk_counts")
    if not isinstance(limits, dict) or not isinstance(actual_counts, dict):
        raise ValueError("baseline and result must contain risk-count objects")

    regressions: list[str] = []
    for risk in RISKS:
        maximum = _nonnegative_int(limits.get(risk), f"maximum_risk_counts.{risk}")
        actual = _nonnegative_int(actual_counts.get(risk), f"risk_counts.{risk}")
        if actual > maximum:
            regressions.append(f"{risk} findings increased: {actual} > {maximum}")

    maximum_errors = _nonnegative_int(baseline.get("maximum_errors"), "maximum_errors")
    actual_errors = _nonnegative_int(result.get("error_count"), "error_count")
    if actual_errors > maximum_errors:
        regressions.append(f"scan errors increased: {actual_errors} > {maximum_errors}")

    minimum_files = _nonnegative_int(
        baseline.get("minimum_scanned_files"), "minimum_scanned_files"
    )
    scanned_files = _nonnegative_int(result.get("scanned_file_count"), "scanned_file_count")
    if scanned_files < minimum_files:
        regressions.append(f"scan coverage decreased: {scanned_files} < {minimum_files} files")

    return regressions


def _append_step_summary(baseline: dict[str, Any], result: dict[str, Any]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    limits = baseline["maximum_risk_counts"]
    actual = result["risk_counts"]
    with Path(path).open("a", encoding="utf-8") as summary:
        summary.write("\n## Dogfood baseline comparison\n\n")
        summary.write("| Signal | Actual | Maximum |\n|---|---:|---:|\n")
        for risk in RISKS:
            summary.write(f"| {risk} | {actual[risk]} | {limits[risk]} |\n")
        summary.write(
            f"| scan errors | {result['error_count']} | {baseline['maximum_errors']} |\n"
        )
        summary.write(
            "| scanned files | "
            f"{result['scanned_file_count']} | minimum {baseline['minimum_scanned_files']} |\n"
        )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_scan_baseline.py BASELINE.json", file=sys.stderr)
        return 2
    try:
        baseline = _load_object(Path(sys.argv[1]).read_text(encoding="utf-8"), "baseline")
        result = _load_object(sys.stdin.read(), "scan result")
        regressions = evaluate(baseline, result)
        _append_step_summary(baseline, result)
    except (OSError, ValueError) as exc:
        print(f"baseline validation error: {exc}", file=sys.stderr)
        return 2

    if regressions:
        for regression in regressions:
            print(f"::error::{regression}")
        return 1
    print("readtheplan dogfood scan is within the reviewed baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
