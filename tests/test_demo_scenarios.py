"""Verify readtheplan correctly classifies demo scenarios."""
import json
from pathlib import Path

import pytest

from readtheplan.plan import analyze_plan_file

DEMO_DIR = Path(__file__).resolve().parent.parent / "demo" / "scenarios"

SCENARIOS = [
    ("01-safe-add-s3-bucket.json", "safe"),
    ("02-review-update-s3-tags.json", "review"),
    ("03-dangerous-replace-ec2.json", "dangerous"),
    ("04-irreversible-delete-rds.json", "irreversible"),
]


@pytest.mark.parametrize("filename,expected_risk", SCENARIOS)
def test_demo_scenario_risk(filename: str, expected_risk: str) -> None:
    """Each demo scenario must produce the expected risk classification."""
    path = DEMO_DIR / filename
    summary = analyze_plan_file(str(path))

    assert len(summary.resource_changes) > 0, f"No resources found in {filename}"
    for rc in summary.resource_changes:
        assert rc.risk == expected_risk, (
            f"{filename}: expected {expected_risk}, got {rc.risk} "
            f"({rc.address}): {rc.explanation}"
        )


def test_demo_results_json_matches():
    """The demo-results.json should match live analysis output."""
    results_path = DEMO_DIR.parent / "demo-results.json"
    results = json.loads(results_path.read_text())

    for entry in results:
        path = DEMO_DIR / entry["file"]
        summary = analyze_plan_file(str(path))
        for rc in summary.resource_changes:
            assert rc.risk == entry["expected"], (
                f"{entry['file']}: results JSON says {entry['expected']}, "
                f"but engine says {rc.risk}"
            )
