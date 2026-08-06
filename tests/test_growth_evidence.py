from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs" / "growth" / "30-day-terraform-gate-evidence-test.md"
LEDGER = ROOT / "docs" / "growth" / "activation-ledger.csv"


def test_30_day_evidence_test_has_decision_contract() -> None:
    plan = PLAN.read_text(encoding="utf-8")

    for required in [
        "20 qualified contacts",
        "5 real-repository trials",
        "2 gates retained at day 14",
        "2026-08-06 through 2026-09-04",
        "2026-09-18",
        "qualified contact",
        "real-repository trial",
        "useful finding",
        "gate retained at day 14",
        "verify_change_click",
        "copy_install",
        "playground_run",
        "generate_ci",
        "setup_help_click",
        "same free, public, MIT-licensed build",
    ]:
        assert required in plan

    for prohibited in [
        "monthly PyPI downloads prove",
        "upload the plan",
        "private feature access",
        "custom event properties",
    ]:
        assert prohibited not in plan


def test_activation_ledger_is_pseudonymous_and_preallocated() -> None:
    with LEDGER.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    expected_headers = [
        "contact_id",
        "cohort_date",
        "qualified",
        "contacted_at",
        "replied",
        "trial_id",
        "trial_started_at",
        "useful_finding_confirmed",
        "day14_due",
        "gate_retained_day14",
        "retention_checked_at",
        "loss_reason_category",
        "next_action",
    ]
    assert reader.fieldnames == expected_headers
    assert [row["contact_id"] for row in rows] == [f"C{index:02d}" for index in range(1, 21)]

    forbidden_header_fragments = {
        "email",
        "name",
        "repo",
        "url",
        "plan",
        "resource",
        "filename",
        "command",
        "credential",
    }
    assert not any(
        fragment in header
        for header in expected_headers
        for fragment in forbidden_header_fragments
    )
