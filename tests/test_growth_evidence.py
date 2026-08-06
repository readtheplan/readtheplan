from __future__ import annotations

import csv
import re
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs" / "growth" / "30-day-terraform-gate-evidence-test.md"
LEDGER = ROOT / "docs" / "growth" / "activation-ledger.csv"

BOOLEAN_FIELDS = {
    "qualified",
    "replied",
    "useful_finding_confirmed",
    "gate_retained_day14",
}
ISO_FIELDS = {
    "cohort_date",
    "contacted_at",
    "trial_started_at",
    "day14_due",
    "retention_checked_at",
}
LOSS_REASONS = {
    "not_qualified",
    "no_reply",
    "no_time",
    "install_blocked",
    "plan_json_blocked",
    "no_useful_signal",
    "too_noisy",
    "no_ci_authority",
    "existing_control_preferred",
    "privacy_concern",
    "unknown",
}
NEXT_ACTIONS = {
    "qualify",
    "schedule_trial",
    "follow_up_once",
    "check_day14",
    "close",
}
RETENTION_EVIDENCE = {
    "confirmation",
    "data_free_workflow_description",
}


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_ledger_row(row: dict[str, str]) -> None:
    assert re.fullmatch(r"C\d{2,}", row["contact_id"])
    for field in BOOLEAN_FIELDS:
        assert row[field] in {"", "yes", "no"}
    for field in ISO_FIELDS:
        if row[field]:
            _parse_iso(row[field])
    assert not row["trial_id"] or re.fullmatch(r"T\d{2,}", row["trial_id"])
    assert not row["loss_reason_category"] or row["loss_reason_category"] in LOSS_REASONS
    assert not row["next_action"] or row["next_action"] in NEXT_ACTIONS
    assert not row["retention_evidence"] or row["retention_evidence"] in RETENTION_EVIDENCE

    if row["trial_started_at"]:
        started = _parse_iso(row["trial_started_at"])
        assert started.date() <= date(2026, 9, 4)
        if row["day14_due"]:
            assert _parse_iso(row["day14_due"]).date() == started.date() + timedelta(days=14)
    if row["retention_evidence"]:
        assert row["gate_retained_day14"] == "yes"
        assert row["retention_checked_at"]


def test_30_day_evidence_test_has_decision_contract() -> None:
    plan = PLAN.read_text(encoding="utf-8")
    semantic_text = plan.replace("`", "")

    required_fragments = [
        "20 qualified contacts",
        "5 real-repository trials",
        "started on or before 2026-09-04",
        "2 gates retained at day 14",
        "at least one of the two threshold-counting retained gates",
        "2026-08-06 through 2026-09-04",
        "2026-09-18",
        "qualified contact",
        "real-repository trial",
        "useful finding",
        "gate retained at day 14",
        "five prospective contacts",
        "extend the ledger with C21",
        "counts as not retained",
        "data-free description",
        "do not request or accept screen sharing",
        "updated privacy disclosure per ADR 0015",
        "Selection and generalizability",
        "Founder-assistance and reciprocity",
        "verify_change_click",
        "copy_install",
        "playground_run",
        "generate_ci",
        "setup_help_click",
        "same free, public, MIT-licensed build",
    ]
    missing = [fragment for fragment in required_fragments if fragment not in semantic_text]
    assert not missing, f"missing decision-contract clauses: {missing}"

    for prohibited in [
        "monthly PyPI downloads prove",
        "upload the plan",
        "private feature access",
        "custom event properties",
    ]:
        assert prohibited not in plan


def test_activation_ledger_is_pseudonymous_and_schema_validated() -> None:
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
        "retention_evidence",
        "loss_reason_category",
        "next_action",
    ]
    assert reader.fieldnames == expected_headers
    assert len(rows) >= 20
    assert [row["contact_id"] for row in rows] == [
        f"C{index:02d}" for index in range(1, len(rows) + 1)
    ]
    for row in rows:
        _validate_ledger_row(row)

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


def test_ledger_validator_accepts_a_filled_closed_schema_row() -> None:
    sample = dict.fromkeys(
        [
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
            "retention_evidence",
            "loss_reason_category",
            "next_action",
        ],
        "",
    )
    sample.update(
        {
            "contact_id": "C21",
            "cohort_date": "2026-08-20",
            "qualified": "yes",
            "contacted_at": "2026-08-20T10:00:00Z",
            "replied": "yes",
            "trial_id": "T06",
            "trial_started_at": "2026-08-20",
            "useful_finding_confirmed": "yes",
            "day14_due": "2026-09-03",
            "gate_retained_day14": "yes",
            "retention_checked_at": "2026-09-03T10:00:00Z",
            "retention_evidence": "data_free_workflow_description",
            "next_action": "close",
        }
    )
    _validate_ledger_row(sample)
