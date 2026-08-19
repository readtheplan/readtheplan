from __future__ import annotations

import csv
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

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
    "qualified_at",
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
ASSISTANCE_CATEGORIES = {
    "none",
    "install_command",
    "workflow_configuration",
    "failure_triage",
}
SAMPLE_CAMPAIGN_START = date(2030, 1, 1)


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _parse_instant(value: str) -> datetime:
    parsed = _parse_iso(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _validate_ledger_row(
    row: dict[str, str], *, campaign_start: date | None = None
) -> None:
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
    assert not row["assistance_category"] or row["assistance_category"] in ASSISTANCE_CATEGORIES

    if row["qualified"]:
        assert row["qualified_at"]

    if row["contacted_at"]:
        assert row["cohort_date"]
        assert _parse_iso(row["cohort_date"]).date() <= _parse_iso(row["contacted_at"]).date()

    if row["qualified_at"]:
        assert row["contacted_at"]
        assert _parse_instant(row["contacted_at"]) <= _parse_instant(row["qualified_at"])

    trial_only_fields = (
        "assistance_category",
        "useful_finding_confirmed",
        "day14_due",
        "gate_retained_day14",
        "retention_checked_at",
        "retention_evidence",
    )
    if any(row[field] for field in trial_only_fields):
        assert row["trial_started_at"]

    if row["trial_started_at"]:
        started = _parse_iso(row["trial_started_at"])
        assert campaign_start is not None, "owner-approved campaign start is required"
        assert campaign_start <= started.date() <= campaign_start + timedelta(days=29)
        assert row["qualified"] == "yes"
        assert row["replied"] == "yes"
        assert row["trial_id"]
        assert row["qualified_at"]
        assert row["contacted_at"]
        assert row["assistance_category"] in ASSISTANCE_CATEGORIES
        assert row["day14_due"]
        assert _parse_iso(row["qualified_at"]).date() <= started.date()
        assert _parse_iso(row["contacted_at"]).date() <= started.date()
        assert _parse_iso(row["day14_due"]).date() == started.date() + timedelta(days=14)
    if row["retention_checked_at"]:
        assert campaign_start is not None, "owner-approved campaign start is required"
        assert row["day14_due"]
        assert _parse_iso(row["retention_checked_at"]).date() >= _parse_iso(row["day14_due"]).date()
        assert _parse_iso(row["retention_checked_at"]).date() <= campaign_start + timedelta(days=43)
    if row["retention_evidence"]:
        assert row["gate_retained_day14"] == "yes"
        assert row["retention_checked_at"]


def test_30_day_evidence_test_has_decision_contract() -> None:
    plan = PLAN.read_text(encoding="utf-8")
    semantic_text = plan.replace("`", "")

    required_fragments = [
        "20 qualified contacts",
        "5 real-repository trials",
        "started on or before D0 + 29 days",
        "2 gates retained at day 14",
        "at least one threshold-counting retained gate",
        "D0 through D0 + 29 days",
        "D0 + 43 days",
        "D0 is the owner-approved campaign start date",
        "blank template only",
        "private, access-restricted operational copy",
        "never commit or share a populated ledger",
        "Evidence insufficient",
        "assistance_category",
        "qualified_at",
        "cohort_date is the scheduled first-outreach date",
        "no later than D0 + 43 days",
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
        "2026-08-06",
        "2026-09-04",
        "2026-09-18",
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
        "qualified_at",
        "contacted_at",
        "replied",
        "trial_id",
        "trial_started_at",
        "assistance_category",
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
        assert all(
            value == "" for field, value in row.items() if field != "contact_id"
        ), "tracked activation-ledger.csv must remain a blank template"

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


def _filled_closed_schema_row() -> dict[str, str]:
    sample = dict.fromkeys(
        [
            "contact_id",
            "cohort_date",
            "qualified",
            "qualified_at",
            "contacted_at",
            "replied",
            "trial_id",
            "trial_started_at",
            "assistance_category",
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
            "cohort_date": "2030-01-15",
            "qualified": "yes",
            "qualified_at": "2030-01-15T10:00:00Z",
            "contacted_at": "2030-01-15T09:00:00Z",
            "replied": "yes",
            "trial_id": "T06",
            "trial_started_at": "2030-01-15",
            "assistance_category": "workflow_configuration",
            "useful_finding_confirmed": "yes",
            "day14_due": "2030-01-29",
            "gate_retained_day14": "yes",
            "retention_checked_at": "2030-01-29T10:00:00Z",
            "retention_evidence": "data_free_workflow_description",
            "next_action": "close",
        }
    )
    return sample


def test_ledger_validator_accepts_a_filled_closed_schema_row() -> None:
    _validate_ledger_row(
        _filled_closed_schema_row(), campaign_start=SAMPLE_CAMPAIGN_START
    )


def test_ledger_validator_rejects_trial_without_owner_approved_campaign_start() -> None:
    with pytest.raises(AssertionError, match="campaign start"):
        _validate_ledger_row(_filled_closed_schema_row(), campaign_start=None)


@pytest.mark.parametrize(
    "updates",
    [
        {"assistance_category": "custom_notes"},
        {"trial_started_at": "2029-12-31", "day14_due": "2030-01-14"},
        {"trial_started_at": "2030-01-31", "day14_due": "2030-02-14"},
        {"contacted_at": "2030-01-16T10:00:00Z"},
        {"qualified_at": "2030-01-16T09:00:00Z"},
        {"retention_checked_at": "2030-01-28T10:00:00Z"},
        {"qualified": "no"},
        {"trial_id": ""},
        {"day14_due": ""},
        {"assistance_category": ""},
        {"trial_started_at": ""},
        {"retention_checked_at": "2030-02-14T10:00:00Z"},
        {"cohort_date": ""},
        {"contacted_at": "2030-01-14T09:00:00Z"},
        {"qualified_at": "2030-01-15T08:00:00Z"},
    ],
)
def test_ledger_validator_rejects_inconsistent_trial_rows(updates: dict[str, str]) -> None:
    sample = _filled_closed_schema_row()
    sample.update(updates)
    with pytest.raises(AssertionError):
        _validate_ledger_row(sample, campaign_start=SAMPLE_CAMPAIGN_START)
