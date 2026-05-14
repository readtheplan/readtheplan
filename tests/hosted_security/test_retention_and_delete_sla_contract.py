from __future__ import annotations

from datetime import UTC, datetime, timedelta


MAX_RETENTION_DAYS = 30
MAX_DELETE_SLA_HOURS = 24


def _validate_retention_contract(record: dict) -> list[str]:
    errors: list[str] = []

    retention_days = record.get("retention_days")
    if not isinstance(retention_days, int) or retention_days <= 0:
        errors.append("invalid-retention-days")
    elif retention_days > MAX_RETENTION_DAYS:
        errors.append("retention-exceeds-policy")

    requested_at = record.get("delete_requested_at")
    due_at = record.get("delete_due_at")
    if requested_at and due_at:
        requested = datetime.fromisoformat(requested_at.replace("Z", "+00:00"))
        due = datetime.fromisoformat(due_at.replace("Z", "+00:00"))
        if due - requested > timedelta(hours=MAX_DELETE_SLA_HOURS):
            errors.append("delete-sla-exceeded")
    else:
        errors.append("missing-delete-sla-metadata")

    return errors


def test_retention_contract_accepts_policy_compliant_record() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    record = {
        "retention_days": 30,
        "delete_requested_at": now.isoformat().replace("+00:00", "Z"),
        "delete_due_at": (now + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
    }
    assert _validate_retention_contract(record) == []


def test_retention_contract_rejects_policy_violations() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    record = {
        "retention_days": 90,
        "delete_requested_at": now.isoformat().replace("+00:00", "Z"),
        "delete_due_at": (now + timedelta(hours=48)).isoformat().replace("+00:00", "Z"),
    }

    errors = _validate_retention_contract(record)
    assert "retention-exceeds-policy" in errors
    assert "delete-sla-exceeded" in errors
