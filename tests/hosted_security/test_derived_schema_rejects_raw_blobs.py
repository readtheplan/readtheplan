from __future__ import annotations

from typing import Any


ALLOWED_TOP_LEVEL_KEYS = {
    "run_id",
    "tenant_id",
    "status",
    "duration_ms",
    "created_at",
    "risks",
    "resource_type_histogram",
    "policy_hits",
}


FORBIDDEN_CONTENT_KEYS = {
    "before",
    "after",
    "raw_plan_json",
    "plan_json",
}


def _validate_derived_payload_schema(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    for key in payload:
        if key not in ALLOWED_TOP_LEVEL_KEYS:
            errors.append(f"unknown-top-level-key:{key}")

    def walk(value: Any, path: str = "$") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in FORBIDDEN_CONTENT_KEYS:
                    errors.append(f"forbidden-key:{path}.{key}")
                walk(child, f"{path}.{key}")
        elif isinstance(value, list):
            for i, child in enumerate(value):
                walk(child, f"{path}[{i}]")

    walk(payload)
    return errors


def test_valid_derived_payload_passes() -> None:
    payload = {
        "run_id": "run_123",
        "tenant_id": "tenant_abc",
        "status": "ok",
        "duration_ms": 120,
        "created_at": "2026-05-14T20:00:00Z",
        "risks": {"safe": 3, "review": 1, "dangerous": 0, "irreversible": 0},
        "resource_type_histogram": {"aws_s3_bucket": 1},
        "policy_hits": ["aws_s3_bucket.public_acl"],
    }
    assert _validate_derived_payload_schema(payload) == []


def test_unknown_and_raw_blob_fields_fail() -> None:
    payload = {
        "run_id": "run_unsafe",
        "tenant_id": "tenant_abc",
        "status": "ok",
        "raw_plan_json": {"resource_changes": []},
        "unexpected": "value",
    }

    errors = _validate_derived_payload_schema(payload)
    assert "unknown-top-level-key:raw_plan_json" in errors
    assert "unknown-top-level-key:unexpected" in errors
    assert "forbidden-key:$.raw_plan_json" in errors
