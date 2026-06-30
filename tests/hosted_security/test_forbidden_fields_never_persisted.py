from __future__ import annotations

from typing import Any

FORBIDDEN_KEYS = {
    "raw_plan_json",
    "plan_json",
    "before",
    "after",
    "secret",
    "password",
    "token",
    "access_key",
    "private_key",
}


def _find_forbidden_paths(value: Any, path: str = "$") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = key.lower()
            next_path = f"{path}.{key}"
            if lowered in FORBIDDEN_KEYS:
                hits.append(next_path)
            hits.extend(_find_forbidden_paths(child, next_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            hits.extend(_find_forbidden_paths(child, f"{path}[{index}]"))
    return hits


def test_derived_payload_fixture_contains_no_forbidden_keys() -> None:
    derived_payload = {
        "run_id": "run_123",
        "tenant_id": "tenant_abc",
        "risks": {"safe": 2, "review": 1, "dangerous": 0, "irreversible": 0},
        "resource_type_histogram": {"aws_s3_bucket": 1, "aws_kms_key": 1},
        "policy_hits": ["aws_s3_bucket.public_acl"],
    }

    assert _find_forbidden_paths(derived_payload) == []


def test_raw_plan_like_fields_are_detected() -> None:
    unsafe_payload = {
        "run_id": "run_unsafe",
        "derived": {"risks": {"review": 1}},
        "raw_plan_json": {"resource_changes": [{"before": {"x": 1}}]},
    }

    hits = _find_forbidden_paths(unsafe_payload)
    assert "$.raw_plan_json" in hits
    assert "$.raw_plan_json.resource_changes[0].before" in hits
