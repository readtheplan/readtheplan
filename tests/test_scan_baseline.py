from __future__ import annotations

import copy

import pytest

from scripts.check_scan_baseline import evaluate


@pytest.fixture
def baseline() -> dict[str, object]:
    return {
        "schema": "readtheplan-scan-baseline-v1",
        "maximum_risk_counts": {
            "safe": 10,
            "review": 20,
            "dangerous": 5,
            "irreversible": 0,
        },
        "maximum_errors": 0,
        "minimum_scanned_files": 4,
    }


@pytest.fixture
def result() -> dict[str, object]:
    return {
        "adapter": "project-scan",
        "risk_counts": {
            "safe": 10,
            "review": 20,
            "dangerous": 5,
            "irreversible": 0,
        },
        "error_count": 0,
        "scanned_file_count": 4,
    }


def test_baseline_accepts_equal_or_improved_scan(
    baseline: dict[str, object], result: dict[str, object]
) -> None:
    assert evaluate(baseline, result) == []
    improved = copy.deepcopy(result)
    improved["risk_counts"]["dangerous"] = 4  # type: ignore[index]
    assert evaluate(baseline, improved) == []


def test_baseline_rejects_risk_error_and_coverage_regressions(
    baseline: dict[str, object], result: dict[str, object]
) -> None:
    regressed = copy.deepcopy(result)
    regressed["risk_counts"]["dangerous"] = 6  # type: ignore[index]
    regressed["error_count"] = 1
    regressed["scanned_file_count"] = 3

    assert evaluate(baseline, regressed) == [
        "dangerous findings increased: 6 > 5",
        "scan errors increased: 1 > 0",
        "scan coverage decreased: 3 < 4 files",
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [("maximum_errors", -1), ("minimum_scanned_files", True)],
)
def test_baseline_rejects_invalid_limits(
    baseline: dict[str, object], result: dict[str, object], field: str, value: object
) -> None:
    baseline[field] = value
    with pytest.raises(ValueError, match="non-negative integer"):
        evaluate(baseline, result)
