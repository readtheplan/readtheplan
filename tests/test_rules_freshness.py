"""Freshness tests for _DEPRECATED_RUNTIMES.

The _DEPRECATED_RUNTIMES set in readtheplan/rules.py is a hardcoded snapshot
that will go stale as AWS announces new deprecations.  These tests verify:

  1. Every entry in the set has a known EOL date that is in the past.
  2. No runtime whose EOL date has passed is missing from the set.

When a new Lambda runtime is deprecated:

  - Add its EOL date to _KNOWN_EOL below.
  - Run the tests — they will tell you to also add the runtime to
    _DEPRECATED_RUNTIMES (and blow up until you do).
"""

from __future__ import annotations

import pytest
from datetime import date

from readtheplan.rules import _DEPRECATED_RUNTIMES

# ---------------------------------------------------------------------------
# Known end-of-life dates for AWS Lambda runtimes.
#
# Source: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
# References:
#   nodejs18.x EOL 2025-04-30: https://docs.aws.amazon.com/lambda/latest/dg/runtime-support-policy.html
#   python3.9  EOL 2025-04-30: https://docs.aws.amazon.com/lambda/latest/dg/runtime-support-policy.html
# ---------------------------------------------------------------------------
# A runtime belongs here when its phase-out / deprecation date has passed.
# This is the *deprecation* date, not the optional second-phase "no more
# updates" date — we flag the runtime as deprecated as soon as AWS stops
# accepting create-function calls without an opt-in.
# ---------------------------------------------------------------------------
_KNOWN_EOL: dict[str, date] = {
    "nodejs12.x": date(2023, 7, 15),
    "nodejs14.x": date(2023, 12, 4),
    "nodejs16.x": date(2024, 6, 12),
    "python3.6": date(2021, 12, 23),
    "python3.7": date(2022, 12, 13),
    "python3.8": date(2024, 10, 14),
    "dotnetcore3.1": date(2022, 12, 3),
    "dotnet5.0": date(2022, 5, 10),
    "dotnet6": date(2024, 11, 12),
    "ruby2.5": date(2021, 8, 30),
    "ruby2.7": date(2022, 12, 7),
    "java8": date(2023, 12, 31),
    "java8.al2": date(2023, 12, 31),
    "go1.x": date(2023, 12, 31),
    "provided": date(2023, 12, 31),
    "nodejs18.x": date(2025, 4, 30),
    "python3.9": date(2025, 4, 30),
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_deprecated_runtimes_have_known_eol() -> None:
    """Every runtime in _DEPRECATED_RUNTIMES must have a _KNOWN_EOL entry."""
    missing = _DEPRECATED_RUNTIMES - set(_KNOWN_EOL)
    assert not missing, (
        f"Runtime(s) {sorted(missing)} are in _DEPRECATED_RUNTIMES "
        f"but have no known EOL date in _KNOWN_EOL. "
        f"Please add them (with source)."
    )


def test_known_eol_dates_are_in_the_past() -> None:
    """Every runtime whose EOL we know must have its deprecation date in the past."""
    today = date.today()
    still_alive: dict[str, date] = {
        runtime: eol
        for runtime, eol in _KNOWN_EOL.items()
        if eol >= today
    }
    if not still_alive:
        return
    # Any runtime in this branch hasn't actually been deprecated by AWS yet.
    # If it's already in _DEPRECATED_RUNTIMES, that's a mistake — remove it.
    # If it's only in _KNOWN_EOL (pre-added for a future deprecation), that's
    # allowed but we should remind maintainers.
    premature = still_alive.keys() & _DEPRECATED_RUNTIMES
    future_only = still_alive.keys() - _DEPRECATED_RUNTIMES
    if premature:
        pytest.fail(
            f"Runtime(s) {sorted(premature)} are in _DEPRECATED_RUNTIMES "
            f"but their EOL dates ({_fmt(still_alive, premature)}) "
            f"are still in the future (today={today}). "
            f"Remove them from _DEPRECATED_RUNTIMES until AWS actually deprecates them."
        )
    if future_only:
        import warnings
        warnings.warn(
            f"Runtime(s) {sorted(future_only)} have known EOL dates "
            f"in the future ({_fmt(still_alive, future_only)}). "
            f"That's fine — they are placeholders in _KNOWN_EOL for "
            f"planned deprecations."
        )


def test_no_missing_deprecated_runtimes() -> None:
    """Every runtime whose EOL date has passed must be in _DEPRECATED_RUNTIMES."""
    today = date.today()
    should_be_deprecated = {
        runtime
        for runtime, eol in _KNOWN_EOL.items()
        if eol < today
    }
    missing = should_be_deprecated - _DEPRECATED_RUNTIMES
    assert not missing, (
        f"Runtime(s) {sorted(missing)} have known EOL dates in the past "
        f"({_fmt(_KNOWN_EOL, missing)}) but are NOT in _DEPRECATED_RUNTIMES.\n"
        f"Please add them to the _DEPRECATED_RUNTIMES set in src/readtheplan/rules.py."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fmt(
    mapping: dict[str, date],
    keys: set[str],
) -> str:
    parts = (f"{k}={mapping[k]}" for k in sorted(keys))
    return ", ".join(parts)
