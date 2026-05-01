from __future__ import annotations

from datetime import datetime, timezone

import pytest

from readtheplan.attestation import (
    ATTESTATION_HEADER,
    build_plan_read_attestation,
    parse_attestation_header,
    plan_sha256,
)


def test_builds_and_parses_plan_read_header() -> None:
    attestation = build_plan_read_attestation(
        agent_id="codex",
        plan_json='{"resource_changes":[]}',
        read_at=datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc),
        run_id="run-123",
    )

    parsed = parse_attestation_header(attestation.to_header_value())

    assert ATTESTATION_HEADER == "x-readtheplan-agent-read"
    assert parsed.agent_id == "codex"
    assert parsed.read_at == "2026-05-01T12:00:00Z"
    assert parsed.run_id == "run-123"
    assert parsed.plan_sha256 == plan_sha256('{"resource_changes":[]}')


def test_rejects_missing_required_fields() -> None:
    with pytest.raises(ValueError, match="missing required"):
        parse_attestation_header("rtp-attest-v1; agent=codex")


def test_rejects_non_token_agent_ids() -> None:
    with pytest.raises(ValueError, match="compact token"):
        build_plan_read_attestation(
            agent_id="bad agent",
            plan_json="{}",
        )
