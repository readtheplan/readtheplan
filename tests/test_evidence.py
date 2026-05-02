from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, cast

import pytest

from readtheplan import controls
from readtheplan.attestation import plan_sha256
from readtheplan.cli import main
from readtheplan.evidence import (
    EVIDENCE_SCHEMA,
    EvidenceEnvelope,
    EvidenceError,
    Reviewer,
    build_evidence,
)
from readtheplan.plan import PlanSummary, analyze_plan_file

FIXTURES = Path(__file__).parent / "fixtures"
EVIDENCE_PLAN = FIXTURES / "evidence_plan.json"
FIXED_TIME = datetime(2026, 5, 2, 18, 24, 11, tzinfo=timezone.utc)
EXPECTED_CONTROLS = ["A1.2", "C1.1", "CC6.1", "CC6.6", "CC6.7", "CC8.1"]


def test_build_evidence_smoke() -> None:
    plan_json = _fixture_plan_json()
    envelope = _build_fixture_evidence()
    payload = envelope.to_dict()

    assert isinstance(envelope, EvidenceEnvelope)
    assert envelope.schema == EVIDENCE_SCHEMA
    assert envelope.generated_at == "2026-05-02T18:24:11Z"
    assert envelope.plan_sha256 == plan_sha256(plan_json)
    assert list(payload) == [
        "schema",
        "generated_at",
        "plan",
        "framework",
        "agent_attestation",
        "reviewer",
        "summary",
        "changes",
    ]
    assert payload["framework"] == {
        "name": "soc2",
        "version": "2017-tsc",
        "schema_version": 1,
    }


def test_build_evidence_plan_sha_matches_attestation_helper() -> None:
    plan_json = _fixture_plan_json()
    envelope = _build_fixture_evidence()

    assert envelope.to_dict()["plan"]["sha256"] == plan_sha256(plan_json)
    assert envelope.to_dict()["agent_attestation"]["plan_sha256"] == plan_sha256(
        plan_json
    )


def test_build_evidence_controls_touched_union_sorted() -> None:
    envelope = _build_fixture_evidence()

    assert envelope.to_dict()["summary"]["controls_touched"] == EXPECTED_CONTROLS


def test_build_evidence_empty_plan() -> None:
    plan_json = b'{"format_version":"1.2","resource_changes":[]}'
    summary = PlanSummary(
        path=Path("empty-plan.json"),
        terraform_version=None,
        resource_changes=(),
    )

    envelope = build_evidence(
        plan_summary=summary,
        plan_json=plan_json,
        catalog=controls.load_catalog("soc2"),
        agent_id="readtheplan@test",
        generated_at=FIXED_TIME,
    )
    payload = envelope.to_dict()

    assert payload["schema"] == EVIDENCE_SCHEMA
    assert payload["summary"]["resource_change_count"] == 0
    assert payload["summary"]["controls_touched"] == []
    assert payload["changes"] == []


def test_build_evidence_reviewer_null_by_default() -> None:
    envelope = _build_fixture_evidence()

    assert envelope.reviewer is None
    assert envelope.to_dict()["reviewer"] is None


def test_build_evidence_reviewer_human_default() -> None:
    envelope = _build_fixture_evidence(reviewer=Reviewer(id="alice@example.com"))

    assert envelope.to_dict()["reviewer"] == {
        "id": "alice@example.com",
        "kind": "human",
    }


def test_build_evidence_reviewer_agent_kind() -> None:
    envelope = _build_fixture_evidence(
        reviewer=Reviewer(id="codex", kind="agent"),
    )

    assert envelope.to_dict()["reviewer"] == {
        "id": "codex",
        "kind": "agent",
    }


def test_build_evidence_reviewer_empty_id_raises() -> None:
    with pytest.raises(EvidenceError, match="reviewer id"):
        _build_fixture_evidence(reviewer=Reviewer(id=""))


def test_cli_evidence_requires_framework(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["analyze", "--evidence", "evidence.json", str(EVIDENCE_PLAN)])

    captured = capsys.readouterr()
    assert exit_code != 0
    assert captured.out == ""
    assert "Error: --evidence requires --framework" in captured.err
    assert "Traceback" not in captured.err


def test_cli_evidence_writes_to_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence_path = tmp_path / "evidence.json"

    exit_code = main(
        [
            "analyze",
            "--framework",
            "soc2",
            "--evidence",
            str(evidence_path),
            "--agent-id",
            "readtheplan@test",
            str(EVIDENCE_PLAN),
        ]
    )

    captured = capsys.readouterr()
    payload = _loads_json(evidence_path.read_text(encoding="utf-8"))
    change = _change_by_address(payload, "aws_kms_key.customer_data")

    assert exit_code == 0
    assert captured.err == ""
    assert "# readtheplan summary:" in captured.out
    assert payload["schema"] == EVIDENCE_SCHEMA
    assert _control_ids(change) == {"CC6.1", "CC6.7", "CC8.1", "A1.2", "C1.1"}


def test_cli_evidence_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "analyze",
            "--framework",
            "soc2",
            "--format",
            "json",
            "--evidence",
            "-",
            "--agent-id",
            "readtheplan@test",
            str(EVIDENCE_PLAN),
        ]
    )

    captured = capsys.readouterr()
    payload = _loads_json(captured.out)

    assert exit_code == 0
    assert captured.err == ""
    assert payload["schema"] == EVIDENCE_SCHEMA
    assert "path" not in payload
    assert "# readtheplan summary:" not in captured.out


def test_build_evidence_deterministic() -> None:
    first = json.dumps(_build_fixture_evidence().to_dict(), indent=2)
    second = json.dumps(_build_fixture_evidence().to_dict(), indent=2)

    assert first == second


def _fixture_plan_json() -> bytes:
    return EVIDENCE_PLAN.read_bytes()


def _fixture_summary() -> PlanSummary:
    return analyze_plan_file(EVIDENCE_PLAN)


def _build_fixture_evidence(
    *,
    reviewer: Reviewer | None = None,
    agent_id: str = "readtheplan@test",
    generated_at: datetime = FIXED_TIME,
) -> EvidenceEnvelope:
    return build_evidence(
        plan_summary=_fixture_summary(),
        plan_json=_fixture_plan_json(),
        catalog=controls.load_catalog("soc2"),
        agent_id=agent_id,
        reviewer=reviewer,
        generated_at=generated_at,
    )


def _loads_json(text: str) -> dict[str, Any]:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise AssertionError("expected JSON object")
    return cast(dict[str, Any], payload)


def _change_by_address(payload: Mapping[str, Any], address: str) -> dict[str, Any]:
    changes = payload["changes"]
    if not isinstance(changes, list):
        raise AssertionError("expected changes list")
    for change in changes:
        if not isinstance(change, dict):
            raise AssertionError("expected change object")
        typed_change = cast(dict[str, Any], change)
        if typed_change["address"] == address:
            return typed_change
    raise AssertionError(f"missing change: {address}")


def _control_ids(change: Mapping[str, Any]) -> set[str]:
    raw_controls = change["controls"]
    if not isinstance(raw_controls, list):
        raise AssertionError("expected controls list")

    ids: set[str] = set()
    for control in raw_controls:
        if not isinstance(control, dict):
            raise AssertionError("expected control object")
        control_id = control.get("id")
        if not isinstance(control_id, str):
            raise AssertionError("expected string control id")
        ids.add(control_id)
    return ids
