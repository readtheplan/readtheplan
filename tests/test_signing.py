from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, cast

import pytest

from readtheplan import controls, signing
from readtheplan.cli import main
from readtheplan.evidence import EvidenceEnvelope, build_evidence
from readtheplan.plan import analyze_plan_file
from readtheplan.signing import (
    SigningError,
    VerificationError,
    VerificationResult,
    sign_envelope,
    verify_envelope,
)

FIXTURES = Path(__file__).parent / "fixtures"
EVIDENCE_PLAN = FIXTURES / "evidence_plan.json"
SIGNED_ENVELOPE = FIXTURES / "signed_envelope.json"
UNSIGNED_ENVELOPE = FIXTURES / "unsigned_envelope.json"
TAMPERED_ENVELOPE = FIXTURES / "tampered_envelope.json"
FIXED_TIME = datetime(2026, 5, 2, 18, 24, 11, tzinfo=timezone.utc)
FIXTURE_IDENTITY = "fixture@example.com"
FIXTURE_ISSUER = "https://issuer.example.test"
FIXTURE_REKOR_UUID = "fixture-rekor-0001"


def test_sign_then_verify_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sigstore(monkeypatch)
    signed = sign_envelope(_build_fixture_evidence())

    result = verify_envelope(json.dumps(signed).encode("utf-8"))

    assert result.ok is True
    assert result.identity == FIXTURE_IDENTITY
    assert result.oidc_issuer == FIXTURE_ISSUER
    assert result.rekor_uuid == FIXTURE_REKOR_UUID


def test_verify_unsigned_envelope_fails() -> None:
    result = verify_envelope(UNSIGNED_ENVELOPE.read_bytes())

    assert result.ok is False
    assert result.reason == "unsigned envelope"


def test_verify_tampered_envelope_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sigstore(monkeypatch)

    result = verify_envelope(TAMPERED_ENVELOPE.read_bytes())

    assert result.ok is False
    assert result.reason is not None
    assert "signature mismatch" in result.reason


def test_verify_malformed_input_raises() -> None:
    with pytest.raises(VerificationError, match="invalid evidence JSON"):
        verify_envelope(b"not json")


def test_verify_wrong_schema_raises() -> None:
    payload = _loads_json(UNSIGNED_ENVELOPE.read_text(encoding="utf-8"))
    payload["schema"] = "rtp-evidence-v0"

    with pytest.raises(VerificationError, match="unsupported evidence schema"):
        verify_envelope(json.dumps(payload).encode("utf-8"))


def test_canonical_payload_order_invariant(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sigstore(monkeypatch)
    envelope = _build_fixture_evidence()
    payload = envelope.to_dict()
    reordered = dict(reversed(list(_mapping(payload["agent_attestation"]).items())))
    variant = _envelope_from_payload({**payload, "agent_attestation": reordered})

    first = sign_envelope(envelope)
    second = sign_envelope(variant)

    assert (
        first["agent_attestation"]["signature"]
        == second["agent_attestation"]["signature"]
    )
    assert verify_envelope(json.dumps(first).encode("utf-8")).ok is True
    assert verify_envelope(json.dumps(second).encode("utf-8")).ok is True


def test_canonicalization_nulls_signature_and_cert() -> None:
    clean = _build_fixture_evidence().to_dict()
    dirty = _loads_json(json.dumps(clean))
    dirty["agent_attestation"]["signature"] = "prior-signature"
    dirty["agent_attestation"]["cert"] = "prior-cert"

    assert signing._canonical_payload(clean) == signing._canonical_payload(dirty)


def test_cli_sign_requires_evidence(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["analyze", "--framework", "soc2", "--sign", str(EVIDENCE_PLAN)])

    captured = capsys.readouterr()
    assert exit_code != 0
    assert captured.out == ""
    assert "Error: --sign requires --evidence" in captured.err
    assert "Traceback" not in captured.err


def test_cli_sign_writes_signed_envelope(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_sigstore(monkeypatch)
    evidence_path = tmp_path / "signed.json"

    exit_code = main(
        [
            "analyze",
            "--framework",
            "soc2",
            "--evidence",
            str(evidence_path),
            "--sign",
            "--agent-id",
            "readtheplan@test",
            str(EVIDENCE_PLAN),
        ]
    )
    result = verify_envelope(evidence_path.read_bytes())
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert result.ok is True


def test_cli_verify_signed_envelope(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_sigstore(monkeypatch)

    exit_code = main(["verify", str(SIGNED_ENVELOPE)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "OK identity=fixture@example.com" in captured.out
    assert f"issuer={FIXTURE_ISSUER}" in captured.out
    assert f"rekor_uuid={FIXTURE_REKOR_UUID}" in captured.out


def test_cli_verify_unsigned_envelope(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["verify", str(UNSIGNED_ENVELOPE)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "FAIL unsigned envelope" in captured.err
    assert "Traceback" not in captured.err


def test_cli_verify_missing_file(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["verify", str(FIXTURES / "missing-envelope.json")])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error: cannot read envelope file" in captured.err
    assert "Traceback" not in captured.err


def test_cli_sign_failure_message(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_sign(
        envelope: EvidenceEnvelope,
        *,
        oidc_issuer: str | None = None,
        rekor_url: str | None = None,
    ) -> dict[str, Any]:
        raise SigningError("OIDC unavailable")

    monkeypatch.setattr("readtheplan.cli.sign_envelope", fail_sign)

    exit_code = main(
        [
            "analyze",
            "--framework",
            "soc2",
            "--evidence",
            "-",
            "--sign",
            str(EVIDENCE_PLAN),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error: sign failed: OIDC unavailable" in captured.err
    assert "Traceback" not in captured.err


def test_verification_result_field_population() -> None:
    ok = VerificationResult(
        ok=True,
        identity=FIXTURE_IDENTITY,
        oidc_issuer=FIXTURE_ISSUER,
        rekor_uuid=FIXTURE_REKOR_UUID,
    )
    fail = VerificationResult(
        ok=False,
        identity="",
        oidc_issuer="",
        rekor_uuid="",
        reason="signature mismatch",
    )

    assert ok.identity
    assert ok.oidc_issuer
    assert ok.rekor_uuid
    assert ok.reason is None
    assert fail.reason == "signature mismatch"


def _patch_sigstore(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(signing, "_sign_payload_with_sigstore", _fake_sign_payload)
    monkeypatch.setattr(signing, "_verify_payload_with_sigstore", _fake_verify_payload)


def _fake_sign_payload(
    payload: bytes,
    *,
    oidc_issuer: str | None,
    rekor_url: str | None,
) -> signing._SignedPayload:
    signature = _fixture_signature(payload)
    bundle = {
        "readtheplan_test_bundle_v1": {
            "identity": FIXTURE_IDENTITY,
            "oidc_issuer": oidc_issuer or FIXTURE_ISSUER,
            "rekor_uuid": rekor_url or FIXTURE_REKOR_UUID,
            "signature": signature,
        }
    }
    return signing._SignedPayload(
        signature=signature,
        bundle_json=json.dumps(bundle, sort_keys=True, separators=(",", ":")),
    )


def _fake_verify_payload(
    payload: bytes,
    *,
    signature: str,
    bundle_json: str,
    rekor_url: str | None,
) -> VerificationResult:
    bundle = _loads_json(bundle_json)
    inner = _mapping(bundle["readtheplan_test_bundle_v1"])
    expected = _fixture_signature(payload)
    if signature != expected or inner["signature"] != signature:
        return VerificationResult(
            ok=False,
            identity="",
            oidc_issuer="",
            rekor_uuid="",
            reason="signature mismatch",
        )
    return VerificationResult(
        ok=True,
        identity=str(inner["identity"]),
        oidc_issuer=str(inner["oidc_issuer"]),
        rekor_uuid=str(inner["rekor_uuid"]),
    )


def _fixture_signature(payload: bytes) -> str:
    digest = hashlib.sha256(payload + b"|readtheplan-test-key").digest()
    return base64.b64encode(digest).decode("ascii")


def _build_fixture_evidence() -> EvidenceEnvelope:
    return build_evidence(
        plan_summary=analyze_plan_file(EVIDENCE_PLAN),
        plan_json=EVIDENCE_PLAN.read_bytes(),
        catalog=controls.load_catalog("soc2"),
        agent_id="readtheplan@test",
        generated_at=FIXED_TIME,
    )


def _envelope_from_payload(payload: Mapping[str, Any]) -> EvidenceEnvelope:
    plan = _mapping(payload["plan"])
    return EvidenceEnvelope(
        schema=str(payload["schema"]),
        generated_at=str(payload["generated_at"]),
        plan_sha256=str(plan["sha256"]),
        plan_source=str(plan["source"]),
        framework=_mapping(payload["framework"]),
        agent_attestation=_mapping(payload["agent_attestation"]),
        reviewer=cast(Mapping[str, Any] | None, payload["reviewer"]),
        summary=_mapping(payload["summary"]),
        changes=cast(list[Mapping[str, Any]], payload["changes"]),
    )


def _loads_json(text: str) -> dict[str, Any]:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise AssertionError("expected JSON object")
    return cast(dict[str, Any], payload)


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise AssertionError("expected mapping")
    return cast(Mapping[str, Any], value)
