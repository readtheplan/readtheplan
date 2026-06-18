from __future__ import annotations

import base64
import re
import sys
import sys
import builtins
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
    SIGNING_INSTALL_HINT,
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


def _fake_x509_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Install a minimal fake cryptography.x509 module so certificate parsing
    tests run without the real optional dependency."""
    class ExtensionNotFound(Exception):
        def __init__(self, msg, oid):
            super().__init__(msg)
            self.oid = oid

    class RFC822Name:
        def __init__(self, value):
            self._value = value

    class UniformResourceIdentifier:
        def __init__(self, value):
            self._value = value

    class SubjectAlternativeName:
        pass

    class FakeSANValue:
        def __init__(self, values):
            self._values = values

        def get_values_for_type(self, typ):
            return [v._value for v in self._values if isinstance(v, typ)]

    class FakeExtension:
        def __init__(self, value):
            self.value = value

    class FakeExtensions:
        def __init__(self, by_class=None, by_oid=None):
            self._by_class = by_class or {}
            self._by_oid = by_oid or {}

        def get_extension_for_class(self, cls):
            if cls in self._by_class:
                return self._by_class[cls]
            raise ExtensionNotFound("not found", cls)

        def get_extension_for_oid(self, oid):
            if oid in self._by_oid:
                return self._by_oid[oid]
            raise ExtensionNotFound("not found", oid)

    class FakeOID:
        def __init__(self, dotted):
            self.dotted_string = dotted

        def __eq__(self, other):
            return isinstance(other, FakeOID) and self.dotted_string == other.dotted_string

        def __hash__(self):
            return hash(self.dotted_string)

    class FakeX509:
        pass
    FakeX509.ExtensionNotFound = ExtensionNotFound
    FakeX509.SubjectAlternativeName = SubjectAlternativeName
    FakeX509.RFC822Name = RFC822Name
    FakeX509.UniformResourceIdentifier = UniformResourceIdentifier
    FakeX509.UnrecognizedExtension = type("UnrecognizedExtension", (), {"value": ""})

    class FakeOIDModule:
        ObjectIdentifier = FakeOID

    fake_x509 = FakeX509()
    fake_x509.FakeExtension = FakeExtension
    fake_x509.FakeExtensions = FakeExtensions
    fake_x509.FakeSANValue = FakeSANValue
    fake_oid = FakeOIDModule()

    fake_crypto = type("mod", (), {})()
    fake_crypto.x509 = fake_x509
    fake_crypto.x509.oid = fake_oid

    monkeypatch.setitem(sys.modules, "cryptography", fake_crypto)
    monkeypatch.setitem(sys.modules, "cryptography.x509", fake_x509)
    monkeypatch.setitem(sys.modules, "cryptography.x509.oid", fake_oid)

    return fake_x509


def test_sign_then_verify_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sigstore(monkeypatch)
    signed = sign_envelope(_build_fixture_evidence())

    result = verify_envelope(
        json.dumps(signed).encode("utf-8"),
        certificate_identity=FIXTURE_IDENTITY,
        certificate_oidc_issuer=FIXTURE_ISSUER,
    )

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

    result = verify_envelope(
        TAMPERED_ENVELOPE.read_bytes(),
        certificate_identity=FIXTURE_IDENTITY,
        certificate_oidc_issuer=FIXTURE_ISSUER,
    )

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
    assert verify_envelope(
        json.dumps(first).encode("utf-8"),
        certificate_identity=FIXTURE_IDENTITY,
        certificate_oidc_issuer=FIXTURE_ISSUER,
    ).ok is True
    assert verify_envelope(
        json.dumps(second).encode("utf-8"),
        certificate_identity=FIXTURE_IDENTITY,
        certificate_oidc_issuer=FIXTURE_ISSUER,
    ).ok is True


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


def test_cli_sign_without_sigstore_prints_install_hint(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def block_sigstore_import(name, *args, **kwargs):
        if name.startswith("sigstore"):
            raise ImportError("sigstore intentionally unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_sigstore_import)

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
    assert SIGNING_INSTALL_HINT in captured.err
    assert "ImportError" not in captured.err
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
    result = verify_envelope(
        evidence_path.read_bytes(),
        certificate_identity=FIXTURE_IDENTITY,
        certificate_oidc_issuer=FIXTURE_ISSUER,
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert result.ok is True


def test_cli_verify_signed_envelope(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_sigstore(monkeypatch)

    exit_code = main(
        [
            "verify",
            "--certificate-identity",
            FIXTURE_IDENTITY,
            "--certificate-oidc-issuer",
            FIXTURE_ISSUER,
            str(SIGNED_ENVELOPE),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "OK identity=fixture@example.com" in captured.out
    assert f"issuer={FIXTURE_ISSUER}" in captured.out
    assert f"rekor_uuid={FIXTURE_REKOR_UUID}" in captured.out


def test_cli_verify_unsigned_envelope(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "verify",
            "--certificate-identity",
            FIXTURE_IDENTITY,
            "--certificate-oidc-issuer",
            FIXTURE_ISSUER,
            str(UNSIGNED_ENVELOPE),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "FAIL unsigned envelope" in captured.err
    assert "Traceback" not in captured.err


def test_cli_verify_missing_file(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "verify",
            "--certificate-identity",
            FIXTURE_IDENTITY,
            "--certificate-oidc-issuer",
            FIXTURE_ISSUER,
            str(FIXTURES / "missing-envelope.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Error: cannot read envelope file" in captured.err
    assert "Traceback" not in captured.err


def test_verify_envelope_without_identity_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_sigstore(monkeypatch)
    signed = sign_envelope(_build_fixture_evidence())

    result = verify_envelope(json.dumps(signed).encode("utf-8"))

    assert result.ok is False
    assert result.reason is not None
    assert "identity verification required" in result.reason


def test_cli_verify_missing_identity_flags(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["verify", str(SIGNED_ENVELOPE)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "--certificate-identity" in captured.err
    assert "--certificate-oidc-issuer" in captured.err
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
    certificate_identity: str | None = None,
    certificate_oidc_issuer: str | None = None,
) -> VerificationResult:
    if not certificate_identity or not certificate_oidc_issuer:
        return VerificationResult(
            ok=False,
            identity="",
            oidc_issuer="",
            rekor_uuid="",
            reason="identity verification required "
            "(--certificate-identity and --certificate-oidc-issuer)",
        )
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

# ── Internal helper coverage ─────────────────────────────────────────


def test_load_envelope_rejects_non_object_json() -> None:
    """JSON arrays/numbers are not valid evidence envelopes."""
    with pytest.raises(VerificationError, match="must be a JSON object"):
        verify_envelope(b"[1, 2, 3]")


def test_load_envelope_rejects_invalid_json_bytes() -> None:
    with pytest.raises(VerificationError, match="invalid evidence JSON"):
        verify_envelope(bytes([0x00, 0x01]))


def test_agent_attestation_missing_raises() -> None:
    """Envelope without agent_attestation dict should raise."""
    payload = {"schema": "rtp-evidence-v1"}
    with pytest.raises(VerificationError, match="missing agent_attestation"):
        verify_envelope(json.dumps(payload).encode("utf-8"))


def test_verify_unsigned_envelope_signature_but_no_cert() -> None:
    """Envelope with signature but missing cert should fail as unsigned."""
    payload = _loads_json(UNSIGNED_ENVELOPE.read_text(encoding="utf-8"))
    payload["agent_attestation"]["signature"] = "some-signature"
    # cert is intentionally absent
    result = verify_envelope(json.dumps(payload).encode("utf-8"))
    assert result.ok is False
    assert result.reason == "unsigned envelope"


def test_verify_unsigned_envelope_cert_but_no_signature() -> None:
    """Envelope with cert but missing signature should fail as unsigned."""
    payload = _loads_json(UNSIGNED_ENVELOPE.read_text(encoding="utf-8"))
    payload["agent_attestation"]["cert"] = "some-cert"
    result = verify_envelope(json.dumps(payload).encode("utf-8"))
    assert result.ok is False
    assert result.reason == "unsigned envelope"


def test_sign_envelope_wraps_sigstore_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Errors from _sign_payload_with_sigstore become SigningError."""

    def boom(*a, **kw):
        raise RuntimeError("network down")

    monkeypatch.setattr(signing, "_sign_payload_with_sigstore", boom)
    with pytest.raises(SigningError, match="network down"):
        sign_envelope(_build_fixture_evidence())


# ── _decode_der_string ───────────────────────────────────────────────


def test_decode_der_string_utf8_string() -> None:
    """DER UTF8String (tag 0x0C) should decode correctly."""
    text = "https://accounts.google.com"
    encoded = bytes([0x0C, len(text)]) + text.encode("utf-8")
    assert signing._decode_der_string(encoded) == text


def test_decode_der_string_ia5_string() -> None:
    """DER IA5String (tag 0x16) should decode correctly."""
    text = "issuer@example.com"
    encoded = bytes([0x16, len(text)]) + text.encode("utf-8")
    assert signing._decode_der_string(encoded) == text


def test_decode_der_string_raw_fallback() -> None:
    """Bytes without a DER tag should fall back to raw UTF-8 decode."""
    raw = "not-der".encode("utf-8")
    assert signing._decode_der_string(raw) == "not-der"


def test_decode_der_string_truncated_length() -> None:
    """If the DER length header claims more than available, decode what we have."""
    encoded = bytes([0x0C, 99]) + b"short"
    # length says 99 but only 5 bytes available — should still return something
    result = signing._decode_der_string(encoded)
    assert "short" in result


# ── _rekor_uuid ──────────────────────────────────────────────────────


def test_rekor_uuid_extracts_uuid() -> None:
    """_rekor_uuid should extract the UUID from the bundle log entry."""

    class FakeInner:
        uuid = "abc-123-def"

    class FakeEntry:
        _inner = FakeInner()

    class FakeBundle:
        log_entry = FakeEntry()

    assert signing._rekor_uuid(FakeBundle()) == "abc-123-def"


def test_rekor_uuid_falls_back_to_log_index() -> None:
    class FakeInner:
        uuid = None
        log_index = 42

    class FakeEntry:
        _inner = FakeInner()

    class FakeBundle:
        log_entry = FakeEntry()

    assert signing._rekor_uuid(FakeBundle()) == "42"


def test_rekor_uuid_returns_empty_on_missing() -> None:
    class FakeInner:
        uuid = None
        log_index = None

    class FakeEntry:
        _inner = FakeInner()

    class FakeBundle:
        log_entry = FakeEntry()

    assert signing._rekor_uuid(FakeBundle()) == ""


def test_rekor_uuid_no_inner() -> None:
    class FakeEntry:
        _inner = None

    class FakeBundle:
        log_entry = FakeEntry()

    assert signing._rekor_uuid(FakeBundle()) == ""


# ── _canonical_payload ───────────────────────────────────────────────


def test_canonical_payload_is_sorted_and_compact() -> None:
    """Canonical payload should be deterministic regardless of key order."""
    evidence = _build_fixture_evidence()
    payload = evidence.to_dict()

    canonical = signing._canonical_payload(payload)
    decoded = json.loads(canonical)

    # signature and cert must be nulled
    assert decoded["agent_attestation"]["signature"] is None
    assert decoded["agent_attestation"]["cert"] is None

    # Verify it's sorted and compact (no extra whitespace)
    re_encoded = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert canonical == re_encoded


# ── MissingSigningDependencyError paths ──────────────────────────────


def test_sign_without_sigstore_raises_missing_dep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sign_envelope should raise SigningError when sigstore is missing."""
    real_import = builtins.__import__

    def block_sigstore(name, *args, **kwargs):
        if name.startswith("sigstore"):
            raise ImportError("no sigstore")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_sigstore)

    with pytest.raises(SigningError):
        sign_envelope(_build_fixture_evidence())


# ── VerificationError on malformed envelope structure ────────────────


def test_verify_envelope_with_non_dict_attestation() -> None:
    """agent_attestation as a string should raise VerificationError."""
    payload = {
        "schema": "rtp-evidence-v1",
        "agent_attestation": "not-a-dict",
    }
    with pytest.raises(VerificationError, match="missing agent_attestation"):
        verify_envelope(json.dumps(payload).encode("utf-8"))


# ── SigningError wrapping ────────────────────────────────────────────


def test_sign_envelope_wraps_missing_dep_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MissingSigningDependencyError from sigstore import should be
    wrapped as SigningError by sign_envelope."""
    from readtheplan.signing import MissingSigningDependencyError

    def raise_missing_dep(*a, **kw):
        raise MissingSigningDependencyError("install sigstore")

    monkeypatch.setattr(signing, "_sign_payload_with_sigstore", raise_missing_dep)
    with pytest.raises(SigningError, match="install sigstore"):
        sign_envelope(_build_fixture_evidence())


# ── Certificate parsing helpers ──────────────────────────────────────────


def test_certificate_identity_extracts_email_san(monkeypatch: pytest.MonkeyPatch) -> None:
    """_certificate_identity returns first email from SubjectAlternativeName."""
    x509 = _fake_x509_module(monkeypatch)

    class FakeSubject:
        rfc4514_string = lambda self: "CN=fallback"

    class FakeSAN:
        def get_values_for_type(self, typ):
            if typ is x509.RFC822Name:
                return ["first@example.com", "second@example.com"]
            if typ is x509.UniformResourceIdentifier:
                return []
            raise ValueError(typ)

    class FakeExtensions:
        def get_extension_for_class(self, cls):
            assert cls is x509.SubjectAlternativeName
            class FakeExt:
                value = FakeSAN()
            return FakeExt()

    class FakeCert:
        extensions = FakeExtensions()
        subject = FakeSubject()

    assert signing._certificate_identity(FakeCert()) == "first@example.com"


def test_certificate_identity_extracts_uri_san(monkeypatch: pytest.MonkeyPatch) -> None:
    """_certificate_identity falls back to URI SAN when no email is present."""
    x509 = _fake_x509_module(monkeypatch)

    class FakeSubject:
        rfc4514_string = lambda self: "CN=fallback"

    class FakeSAN:
        def get_values_for_type(self, typ):
            if typ is x509.RFC822Name:
                return []
            if typ is x509.UniformResourceIdentifier:
                return ["https://example.test"]
            raise ValueError(typ)

    class FakeExtensions:
        def get_extension_for_class(self, cls):
            assert cls is x509.SubjectAlternativeName
            class FakeExt:
                value = FakeSAN()
            return FakeExt()

    class FakeCert:
        extensions = FakeExtensions()
        subject = FakeSubject()

    assert signing._certificate_identity(FakeCert()) == "https://example.test"


def test_certificate_identity_falls_back_to_subject(monkeypatch: pytest.MonkeyPatch) -> None:
    """When SAN extension is absent, return cert subject RFC4514 string."""
    x509 = _fake_x509_module(monkeypatch)

    class FakeExtensions:
        def get_extension_for_class(self, cls):
            raise x509.ExtensionNotFound("not found", cls)

    class FakeSubject:
        def rfc4514_string(self):
            return "CN=subject-fallback,O=Test"

    class FakeCert:
        extensions = FakeExtensions()
        subject = FakeSubject()

    assert signing._certificate_identity(FakeCert()) == "CN=subject-fallback,O=Test"


def test_certificate_identity_falls_back_when_san_has_no_email_or_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    """SAN present but empty still falls back to subject."""
    x509 = _fake_x509_module(monkeypatch)

    class FakeSubject:
        def rfc4514_string(self):
            return "CN=no-values"

    class FakeSAN:
        def get_values_for_type(self, typ):
            return []

    class FakeExtensions:
        def get_extension_for_class(self, cls):
            class FakeExt:
                value = FakeSAN()
            return FakeExt()

    class FakeCert:
        extensions = FakeExtensions()
        subject = FakeSubject()

    assert signing._certificate_identity(FakeCert()) == "CN=no-values"


def test_certificate_oidc_issuer_extracts_first_matching_oid(monkeypatch: pytest.MonkeyPatch) -> None:
    """_certificate_oidc_issuer prefers the 1.8 OID, then 1.1."""
    x509 = _fake_x509_module(monkeypatch)
    ObjectIdentifier = x509.oid.ObjectIdentifier

    # Build a DER-encoded UTF8String for the issuer URL
    url = "https://accounts.google.com"
    der_value = bytes([0x0C, len(url)]) + url.encode("utf-8")

    class FakeExtension:
        class value:
            value = der_value

    class FakeExtensions:
        _extensions = {ObjectIdentifier("1.3.6.1.4.1.57264.1.8"): FakeExtension()}

        def get_extension_for_oid(self, oid):
            if oid in self._extensions:
                return self._extensions[oid]
            raise x509.ExtensionNotFound("not found", oid)

    class FakeCert:
        extensions = FakeExtensions()

    assert signing._certificate_oidc_issuer(FakeCert()) == url


def test_certificate_oidc_issuer_falls_back_to_second_oid(monkeypatch: pytest.MonkeyPatch) -> None:
    """When 1.8 is absent, 1.1 OID is used."""
    x509 = _fake_x509_module(monkeypatch)
    ObjectIdentifier = x509.oid.ObjectIdentifier

    url = "https://issuer.example.test"
    der_value = bytes([0x0C, len(url)]) + url.encode("utf-8")

    class FakeExtension:
        class value:
            value = der_value

    class FakeExtensions:
        _extensions = {ObjectIdentifier("1.3.6.1.4.1.57264.1.1"): FakeExtension()}

        def get_extension_for_oid(self, oid):
            if oid in self._extensions:
                return self._extensions[oid]
            raise x509.ExtensionNotFound("not found", oid)

    class FakeCert:
        extensions = FakeExtensions()

    assert signing._certificate_oidc_issuer(FakeCert()) == url


def test_certificate_oidc_issuer_returns_empty_when_no_oid(monkeypatch: pytest.MonkeyPatch) -> None:
    """When neither OID extension is present, return empty string."""
    x509 = _fake_x509_module(monkeypatch)

    class FakeExtensions:
        def get_extension_for_oid(self, oid):
            raise x509.ExtensionNotFound("not found", oid)

    class FakeCert:
        extensions = FakeExtensions()

    assert signing._certificate_oidc_issuer(FakeCert()) == ""


# ── Sigstore signing context / verifier ───────────────────────────


def test_signing_context_without_rekor_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """_signing_context delegates to SigningContext.from_trust_config."""
    calls = []

    class FakeSigningContext:
        @classmethod
        def from_trust_config(cls, trust_config):
            calls.append(("from_trust_config", trust_config))
            return "fake-context"

    fake_sigstore_sign = type("mod", (), {"SigningContext": FakeSigningContext})()
    monkeypatch.setitem(sys.modules, "sigstore.sign", fake_sigstore_sign)

    result = signing._signing_context("trusty", rekor_url=None)
    assert result == "fake-context"
    assert calls == [("from_trust_config", "trusty")]


def test_signing_context_with_custom_rekor_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """_signing_context builds a SigningContext with a custom RekorClient."""
    calls = []

    class FakeRekorClient:
        def __init__(self, url):
            calls.append(("RekorClient", url))

    class FakeSigningConfig:
        def get_fulcio(self):
            return "fulcio"
        def get_tsas(self):
            return ["tsa"]

    class FakeTrustedRoot:
        pass

    class FakeTrustConfig:
        signing_config = FakeSigningConfig()
        trusted_root = FakeTrustedRoot()

    class FakeSigningContext:
        def __init__(self, **kwargs):
            calls.append(("SigningContext", kwargs))

    fake_sign = type("mod", (), {"SigningContext": FakeSigningContext})()
    fake_rekor = type("mod", (), {"RekorClient": FakeRekorClient})()
    monkeypatch.setitem(sys.modules, "sigstore.sign", fake_sign)
    monkeypatch.setitem(
        sys.modules, "sigstore._internal.rekor.client", fake_rekor
    )

    result = signing._signing_context(FakeTrustConfig(), rekor_url="https://rekor.local")
    assert result is not None
    assert calls[0] == ("RekorClient", "https://rekor.local")
    _, kwargs = calls[1]
    assert kwargs["fulcio"] == "fulcio"
    assert kwargs["rekor"] is not None
    assert kwargs["trusted_root"] is FakeTrustConfig.trusted_root
    assert kwargs["tsa_clients"] == ["tsa"]


def test_verifier_without_rekor_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """_verifier returns Verifier.production() when no rekor_url is given."""

    class FakeVerifier:
        @classmethod
        def production(cls):
            return "production-verifier"

    fake_verify = type("mod", (), {"Verifier": FakeVerifier})()
    monkeypatch.setitem(sys.modules, "sigstore.verify", fake_verify)

    assert signing._verifier(rekor_url=None) == "production-verifier"


def test_verifier_with_custom_rekor_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """_verifier installs a custom RekorClient when rekor_url is given."""

    class FakeRekorClient:
        def __init__(self, url):
            self.url = url

    class FakeVerifier:
        @classmethod
        def production(cls):
            v = FakeVerifier()
            v._rekor = None
            return v

    fake_verify = type("mod", (), {"Verifier": FakeVerifier})()
    fake_rekor = type("mod", (), {"RekorClient": FakeRekorClient})()
    monkeypatch.setitem(sys.modules, "sigstore.verify", fake_verify)
    monkeypatch.setitem(
        sys.modules, "sigstore._internal.rekor.client", fake_rekor
    )

    verifier = signing._verifier(rekor_url="https://rekor.local")
    assert isinstance(verifier._rekor, FakeRekorClient)
    assert verifier._rekor.url == "https://rekor.local"


# ── _sign_payload_with_sigstore ───────────────────────────────────


def test_sign_payload_with_sigstore_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """_sign_payload_with_sigstore returns base64 signature and bundle JSON."""
    payload = b"payload-to-sign"

    class FakeTrustConfig:
        class signing_config:
            @staticmethod
            def get_oidc_url():
                return "https://default.oidc"

    class FakeIssuer:
        def __init__(self, url):
            self.url = url
        def identity_token(self):
            return f"token-for-{self.url}"

    class FakeBundle:
        signature = b"sig-bytes"
        def to_json(self):
            return '{"bundle":"json"}'

    class FakeSigner:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def sign_artifact(self, data):
            assert data == payload
            return FakeBundle()

    class FakeContext:
        def signer(self, token):
            assert token == "token-for-https://custom.oidc"
            return FakeSigner()
    fake_context = FakeContext()

    class FakeClientTrustConfig:
        @classmethod
        def production(cls):
            return FakeTrustConfig()

    fake_oidc = type("mod", (), {"Issuer": FakeIssuer})()
    fake_models = type("mod", (), {"ClientTrustConfig": FakeClientTrustConfig})()

    # Patch _signing_context so we don't need real sigstore.sign
    captured_context = {}
    def fake_signing_context(trust_config, *, rekor_url):
        captured_context["instance"] = trust_config
        captured_context["rekor_url"] = rekor_url
        return fake_context

    monkeypatch.setitem(sys.modules, "sigstore.models", fake_models)
    monkeypatch.setitem(sys.modules, "sigstore.oidc", fake_oidc)
    monkeypatch.setattr(signing, "_signing_context", fake_signing_context)

    signed = signing._sign_payload_with_sigstore(
        payload,
        oidc_issuer="https://custom.oidc",
        rekor_url="https://rekor.example",
    )

    assert signed.signature == base64.b64encode(b"sig-bytes").decode("ascii")
    assert signed.bundle_json == '{"bundle":"json"}'


def test_sign_payload_with_sigstore_uses_default_oidc_issuer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When oidc_issuer is None, the trust config default is used."""
    payload = b"payload"

    class FakeTrustConfig:
        class signing_config:
            @staticmethod
            def get_oidc_url():
                return "https://default.oidc"

    class FakeIssuer:
        def __init__(self, url):
            self.url = url

    class FakeBundle:
        signature = b"x"
        def to_json(self):
            return "{}"

    class FakeSigner:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def sign_artifact(self, data): return FakeBundle()

    fake_context = type("obj", (), {"signer": lambda self, token: FakeSigner()})()

    class FakeClientTrustConfig:
        @classmethod
        def production(cls): return FakeTrustConfig()

    monkeypatch.setitem(
        sys.modules, "sigstore.models",
        type("mod", (), {"ClientTrustConfig": FakeClientTrustConfig})()
    )
    monkeypatch.setitem(
        sys.modules, "sigstore.oidc",
        type("mod", (), {"Issuer": FakeIssuer})()
    )
    monkeypatch.setattr(
        signing, "_signing_context",
        lambda trust_config, *, rekor_url: fake_context
    )

    # Capture the Issuer URL passed in
    captured = {}
    original_issuer = FakeIssuer
    class CapturingIssuer:
        def __init__(self, url):
            captured["url"] = url
        def identity_token(self):
            return "token"
    monkeypatch.setitem(sys.modules, "sigstore.oidc", type("mod", (), {"Issuer": CapturingIssuer})())

    signing._sign_payload_with_sigstore(payload, oidc_issuer=None, rekor_url=None)
    assert captured["url"] == "https://default.oidc"


# ── _verify_payload_with_sigstore ──────────────────────────────────


def _make_fake_sigstore_modules(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Install fake sigstore modules and return handles."""
    state = {"verify_called": False, "verify_error": None}

    class FakePolicy:
        class Identity:
            def __init__(self, identity, issuer):
                self.identity = identity
                self.issuer = issuer

    class FakeBundle:
        def __init__(self, signature_bytes):
            self.signature = signature_bytes
            self.signing_certificate = "fake-cert"
            self.log_entry = "fake-entry"
        @classmethod
        def from_json(cls, bundle_json):
            import json as _json
            data = _json.loads(bundle_json)
            return cls(base64.b64decode(data["signature"]))

    class FakeVerifier:
        def verify_artifact(self, payload, bundle, policy):
            state["verify_called"] = True
            state["payload"] = payload
            state["bundle"] = bundle
            state["policy"] = policy
            if state["verify_error"]:
                raise state["verify_error"]

    class FakeSigstoreVerificationError(Exception):
        pass

    class FakeSigstoreError(Exception):
        pass

    fake_errors = type("mod", (), {
        "Error": FakeSigstoreError,
        "VerificationError": FakeSigstoreVerificationError,
    })()
    fake_models = type("mod", (), {"Bundle": FakeBundle})()
    fake_verify = type("mod", (), {
        "Verifier": FakeVerifier,
        "policy": FakePolicy(),
    })()

    monkeypatch.setitem(sys.modules, "sigstore.errors", fake_errors)
    monkeypatch.setitem(sys.modules, "sigstore.models", fake_models)
    monkeypatch.setitem(sys.modules, "sigstore.verify", fake_verify)

    # Patch internal helpers so we don't need real cryptography during these tests
    monkeypatch.setattr(signing, "_certificate_identity", lambda cert: "cert-identity")
    monkeypatch.setattr(signing, "_certificate_oidc_issuer", lambda cert: "cert-issuer")
    monkeypatch.setattr(signing, "_rekor_uuid", lambda bundle: "rekor-123")
    monkeypatch.setattr(signing, "_verifier", lambda *, rekor_url: FakeVerifier())

    return state


def test_verify_payload_with_sigstore_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful verification extracts identity/issuer/rekor_uuid."""
    state = _make_fake_sigstore_modules(monkeypatch)
    payload = b"signed-payload"
    signature_b64 = base64.b64encode(b"signature").decode("ascii")
    bundle_json = '{"signature":"' + signature_b64 + '"}'

    result = signing._verify_payload_with_sigstore(
        payload,
        signature=signature_b64,
        bundle_json=bundle_json,
        rekor_url=None,
        certificate_identity="expected@example.com",
        certificate_oidc_issuer="https://issuer.example.com",
    )

    assert result.ok is True
    assert result.identity == "cert-identity"
    assert result.oidc_issuer == "cert-issuer"
    assert result.rekor_uuid == "rekor-123"
    assert state["verify_called"] is True


def test_verify_payload_with_sigstore_signature_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Base64 signature not matching the bundle's raw signature returns mismatch."""
    _make_fake_sigstore_modules(monkeypatch)
    payload = b"signed-payload"
    bundle_json = '{"signature":"' + base64.b64encode(b"real-sig").decode("ascii") + '"}'

    result = signing._verify_payload_with_sigstore(
        payload,
        signature=base64.b64encode(b"different-sig").decode("ascii"),
        bundle_json=bundle_json,
        rekor_url=None,
        certificate_identity="id",
        certificate_oidc_issuer="issuer",
    )

    assert result.ok is False
    assert result.reason == "signature mismatch"


def test_verify_payload_with_sigstore_missing_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without certificate_identity/oidc_issuer, verification is skipped."""
    _make_fake_sigstore_modules(monkeypatch)

    result = signing._verify_payload_with_sigstore(
        b"payload",
        signature="c2ln",  # base64("sig") matches the bundle signature
        bundle_json='{"signature":"c2ln"}',
        rekor_url=None,
    )

    assert result.ok is False
    assert "identity verification required" in result.reason


def test_verify_payload_with_sigstore_verification_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SigstoreVerificationError is surfaced in VerificationResult.reason."""
    state = _make_fake_sigstore_modules(monkeypatch)
    from sigstore.errors import VerificationError as FakeVerificationError
    state["verify_error"] = FakeVerificationError("bad signature")

    sig_b64 = base64.b64encode(b"sig").decode("ascii")
    result = signing._verify_payload_with_sigstore(
        b"payload",
        signature=sig_b64,
        bundle_json='{"signature":"' + sig_b64 + '"}',
        rekor_url=None,
        certificate_identity="id",
        certificate_oidc_issuer="issuer",
    )

    assert result.ok is False
    assert "bad signature" in result.reason


def test_verify_payload_with_sigstore_sigstore_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generic SigstoreError is surfaced in VerificationResult.reason."""
    state = _make_fake_sigstore_modules(monkeypatch)
    from sigstore.errors import Error as FakeError
    state["verify_error"] = FakeError("network error")

    sig_b64 = base64.b64encode(b"sig").decode("ascii")
    result = signing._verify_payload_with_sigstore(
        b"payload",
        signature=sig_b64,
        bundle_json='{"signature":"' + sig_b64 + '"}',
        rekor_url=None,
        certificate_identity="id",
        certificate_oidc_issuer="issuer",
    )

    assert result.ok is False
    assert "network error" in result.reason


def test_verify_payload_with_sigstore_invalid_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ValueError/JSONDecodeError from Bundle.from_json is surfaced."""
    _make_fake_sigstore_modules(monkeypatch)

    result = signing._verify_payload_with_sigstore(
        b"payload",
        signature="c2ln",
        bundle_json="not valid json",
        rekor_url=None,
        certificate_identity="id",
        certificate_oidc_issuer="issuer",
    )

    assert result.ok is False
    # json.JSONDecodeError reason is the JSON parser message; generic fallback
    # string only appears when str(exc) is empty.
    assert result.reason is not None
    assert len(result.reason) > 0


# ── Import-error branches (missing optional deps) ──────────────────────────


def test_certificate_identity_without_cryptography_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing cryptography library should raise VerificationError."""
    real_import = builtins.__import__

    def block_crypto(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("cryptography unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_crypto)

    with pytest.raises(VerificationError, match=re.escape(SIGNING_INSTALL_HINT)):
        signing._certificate_identity("fake-cert")


def test_certificate_oidc_issuer_without_cryptography_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing cryptography library should raise VerificationError."""
    real_import = builtins.__import__

    def block_crypto(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("cryptography unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_crypto)

    with pytest.raises(VerificationError, match=re.escape(SIGNING_INSTALL_HINT)):
        signing._certificate_oidc_issuer("fake-cert")


def test_sign_payload_with_sigstore_without_sigstore_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing sigstore library should raise MissingSigningDependencyError."""
    real_import = builtins.__import__

    def block_sigstore(name, *args, **kwargs):
        if name.startswith("sigstore"):
            raise ImportError("sigstore unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_sigstore)

    with pytest.raises(signing.MissingSigningDependencyError, match=re.escape(SIGNING_INSTALL_HINT)):
        signing._sign_payload_with_sigstore(b"payload", oidc_issuer=None, rekor_url=None)


def test_signing_context_without_sigstore_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing sigstore.sign should raise MissingSigningDependencyError."""
    real_import = builtins.__import__

    def block_sigstore_sign(name, *args, **kwargs):
        if name == "sigstore.sign":
            raise ImportError("sigstore.sign unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_sigstore_sign)

    with pytest.raises(signing.MissingSigningDependencyError, match=re.escape(SIGNING_INSTALL_HINT)):
        signing._signing_context("trust-config", rekor_url=None)


def test_signing_context_without_rekor_client_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing sigstore._internal.rekor.client with custom rekor_url raises."""
    real_import = builtins.__import__

    def block_rekor(name, *args, **kwargs):
        if name == "sigstore._internal.rekor.client":
            raise ImportError("rekor client unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_rekor)

    with pytest.raises(signing.MissingSigningDependencyError, match=re.escape(SIGNING_INSTALL_HINT)):
        signing._signing_context("trust-config", rekor_url="https://rekor.local")


def test_verifier_without_sigstore_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing sigstore.verify should raise VerificationError."""
    real_import = builtins.__import__

    def block_sigstore_verify(name, *args, **kwargs):
        if name == "sigstore.verify":
            raise ImportError("sigstore.verify unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_sigstore_verify)

    with pytest.raises(VerificationError, match=re.escape(SIGNING_INSTALL_HINT)):
        signing._verifier(rekor_url=None)


def test_verifier_without_rekor_client_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing sigstore._internal.rekor.client with custom rekor_url raises."""
    real_import = builtins.__import__

    def block_rekor(name, *args, **kwargs):
        if name == "sigstore._internal.rekor.client":
            raise ImportError("rekor client unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_rekor)

    with pytest.raises(VerificationError, match=re.escape(SIGNING_INSTALL_HINT)):
        signing._verifier(rekor_url="https://rekor.local")


def test_verify_payload_with_sigstore_without_sigstore_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing sigstore verification deps should raise VerificationError."""
    real_import = builtins.__import__

    def block_sigstore(name, *args, **kwargs):
        if name.startswith("sigstore"):
            raise ImportError("sigstore unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_sigstore)

    with pytest.raises(VerificationError, match=re.escape(SIGNING_INSTALL_HINT)):
        signing._verify_payload_with_sigstore(
            b"payload",
            signature="sig",
            bundle_json='{}',
            rekor_url=None,
        )

