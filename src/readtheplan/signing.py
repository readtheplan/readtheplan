from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, cast

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
from sigstore.errors import Error as SigstoreError
from sigstore.errors import VerificationError as SigstoreVerificationError
from sigstore.models import Bundle, ClientTrustConfig
from sigstore.oidc import Issuer
from sigstore.sign import SigningContext
from sigstore.verify import Verifier, policy

from readtheplan.evidence import EVIDENCE_SCHEMA, EvidenceEnvelope


class SigningError(ValueError):
    """Raised when signing fails."""


class VerificationError(ValueError):
    """Raised when evidence verification input is malformed."""


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    identity: str
    oidc_issuer: str
    rekor_uuid: str
    reason: str | None = None


@dataclass(frozen=True)
class _SignedPayload:
    signature: str
    bundle_json: str


class _BundleLike(Protocol):
    @property
    def signature(self) -> bytes: ...

    @property
    def signing_certificate(self) -> x509.Certificate: ...

    @property
    def log_entry(self) -> Any: ...

    def to_json(self) -> str: ...


def sign_envelope(
    envelope: EvidenceEnvelope,
    *,
    oidc_issuer: str | None = None,
    rekor_url: str | None = None,
) -> dict[str, Any]:
    """Sign the envelope and return the signed envelope dict."""

    payload = envelope.to_dict()
    signed = _json_copy(payload)
    try:
        signed_payload = _sign_payload_with_sigstore(
            _canonical_payload(payload),
            oidc_issuer=oidc_issuer,
            rekor_url=rekor_url,
        )
    except Exception as exc:
        raise SigningError(str(exc)) from exc

    attestation = _agent_attestation(signed)
    attestation["signature"] = signed_payload.signature
    attestation["cert"] = signed_payload.bundle_json
    return signed


def verify_envelope(
    envelope_bytes: bytes,
    *,
    rekor_url: str | None = None,
) -> VerificationResult:
    """Verify a signed rtp-evidence-v1 envelope."""

    payload = _load_envelope(envelope_bytes)
    if payload.get("schema") != EVIDENCE_SCHEMA:
        raise VerificationError(
            f"unsupported evidence schema: {payload.get('schema')!r}"
        )

    attestation = _agent_attestation(payload)
    signature = attestation.get("signature")
    bundle_json = attestation.get("cert")
    if not isinstance(signature, str) or not signature:
        return VerificationResult(
            ok=False,
            identity="",
            oidc_issuer="",
            rekor_uuid="",
            reason="unsigned envelope",
        )
    if not isinstance(bundle_json, str) or not bundle_json:
        return VerificationResult(
            ok=False,
            identity="",
            oidc_issuer="",
            rekor_uuid="",
            reason="unsigned envelope",
        )

    canonical_payload = _canonical_payload(payload)
    return _verify_payload_with_sigstore(
        canonical_payload,
        signature=signature,
        bundle_json=bundle_json,
        rekor_url=rekor_url,
    )


def _canonical_payload(payload: Mapping[str, Any]) -> bytes:
    canonical = _json_copy(payload)
    attestation = _agent_attestation(canonical)
    attestation["signature"] = None
    attestation["cert"] = None
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_payload_with_sigstore(
    payload: bytes,
    *,
    oidc_issuer: str | None,
    rekor_url: str | None,
) -> _SignedPayload:
    trust_config = ClientTrustConfig.production()
    issuer = Issuer(oidc_issuer or trust_config.signing_config.get_oidc_url())
    context = _signing_context(trust_config, rekor_url=rekor_url)
    identity_token = issuer.identity_token()

    with context.signer(identity_token) as signer:
        bundle = cast(_BundleLike, signer.sign_artifact(payload))

    return _SignedPayload(
        signature=base64.b64encode(bundle.signature).decode("ascii"),
        bundle_json=bundle.to_json(),
    )


def _verify_payload_with_sigstore(
    payload: bytes,
    *,
    signature: str,
    bundle_json: str,
    rekor_url: str | None,
) -> VerificationResult:
    try:
        bundle = Bundle.from_json(bundle_json)
        if base64.b64encode(bundle.signature).decode("ascii") != signature:
            return VerificationResult(
                ok=False,
                identity="",
                oidc_issuer="",
                rekor_uuid="",
                reason="signature mismatch",
            )
        verifier = _verifier(rekor_url=rekor_url)
        verifier.verify_artifact(payload, bundle, policy.UnsafeNoOp())
    except SigstoreVerificationError as exc:
        return VerificationResult(
            ok=False,
            identity="",
            oidc_issuer="",
            rekor_uuid="",
            reason=str(exc) or "signature verification failed",
        )
    except SigstoreError as exc:
        return VerificationResult(
            ok=False,
            identity="",
            oidc_issuer="",
            rekor_uuid="",
            reason=str(exc) or "sigstore verification failed",
        )
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return VerificationResult(
            ok=False,
            identity="",
            oidc_issuer="",
            rekor_uuid="",
            reason=str(exc) or "invalid sigstore bundle",
        )

    bundle_like = cast(_BundleLike, bundle)
    return VerificationResult(
        ok=True,
        identity=_certificate_identity(bundle_like.signing_certificate),
        oidc_issuer=_certificate_oidc_issuer(bundle_like.signing_certificate),
        rekor_uuid=_rekor_uuid(bundle_like),
    )


def _signing_context(
    trust_config: ClientTrustConfig,
    *,
    rekor_url: str | None,
) -> SigningContext:
    if not rekor_url:
        return SigningContext.from_trust_config(trust_config)

    from sigstore._internal.rekor.client import RekorClient

    signing_config = trust_config.signing_config
    return SigningContext(
        fulcio=signing_config.get_fulcio(),
        rekor=RekorClient(rekor_url),
        trusted_root=trust_config.trusted_root,
        tsa_clients=signing_config.get_tsas(),
    )


def _verifier(*, rekor_url: str | None) -> Verifier:
    verifier = Verifier.production()
    if rekor_url:
        from sigstore._internal.rekor.client import RekorClient

        verifier._rekor = RekorClient(rekor_url)
    return verifier


def _load_envelope(envelope_bytes: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(envelope_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid evidence JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise VerificationError("evidence envelope must be a JSON object")
    return cast(dict[str, Any], payload)


def _agent_attestation(payload: Mapping[str, Any]) -> dict[str, Any]:
    raw_attestation = payload.get("agent_attestation")
    if not isinstance(raw_attestation, dict):
        raise VerificationError("evidence envelope missing agent_attestation object")
    return cast(dict[str, Any], raw_attestation)


def _json_copy(payload: Mapping[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(json.dumps(payload)))


def _certificate_identity(cert: x509.Certificate) -> str:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return cert.subject.rfc4514_string()

    emails = san.get_values_for_type(x509.RFC822Name)
    if emails:
        return emails[0]
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if uris:
        return uris[0]
    return cert.subject.rfc4514_string()


def _certificate_oidc_issuer(cert: x509.Certificate) -> str:
    for oid in (
        ObjectIdentifier("1.3.6.1.4.1.57264.1.8"),
        ObjectIdentifier("1.3.6.1.4.1.57264.1.1"),
    ):
        try:
            extension = cert.extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound:
            continue
        value = cast(x509.UnrecognizedExtension, extension.value).value
        return _decode_der_string(value)
    return ""


def _decode_der_string(value: bytes) -> str:
    if len(value) >= 2 and value[0] in {0x0C, 0x16}:
        length = value[1]
        if len(value) >= 2 + length:
            return value[2 : 2 + length].decode("utf-8", errors="replace")
    return value.decode("utf-8", errors="replace")


def _rekor_uuid(bundle: _BundleLike) -> str:
    entry = bundle.log_entry
    inner = getattr(entry, "_inner", None)
    uuid = getattr(inner, "uuid", None)
    if uuid:
        return str(uuid)
    log_index = getattr(inner, "log_index", None)
    if log_index is not None:
        return str(log_index)
    return ""
