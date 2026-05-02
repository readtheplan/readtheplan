# ADR 0008: Signed Attestation

## Status

Proposed

## Context

ADR 0007 introduced the `rtp-evidence-v1` JSON envelope: one stable
document per analyze run that wraps plan hash + framework view +
controls touched + change list + agent attestation. The
`agent_attestation.signature` field exists in the schema but is always
`null` because nothing signs the envelope yet.

Without a signature, the envelope is *evidence shaped* but not *evidence
trusted*. Anyone can hand-edit the JSON and the contents are no longer
verifiable. Auditors and GRC integrations want a tamper-evident artifact —
they need to know the envelope they're consuming was produced by a known
agent against a specific plan SHA, and hasn't been touched since.

The realistic options for signing infrastructure-change evidence:

1. **Long-lived static keys** (PGP, raw RSA, Ed25519). Simple but
   key-management is the well-known weakest link of audit-trail systems.
   Auditors don't love static keys for AI-agent contexts because key
   rotation and leak-recovery procedures are usually missing.
2. **Sigstore keyless OIDC signing** (`cosign sign-blob` model). Short-lived
   identity-bound keys, automatic Rekor transparency-log entry, no
   long-lived secrets to rotate or revoke. Open standard backed by Linux
   Foundation. Verification is `cosign verify-blob` plus a Rekor lookup.
3. **DSSE / in-toto** (Supply-chain Levels for Software Artifacts —
   SLSA). More complex, more general; built for build-provenance use
   cases. Overkill for our payload shape today.
4. **JWS / JWT with org-controlled keys**. Familiar, but again imposes
   key-management burden on the user.

## Decision

Adopt **sigstore keyless signing** as the signature mechanism for v1
evidence envelopes, and add a `verify` subcommand to the CLI.

Implementation outline:

- New module `src/readtheplan/signing.py` with two operations:
  - `sign_envelope(envelope: EvidenceEnvelope, *, identity: str | None = None) -> SignedEnvelope`
  - `verify_envelope(envelope_json: bytes) -> VerificationResult`
- New CLI flag `--sign` on `analyze` (requires `--evidence`). When set,
  the evidence file written contains the signature embedded in
  `agent_attestation.signature` and the bundle/cert in a sibling
  `agent_attestation.cert` field.
- New CLI subcommand `readtheplan verify <evidence.json>`. Reads the
  envelope, verifies the signature against Sigstore's Rekor transparency
  log, prints a one-line PASS/FAIL plus the signing identity. Exits
  non-zero on FAIL.
- The signature covers a canonical JSON serialization of the envelope
  with `signature` and `cert` fields nulled — i.e., the signature is
  computed over the rest of the envelope, then inserted. This is the
  same pattern DSSE uses; we don't adopt DSSE format itself, just the
  "sign over the document with the signature field nulled" technique.

### Sigstore client choice

Use the **`sigstore` Python package** (PyPI: `sigstore`, maintained by
the Sigstore project). It's the upstream-blessed Python implementation
with parity for the keyless flow that `cosign sign-blob`/`verify-blob`
offers. **Pin to `sigstore>=4.0,<5`** — current major release on PyPI
is 4.x as of this ADR. (The earlier 3.x pin was a typo from my draft;
Codex caught it before implementation. Documented here so the next
ADR review knows why this number exists.)

The v4 public API uses `SigningContext` + `Signer.sign_artifact()` for
signing and `Verifier.verify_artifact(input_, bundle, policy)` for
verification, with a `Bundle` object carrying signature + cert + Rekor
entry. This ADR's pseudocode is intentionally light on import paths —
follow the upstream package's actual public API documented at
[sigstore-python](https://sigstore.github.io/sigstore-python/api/sign/).

This is the **first new runtime dependency** since PyYAML in PR #3.
PyYAML was justified by readable catalog data; sigstore is justified by
the entire premise of signed attestation. Reviewers should understand
this is a deliberate, narrow expansion.

### Identity model

Keyless signing requires an OIDC identity. Three contexts:

- **CI (GitHub Actions / GitLab CI)**: the workflow's OIDC identity
  is supplied automatically. No user setup required. Identity in the
  signed envelope reads e.g.
  `https://github.com/readtheplan/readtheplan/.github/workflows/test-action.yml@refs/heads/main`.
- **Local human**: `sigstore` package supports the OAuth flow against
  Sigstore's public Fulcio instance (sign-in via Google / GitHub /
  Microsoft). One browser dance per session.
- **Custom OIDC issuer**: organizations running their own Fulcio +
  Rekor (e.g. for confidentiality) configure via `--oidc-issuer` and
  `--rekor-url` flags. Defaults are the public Sigstore instances.

The signing identity is recorded in `agent_attestation.cert` (the X.509
cert subject) and verified by `verify` against expected identity
patterns. The CLI does **not** hard-code expected identities — `verify`
prints the identity and lets the consumer (CI, GRC) decide whether
it's trusted.

### Schema impact on `rtp-evidence-v1`

Backwards-compatible: the existing `agent_attestation.signature` field
flips from always-`null` to "a base64-encoded signature when signed,
`null` when unsigned." A new sibling `agent_attestation.cert` field is
added (the X.509 cert chain). Both fields are optional in `v1`; an
unsigned envelope (signature `null`, cert absent) remains valid and
identical to today's output.

This is *not* a breaking change. Tools that key off `signature ==
null` continue to work. Tools that want signature verification check
for `signature != null` first.

### Verification semantics

`readtheplan verify <envelope.json>`:

1. Read and parse the envelope. Reject if `schema != "rtp-evidence-v1"`.
2. Extract `signature` and `cert`. If either is missing, exit non-zero
   with `unsigned envelope`.
3. Reconstruct the canonical signing payload by replacing
   `signature` and `cert` with `null` in the envelope, then
   serializing with sorted keys + compact JSON.
4. Verify the signature against the cert via `sigstore.verify`.
5. Verify the cert chains to Sigstore's Fulcio root.
6. Verify the Rekor transparency log entry exists for this signature.
7. On success, print one line:
   `OK identity=<cert_subject> issuer=<oidc_issuer> rekor_uuid=<uuid>`
   and exit 0.
8. On any failure, print a one-line reason and exit 1.

The verify command is **read-only**. It never modifies the envelope, and
it never reaches out to anything except Sigstore's public infrastructure
(Fulcio, Rekor) by default.

### Out of scope for this ADR

- **DSSE / in-toto bundle format.** Future ADR may convert evidence to
  DSSE for compatibility with SLSA-level downstream consumers; not
  required for v1.
- **Multi-signer** (e.g., agent + human reviewer co-sign). One signer per
  envelope in v1.
- **Custom transparency log.** Use Rekor public instance only.
- **Offline verification** (verify without Rekor reachability). Online
  verify only in v1; offline verify is a separate ADR.
- **Signature rotation** / re-signing of historical envelopes. v1
  envelopes are point-in-time; if a signing identity is compromised,
  the response is to re-issue the evidence at the new identity, not
  to re-sign old envelopes.
- **Hardware-backed identities** (TPM, HSM). Out of scope; sigstore
  handles ephemeral keys via Fulcio.
- **PR-comment rendering of verification results.** CI integrations
  bolt onto `verify`'s exit code and one-line output later.

## Consequences

### Positive

- The first version of readtheplan that ships *trustworthy* evidence,
  not just well-shaped evidence. Auditors can verify the document
  themselves with public-Sigstore infrastructure.
- No long-lived keys for the user to manage. CI gets identity for free
  via GitHub Actions OIDC; humans use one OAuth flow per local session.
- Schema stays backwards compatible — unsigned envelopes still work.
- Sets up the GRC-platform integration story: a Vanta / Drata webhook
  can carry the signed envelope and the receiver can verify cryptographically.

### Negative

- New runtime dependency on `sigstore` (~30 transitive deps including
  `cryptography`, `securesystemslib`). Heavier install footprint.
  Mitigation: pin upper bound (`<4`), vendor in CI test runs, document
  the install size in README.
- Online verify requires Sigstore public infrastructure to be
  reachable. If Rekor is down, verify fails. Mitigation: out-of-scope
  offline-verify ADR for later.
- Auditor opinions on Sigstore vary. Some compliance frameworks
  (FedRAMP High, certain PCI assessments) may not accept Sigstore as
  the sole signature authority yet. Mitigation: design accepts custom
  OIDC issuers / private Rekor for organizations that need them.
- One more CLI surface (`verify`) to maintain.

### Maintenance contract

- The signing payload definition (envelope with `signature` and `cert`
  nulled, sorted-keys compact JSON) is part of the v1 schema contract.
  Changing how the payload is canonicalized is a v2 schema bump.
- `sigstore` package version pin (`>=4.0,<5`) is review