# Codex task — ADR 0008 signed attestation (sigstore)

**Authoring agent:** Cowork (Claude)
**Implementation agent:** Codex
**Reviewer:** Cowork (Claude), via the `engineering:code-review` skill
**Branch:** `codex/readtheplan-signed-attestation`
**Commit trailer:** `AI-Assisted: Codex`
**Reference ADR:** [`docs/adr/0008-signed-attestation.md`](../adr/0008-signed-attestation.md)

---

## Goal

Land sigstore keyless signing for `rtp-evidence-v1` envelopes plus a
`verify` subcommand. The envelope's `agent_attestation.signature` field
flips from always-`null` to a real base64 signature when `--sign` is
passed; a sibling `cert` field carries the X.509 cert chain.
`readtheplan verify <envelope>` checks the signature against Sigstore's
Fulcio root and Rekor transparency log.

ADR 0008 is the source of truth. If anything in this brief contradicts
the ADR, the ADR wins; stop and write up the issue.

---

## Inputs already on main (read-only for this task)

- `docs/adr/0008-signed-attestation.md` — the ADR.
- `src/readtheplan/evidence.py` — `EvidenceEnvelope`, `build_evidence`,
  `EvidenceError`, `EVIDENCE_SCHEMA`. Read-only.
- `src/readtheplan/attestation.py` — `PlanReadAttestation` and helpers.
  Read-only.
- `src/readtheplan/cli.py` — modify only the new flag and subcommand
  plumbing; do not refactor existing `_analyze` beyond minimal additions.

The schema impact on `rtp-evidence-v1` is documented in ADR 0008
§"Schema impact on `rtp-evidence-v1`": new optional `cert` field added
to `agent_attestation`, `signature` field flips meaning. Both fields
are still optional; an unsigned envelope is identical to today's
output. **Do not modify `evidence.py`'s public surface or its
`EvidenceEnvelope` dataclass** — the cert and signature flow through
`agent_attestation` (which is already a `Mapping[str, Any]`).

---

## Files you will write

```
src/readtheplan/signing.py                     (new — sigstore wrapper)
src/readtheplan/cli.py                         (modify — add --sign + verify subcommand)
pyproject.toml                                 (modify — add sigstore dep)
tests/test_signing.py                          (new)
tests/fixtures/signed_envelope.json            (new — pre-signed fixture for verify tests)
tests/fixtures/unsigned_envelope.json          (new — for verify-fails-on-unsigned test)
tests/fixtures/tampered_envelope.json          (new — for verify-fails-on-tamper test)
README.md                                      (modify — short subsection)
```

No other files. Do **not** modify `evidence.py`, `attestation.py`,
`controls.py`, `plan.py`, or `rules.py`. The signing layer wraps
`evidence.py`'s output; it does not restructure it.

---

## Module: `src/readtheplan/signing.py`

### Public surface

```python
from __future__ import annotations
from dataclasses import dataclass

from readtheplan.evidence import EvidenceEnvelope

class SigningError(ValueError):
    """Raised when signing fails (e.g. OIDC unavailable, network)."""

class VerificationError(ValueError):
    """Raised when verification fails (signature mismatch, cert chain
    invalid, Rekor entry missing, schema wrong, payload tampered)."""

@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    identity: str            # cert subject, e.g. "alice@example.com"
    oidc_issuer: str         # e.g. "https://accounts.google.com"
    rekor_uuid: str          # transparency-log entry UUID
    reason: str | None = None  # populated when ok=False

def sign_envelope(
    envelope: EvidenceEnvelope,
    *,
    oidc_issuer: str | None = None,   # default: sigstore public
    rekor_url: str | None = None,     # default: sigstore public Rekor
) -> dict[str, Any]:
    """Sign the envelope and return the envelope-as-dict with
    agent_attestation.signature and agent_attestation.cert populated.

    Internally:
    - Build canonical signing payload (envelope dict with
      agent_attestation.signature and agent_attestation.cert nulled,
      sorted keys, compact JSON, UTF-8 encoded).
    - Call sigstore.sign on the payload bytes.
    - Insert returned signature (base64) and cert chain (PEM, single
      string) back into agent_attestation.
    - Return the resulting dict.
    """

def verify_envelope(
    envelope_bytes: bytes,
    *,
    rekor_url: str | None = None,
) -> VerificationResult:
    """Verify a signed envelope.

    Reads the envelope from bytes, reconstructs the canonical signing
    payload (signature/cert nulled), verifies signature against cert,
    verifies cert chains to Fulcio root, verifies Rekor entry. Returns
    a VerificationResult with ok=True on success, ok=False with a
    populated reason on failure.

    Raises VerificationError only on programming errors (e.g. malformed
    JSON, schema != rtp-evidence-v1). Signature/cert/Rekor failures
    return ok=False rather than raising — they're expected failure
    modes that callers want to handle gracefully.
    """
```

### Canonical signing payload

The payload that gets signed is constructed exactly this way:

1. Start with `envelope.to_dict()`.
2. Inside the resulting dict, set `agent_attestation.signature = None`
   and `agent_attestation.cert = None`. (The envelope as produced by
   `build_evidence` already has signature=None; cert never existed
   on unsigned envelopes. The point is to be defensive: even if
   pre-existing values are present, they're nulled before signing.)
3. Serialize with `json.dumps(payload, sort_keys=True, separators=(",", ":"))`.
4. Encode UTF-8.

Verifying does the same construction and compares. **This is part of
the v1 schema contract** — changing canonicalization is a v2 schema
bump.

### Imports

```python
from sigstore.sign import Signer
from sigstore.verify import Verifier, VerificationMaterials
# (use whichever entry points sigstore>=3.0 exposes; the ADR pins
# the major version, so import paths must be valid for sigstore 3.x)
```

If the `sigstore` package's import path differs from the above sketch,
follow the package's actual public API. Document any departure in the
PR description.

---

## CLI changes — `src/readtheplan/cli.py`

### `--sign` flag (on `analyze`)

```
--sign                Sign the evidence envelope using sigstore keyless
                      signing. Requires --evidence.

--oidc-issuer URL     OIDC issuer for sigstore signing. Defaults to
                      sigstore public.

--rekor-url URL       Rekor transparency log URL. Defaults to
                      sigstore public.
```

Behavior:

- `--sign` without `--evidence` exits non-zero with
  `"Error: --sign requires --evidence"`. No traceback.
- When `--sign` and `--evidence` are both set, after `build_evidence`
  the CLI calls `sign_envelope(envelope, oidc_issuer=..., rekor_url=...)`
  and writes the *signed* dict (returned by `sign_envelope`) to the
  evidence path or stdout — replacing the unsigned write.
- Signing failure (`SigningError`) exits non-zero with
  `f"Error: sign failed: {exc}"`. No traceback.

### `verify` subcommand

```
readtheplan verify [--rekor-url URL] <envelope.json>
```

Behavior:

- Reads the file at `<envelope.json>`. Calls `verify_envelope` with
  the bytes.
- On `ok=True`: prints
  `f"OK identity={result.identity} issuer={result.oidc_issuer} rekor_uuid={result.rekor_uuid}"`
  and exits 0.
- On `ok=False`: prints
  `f"FAIL {result.reason}"` to stderr and exits 1.
- On `VerificationError` (programming/format error): prints
  `f"Error: {exc}"` to stderr and exits 1. No traceback.

Wire the subcommand under the existing `subparsers` dispatch (next to
`analyze`).

---

## `pyproject.toml` changes

Add `sigstore>=3.0,<4` to `[project.dependencies]`. Keep the existing
`PyYAML>=6.0` dep.

The full `dependencies` line should look something like:

```toml
dependencies = ["PyYAML>=6.0", "sigstore>=3.0,<4"]
```

If the actual published `sigstore` major version on PyPI today is not
`3.x`, pin to whatever the current major is (`>=N.0,<N+1`) and call it
out in the PR description so we can revisit the ADR's pin guidance.

---

## Test fixtures

Three fixture files under `tests/fixtures/`:

1. **`signed_envelope.json`** — A pre-signed envelope produced by running
   `sign_envelope` once during fixture generation against the existing
   `evidence_plan.json`. To produce it deterministically for the test
   suite, you have two options:

   **Option A:** Sign with a fresh local keypair (use `sigstore`'s
   non-keyless mode if available, or fall back to a local Ed25519 key)
   and bundle the public key alongside. **Recommended** since CI
   doesn't have OIDC identity by default and this lets tests run
   offline.

   **Option B:** Mock the sigstore client at test time and inject
   pre-canned signature bytes. Cleaner test isolation but more mocking.

   Pick whichever makes the test suite hermetic. Document the choice
   in the PR.

2. **`unsigned_envelope.json`** — An envelope with
   `agent_attestation.signature = null` and no `cert` field. Used to
   verify that `verify` correctly rejects unsigned input.

3. **`tampered_envelope.json`** — Take `signed_envelope.json` and modify
   one field (e.g., a `change.address` string). The signature should
   no longer verify. Used to verify the canonicalization actually
   covers the data.

---

## Tests — `tests/test_signing.py`

Required test cases. Names and intent are fixed; style is yours.

```python
# 1. Round-trip: sign then verify a freshly-built envelope.
def test_sign_then_verify_roundtrip():
    # build_evidence -> sign_envelope -> verify_envelope -> ok=True

# 2. verify_envelope on the unsigned fixture returns ok=False.
def test_verify_unsigned_envelope_fails():

# 3. verify_envelope on the tampered fixture returns ok=False.
#    The reason string mentions signature mismatch.
def test_verify_tampered_envelope_fails():

# 4. verify_envelope on a malformed (non-JSON) input raises
#    VerificationError, not ok=False.
def test_verify_malformed_input_raises():

# 5. verify_envelope rejects schema != "rtp-evidence-v1".
def test_verify_wrong_schema_raises():

# 6. Canonicalization: signing payload is identical regardless of
#    field order in the input envelope dict.
def test_canonical_payload_order_invariant():
    # Build the same envelope twice with different dict insertion
    # orders for agent_attestation, sign each, verify both pass.

# 7. Signature does not depend on the prior value of signature/cert
#    fields (the canonicalizer nulls them before signing).
def test_canonicalization_nulls_signature_and_cert():

# 8. CLI: --sign without --evidence exits non-zero with helpful
#    message.
def test_cli_sign_requires_evidence(capsys):

# 9. CLI: analyze --evidence <path> --sign writes a signed envelope
#    file. Verify reads it back as ok.
def test_cli_sign_writes_signed_envelope(tmp_path):

# 10. CLI: verify <envelope> on signed_envelope.json prints OK and
#     exits 0.
def test_cli_verify_signed_envelope(capsys):

# 11. CLI: verify <envelope> on unsigned_envelope.json prints FAIL
#     and exits 1.
def test_cli_verify_unsigned_envelope(capsys):

# 12. CLI: verify on a non-existent file exits non-zero with a clear
#     message (not a Python traceback).
def test_cli_verify_missing_file(capsys):

# 13. SigningError flows through to a non-zero exit with a clear
#     message (mock sigstore to raise; assert no traceback).
def test_cli_sign_failure_message(capsys, monkeypatch):

# 14. VerificationResult round-trip: ok=True case has all four fields
#     populated; ok=False case has reason populated.
def test_verification_result_field_population():
```

The full pytest suite (existing 61 + 14 new = 75) must pass on Python
3.10 and 3.13. CI already covers both.

If sigstore signing requires network access at test time and CI is
blocked, the test must be skipped via `pytest.mark.skipif` rather than
left to fail. Tests that exercise the canonicalization layer must
*not* require network — they should use mocked or pre-canned signature
bytes.

---

## README changes

Add a new subsection after "Evidence envelope (preview)":

```markdown
### Signed attestation (preview)

Add `--sign` to write a sigstore-signed evidence envelope:

```bash
readtheplan analyze --framework soc2 \
                    --evidence evidence.json \
                    --sign \
                    plan.json
```

In CI, the workflow's OIDC identity is used automatically. Locally,
`sigstore` opens a browser for one-time OAuth.

Verify a signed envelope:

```bash
readtheplan verify evidence.json
# OK identity=alice@example.com issuer=https://accounts.google.com rekor_uuid=...
```

`verify` exits 0 on success, 1 on any failure (unsigned, tampered,
schema wrong, signature mismatch, Rekor entry missing). See
`docs/adr/0008-signed-attestation.md` for the full schema and
verification semantics.

```

Keep the (preview) heading, no marketing copy.

---

## Out of scope (do not add)

- DSSE / in-toto bundle format.
- Multi-signer (agent + reviewer co-sign).
- Custom transparency log (private Rekor) wiring beyond accepting
  `--rekor-url`.
- Offline verification.
- Signature rotation / re-signing.
- Hardware-backed identities (TPM, HSM).
- PR-comment rendering of verification results.
- Modifying `evidence.py`, `attestation.py`, `controls.py`, `plan.py`,
  `rules.py`.
- Any new runtime dependency beyond `sigstore` itself.

If a follow-on idea looks unavoidable to land this slice, write it as
a TODO in the PR description and continue without it.

---

## Acceptance / definition of done

- [ ] All 14 listed tests pass on Python 3.10 and 3.13.
- [ ] Existing 61 pytest tests still pass with no modifications.
- [ ] `mypy --strict src/readtheplan/signing.py src/readtheplan/cli.py`
      passes.
- [ ] `ruff check` / `black --check` clean per existing project style.
- [ ] `readtheplan analyze --help` shows the new `--sign`,
      `--oidc-issuer`, `--rekor-url` flags.
- [ ] `readtheplan --help` shows the new `verify` subcommand.
- [ ] `readtheplan verify --help` shows `--rekor-url` and the positional
      file argument.
- [ ] PyPI install of the package picks up `sigstore>=3.0,<4` (verify in
      a fresh venv).
- [ ] PR description maps each substantive decision back to ADR 0008
      sections and lists anything skipped vs. the brief.
- [ ] Commit message includes `AI-Assisted: Codex` trailer.
- [ ] PR is opened against `main` from
      `codex/readtheplan-signed-attestation`.

---

## Review handoff

When the PR is open and CI is green, comment `@cowork ready for review`.
Cowork will review using the `engineering:code-review` skill, with these
specific checks:

1. **Layering**: `evidence.py`, `attestation.py`, `controls.py`,
   `plan.py`, `rules.py` all untouched. (ADR 0008 §"Decision" — signing
   wraps the envelope, doesn't modify it.)
2. **Backwards compatibility**: an unsigned envelope produced by
   `build_evidence` (no `--sign`) is byte-identical to PR #6's output.
   `signature` stays `null`, `cert` field absent.
3. **Canonicalization fidelity**: signing payload is `signature`-and-
   `cert`-nulled, sorted-keys, compact JSON, UTF-8. Test 6 and 7
   exercise this.
4. **Verify exit codes**: 0 on OK, 1 on any failure mode (unsigned,
   tampered, schema wrong, malformed, missing file). No tracebacks
   reach stderr.
5. **Dependency hygiene**: only `sigstore>=3.0,<4` added; no other new
   runtime deps; pin lower and upper bounds.

Cowork will request changes inline; expected total review turnaround
is under one full pass.

---

## Risk callouts (read this before starting)

- **Sigstore upstream API may differ.** The brief sketches imports as
  `from sigstore.sign import Signer`; the actual public API in
  `sigstore>=3.0` may use different entry points. Follow the upstream
  package's actual API, document the mapping in the PR.

- **Network in tests.** Sigstore keyless requires Fulcio + Rekor
  reachability. CI may or may not have egress. Strategy:
  - Tests that exercise canonicalization, schema, and CLI plumbing
    must be hermetic (no network).
  - Tests that exercise actual sign+verify round-trip can be marked
    `@pytest.mark.skipif(no_network)`.
  - Pre-signed fixtures are the bridge — they let verify-side tests
    run offline without skipping.

- **OIDC identity in tests.** Avoid requiring real OIDC. Use sigstore's
  test/staging mode or mock the signer. Document the choice.

- **Fixture generation.** The `signed_envelope.json` fixture must be
  produced reproducibly by something other than a one-off "I ran
  cosign once and committed the output." Either deterministic local
  signing or mocked signature bytes. Document the choice in the PR;
  reviewers want to see the fixture is regenerable.
