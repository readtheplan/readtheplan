# Codex launch prompt — task 0005 (signed attestation)

Paste the block below into Codex as a single message to start the
ADR 0008 signed attestation implementation. Companion brief at
[`codex-task-0005-signed-attestation.md`](codex-task-0005-signed-attestation.md).

---

You are picking up the third compliance wedge on the readtheplan repo
(https://github.com/readtheplan/readtheplan), checked out at
`C:\Users\admin\Documents\coding\readtheplan`.

Cowork (Claude) has already written ADR 0008 and a self-contained
task brief. This PR adds a new module — `signing.py` — that wraps
the existing `rtp-evidence-v1` envelope with sigstore keyless
signing, plus a `readtheplan verify <envelope>` subcommand.

This is the largest of the three compliance wedges. Read carefully
before starting; the brief includes risk callouts about sigstore's
upstream API and CI network constraints that you should plan for
before writing code.

Read these files first, in this order:

1. `docs/handoff/codex-task-0005-signed-attestation.md`
   Your task brief. Source of truth. Includes risk callouts at the
   bottom — read those.
2. `docs/adr/0008-signed-attestation.md`
   The design decisions the brief implements. Includes the schema
   impact on `rtp-evidence-v1` and the verification semantics.
3. `src/readtheplan/evidence.py`
   The envelope you're wrapping. Read-only.
4. `src/readtheplan/attestation.py`
   Existing attestation module. Read-only.

Then execute:

- Cut branch: `codex/readtheplan-signed-attestation` (from `main`).
- Write exactly the files listed under the brief's "Files you will
  write" section. No others.
- Do NOT modify `evidence.py`, `attestation.py`, `controls.py`,
  `plan.py`, or `rules.py`. ADR 0008's layering contract forbids it.
- Implement `signing.py` with the public surface specified in the
  brief (`SigningError`, `VerificationError`, `VerificationResult`,
  `sign_envelope`, `verify_envelope`).
- Add `--sign`, `--oidc-issuer`, `--rekor-url` flags to `analyze`.
  Behavior per the brief.
- Add the `verify` subcommand to `cli.py`'s subparser dispatch.
- Add `sigstore>=4.0,<5` to `pyproject.toml` `[project.dependencies]`.
  Pin verified against PyPI's current 4.x major during the brief
  revision. Keep this pin unless there's been another major bump
  between now and your implementation.
- Generate the three test fixtures (`signed_envelope.json`,
  `unsigned_envelope.json`, `tampered_envelope.json`) reproducibly.
  Document fixture generation in the PR.
- Add the 14 named tests to `tests/test_signing.py`. The names and
  intent are fixed; style is yours.
- Update `README.md` with the new "Signed attestation (preview)"
  subsection per the brief's sketch.

Quality gates (all must pass before opening the PR):

- pytest passes on Python 3.10 and 3.13: existing 61 tests + 14 new
  tests. Network-dependent tests must be `@pytest.mark.skipif`-gated,
  not failing.
- ruff/black/mypy --strict clean for new + modified Python files.
- `readtheplan analyze --help` shows the new flags.
- `readtheplan --help` shows the new `verify` subcommand.
- A fresh-venv install picks up `sigstore>=4.0,<5`.
- Each commit ends with the trailer: `AI-Assisted: Codex`.

If anything in the brief looks wrong, contradicts the ADR, the
upstream sigstore API differs from the brief's revised v4 sketch
(SigningContext + Signer.sign_artifact, Verifier.verify_artifact
with Bundle), or any risk-callout situation arises that needs a
design call — stop, do not work around it. Reply with a short
PR-style write-up of the issue and wait. The risk callouts at the
bottom of the brief are specifically asking you to flag deviations
rather than guess.

This is the second iteration of this brief; the first was blocked
on a pin/API drift that has now been corrected. Thanks for catching
it. The same handshake applies if anything else surfaces.

Open the PR against `main` from
`codex/readtheplan-signed-attestation`. PR description must:

- Map each substantive decision back to ADR 0008 sections.
- Document the fixture-generation strategy you picked.
- Document the actual sigstore API surface you used.
- List anything you skipped vs. the brief and why.
- Include the standard `AI-Assisted: Codex` trailer.

When CI is green and the PR is open, comment `@cowork ready for
review` on the PR. Cowork will review against the five specific
checks at the bottom of the brief (layering, backwards compatibility,
canonicalization fidelity, verify exit codes, dependency hygiene).

Out of scope for this PR — do not bundle even if convenient:

- DSSE / in-toto bundle format
- Multi-signer (agent + reviewer co-sign)
- Custom transparency log wiring beyond `--rekor-url`
- Offline verificati