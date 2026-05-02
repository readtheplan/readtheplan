# Codex launch prompt — task 0004 (evidence envelope)

Paste the block below into Codex as a single message to start the
ADR 0007 evidence envelope implementation. Companion brief at
[`codex-task-0004-evidence-envelope.md`](codex-task-0004-evidence-envelope.md).

---

You are picking up the next compliance wedge on the readtheplan repo
(https://github.com/readtheplan/readtheplan), checked out at
`C:\Users\admin\Documents\coding\readtheplan`.

Cowork (Claude) has already written ADR 0007 and a self-contained task
brief. This PR adds a new module — `evidence.py` — and a `--evidence`
CLI flag that writes a versioned JSON document wrapping plan hash +
framework view + controls touched + change list + agent attestation +
optional reviewer.

Read these files first, in this order:

1. `docs/handoff/codex-task-0004-evidence-envelope.md`
   Your task brief. Source of truth.
2. `docs/adr/0007-evidence-envelope.md`
   The design decisions the brief implements. Includes the full
   `rtp-evidence-v1` schema specification.
3. `src/readtheplan/attestation.py`
   Existing module the envelope embeds. Read-only; do not modify.

Then execute:

- Cut branch: `codex/readtheplan-evidence-envelope` (from `main`).
- Write exactly the files listed under the brief's "Files you will
  write" section. No others.
- Do NOT modify `controls.py`, `plan.py`, `rules.py`, or
  `attestation.py`. ADR 0007's layering contract forbids it.
- Implement `evidence.py` with the public surface specified in the
  brief (`EVIDENCE_SCHEMA`, `Reviewer`, `EvidenceEnvelope`,
  `build_evidence`, `EvidenceError`). `EVIDENCE_SCHEMA` must be the
  literal string `"rtp-evidence-v1"` — it's contractually fixed.
- Add the four new flags to `cli.py`'s `analyze` subparser:
  `--evidence`, `--agent-id`, `--reviewer-id`, `--reviewer-kind`,
  `--run-id`. Behavior per the brief.
- Add `tests/fixtures/evidence_plan.json` with the four cases in the
  brief's fixture table.
- Add the 12 named tests to `tests/test_evidence.py`. The names and
  intent are fixed; style is yours.
- Update `README.md` with the new "Evidence envelope (preview)"
  subsection per the brief's sketch.
- Do NOT add any new runtime dependency. The envelope is plain JSON;
  the standard library plus the existing PyYAML dep covers it.

Quality gates (all must pass before opening the PR):

- pytest passes on Python 3.10 and 3.13: existing 46 tests + 12 new tests.
- ruff/black/mypy --strict clean for new + modified Python files.
- `readtheplan analyze --help` shows all five new flags.
- Each commit ends with the trailer: `AI-Assisted: Codex`.

If anything in the brief looks wrong, contradicts the ADR, or is
infeasible — stop, do not work around it. Reply with a short PR-style
write-up of the issue and wait. Silent deviation defeats the whole
review handoff.

Open the PR against `main` from
`codex/readtheplan-evidence-envelope`. PR description must:

- Map each substantive decision back to ADR 0007 sections.
- List anything you skipped vs. the brief and why.
- Include the standard `AI-Assisted: Codex` trailer.

When CI is green and the PR is open, comment `@cowork ready for review`
on the PR. Cowork will review against the five specific checks at the
bottom of the brief (layering, schema fidelity, attestation re-use,
determinism, CLI exclusivity).

Out of scope for this PR — do not bundle even if convenient:

- Cryptographic signing (ADR 0008 — separate upcoming PR)
- Sigstore transparency log integration
- DSSE / in-toto bundle formats
- A `verify` subcommand
- GRC webhook posting
- Multi-framework evidence in one envelope
- PR-comment rendering
- Renaming or modifying any existing dataclass in attestation.py,
  controls.py, rules.py, or plan.py
- Adding any new runtime dependency

Anything that "obviously also needs to land" goes in the PR description
as a TODO for a follow-on task.
