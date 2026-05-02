# Codex launch prompt — task 0003 (ISO 27001 wiring)

Paste the block below into Codex as a single message to start the
ADR 0006 ISO 27001 catalog wiring. Companion brief at
[`codex-task-0003-iso27001-wiring.md`](codex-task-0003-iso27001-wiring.md).

**Prerequisites — both must be true before launching:**

- PRs #3 (SOC 2 wedge) and #4 (test-action paths) are merged to main.
- ADR 0005 has been flipped to `Accepted` on main (Cowork's job, post-merge).

If either prerequisite isn't met, hold this prompt — Codex will block on
missing inputs the same way they did on task 0002.

---

You are picking up the next compliance wedge on the readtheplan repo
(https://github.com/readtheplan/readtheplan), checked out at
`C:\Users\admin\Documents\coding\readtheplan`.

Cowork (Claude) has already written the ADR, seed catalog, and a
self-contained task brief. This is the first PR that proves new
frameworks are purely data — no loader / CLI / format changes.

Read these files first, in this order:

1. `docs/handoff/codex-task-0003-iso27001-wiring.md`
   Your task brief. Source of truth.
2. `docs/adr/0006-iso-27001-control-catalog.md`
   The design decisions the brief implements.
3. `src/readtheplan/data/controls/iso27001.yaml`
   Seed catalog you will wire up via tests. Read-only unless a real bug —
   in which case, call it out in the PR.

Then execute:

- Cut branch: `codex/readtheplan-iso27001-controls` (from `main`).
- Write exactly the files listed under the brief's "Files you will write"
  section. No others.
- Do NOT modify `controls.py`, `plan.py`, `rules.py`, or `attestation.py`.
  ADR 0006's layering contract forbids it.
- Add `tests/fixtures/iso27001_plan.json` with the six cases in the brief's
  fixture table.
- Add the eight named tests to `tests/test_controls.py`. The names and
  intent are fixed; style is yours.
- Update `README.md`'s "Compliance control IDs (preview)" subsection per
  the brief's sketch (≤ ~12 lines, no marketing copy).
- Update `cli.py`'s `--framework` help string to derive from
  `available_frameworks()` instead of the hardcoded `"Currently
  available: soc2"`.

Quality gates (all must pass before opening the PR):

- pytest passes on Python 3.10 and 3.13: existing 30 tests + 8 new tests.
- ruff/black/mypy --strict clean.
- `readtheplan analyze --help` shows both `soc2` and `iso27001` in the
  `--framework` line.
- Each commit ends with the trailer: `AI-Assisted: Codex`.

If anything in the brief looks wrong, contradicts the ADR, or is
infeasible — stop, do not work around it. Reply with a short PR-style
write-up of the issue and wait. Silent deviation defeats the whole
review handoff.

Open the PR against `main` from `codex/readtheplan-iso27001-controls`.
PR description must:

- Map each substantive decision back to an ADR section.
- List anything you skipped vs. the brief and why.
- Include the standard `AI-Assisted: Codex` trailer.

When CI is green and the PR is open, comment `@cowork ready for review`
on the PR. Cowork will review against the five specific checks at the
bottom of the brief (layering, catalog visibility, backwards compat,
help-string derivation, order-invariance regression).

Out of scope for this PR — do not bundle even if convenient:

- Multi-framework simultaneous rendering (e.g. `--framework soc2,iso27001`)
- HIPAA, PCI-DSS, NIST 800-53, CIS AWS catalogs
- Customer-supplied control overlays
- Evidence envelope output (separate upcoming ADR)
- Signed attestation (separate upcoming ADR)
- Any change to controls.py, plan.py, rules.py, attestation.py
- Renaming available_frameworks() or changing its signature

Anything that "obviously also needs to land" goes in the PR description
as a TODO for a follow-on task.
