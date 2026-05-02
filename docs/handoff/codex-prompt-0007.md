# Codex launch prompt — task 0007 (HIPAA wiring)

Paste the block below into Codex as a single message. Companion brief at
[`codex-task-0007-hipaa-wiring.md`](codex-task-0007-hipaa-wiring.md).

---

You are picking up the third compliance framework on the readtheplan
repo (https://github.com/readtheplan/readtheplan), checked out at
`C:\Users\admin\Documents\coding\readtheplan`.

Cowork (Claude) has already written ADR 0009, the seed `hipaa.yaml`
catalog, and a self-contained task brief. Same pattern as PR #5
(ISO 27001) — data is already on main; this PR adds tests + README.

Read these files first, in this order:

1. `docs/handoff/codex-task-0007-hipaa-wiring.md`
   Your task brief. Source of truth.
2. `docs/adr/0009-hipaa-control-catalog.md`
   The design decisions the brief implements.
3. `src/readtheplan/data/controls/hipaa.yaml`
   Seed catalog you will wire up via tests. Read-only unless a real
   bug — in which case, call it out in the PR.

Then execute:

- Cut branch: `codex/readtheplan-hipaa-controls` (from `main`).
- Write exactly the files listed under "Files you will write":
  - `tests/fixtures/hipaa_plan.json` (new — six cases per the brief
    table)
  - `tests/test_controls.py` (modify — add the 8 named tests)
  - `README.md` (modify — extend the "Compliance control IDs (preview)"
    subsection per the brief's sketch)
- Do NOT modify `controls.py`, `evidence.py`, `signing.py`,
  `attestation.py`, `plan.py`, `rules.py`, or `cli.py`. ADR 0009's
  layering contract (same as ADR 0006) forbids it.

Quality gates:
- pytest passes on Python 3.10 and 3.13: existing 76 tests + 8 new
  tests = 84 total.
- ruff/black clean.
- `readtheplan analyze --help` shows `hipaa`, `iso27001`, `soc2` in
  the `--framework` line (no code change — `available_frameworks()`
  derives it automatically).
- Each commit ends with the trailer: `AI-Assisted: Codex`.

If anything in the brief looks wrong or contradicts the ADR — stop,
do not work around it. Reply with a short PR-style write-up of the
issue and wait. Same handshake as before.

Open the PR against `main` from `codex/readtheplan-hipaa-controls`.
PR description must:
- Map decisions back to ADR 0009 sections.
- List anything skipped vs. the brief and why.
- Include `AI-Assisted: Codex` trailer.

When CI is green (test-action, pytest (3.10), pytest (3.13) all
passing), comment `@cowork ready for review`.

Out of scope:
- HIPAA Privacy Rule, Breach Notification Rule
- HITRUST CSF, 42 CFR Part 2, state-specific privacy rules
- PCI-DSS, NIST 800-53, CIS AWS catalogs
- Multi-framework simultaneous rendering
- Customer-supplied control overlays
- Any change to controls.py / evidence.py / signing.py / attestation.py / plan.py / rules.py / cli.py
- Any new runtime dependency
