# Codex launch prompt — task 0001 (SOC 2 wedge)

Paste the block below into Codex as a single message to start the
ADR 0005 SOC 2 wedge implementation. The companion task brief is
[`codex-task-0001-soc2-wedge.md`](codex-task-0001-soc2-wedge.md).

---

You are picking up an implementation task on the readtheplan repo
(https://github.com/readtheplan/readtheplan), checked out at
`C:\Users\admin\Documents\coding\readtheplan`.

Cowork (Claude) has already written the ADR, seed data, and a
self-contained task brief. Your job is to implement what the brief
specifies — no more, no less.

Read these files first, in this order:

1. `docs/handoff/codex-task-0001-soc2-wedge.md`
   Your task brief. This is the source of truth. Everything else supports it.
2. `docs/adr/0005-compliance-control-mapping.md`
   The design decisions the brief implements.
3. `src/readtheplan/data/controls/soc2.yaml`
   Seed catalog you will wire up. Treat as versioned API surface — read-only
   unless you find a real bug, in which case call it out in the PR.

Then execute:

- Cut branch: `codex/readtheplan-soc2-controls` (from `main`).
- Write exactly the files listed under the brief's "Files you will write"
  section. No others.
- Do NOT modify `rules.py`, `plan.py`, or `attestation.py`. ADR 0005's
  layering contract forbids it.
- Implement `controls.py` with the public surface defined in the brief
  (`ControlEntry`, `ControlCatalog`, `load_catalog`, `available_frameworks`,
  `FrameworkNotFoundError`, `CatalogSchemaError`).
- Add the `--framework` flag to `cli.py` per the spec. Default-off behavior
  must produce byte-identical output to the prior version.
- Update `pyproject.toml` so `data/controls/*.yaml` ships in the wheel.
- Add `tests/fixtures/soc2_plan.json` with the six cases in the brief's
  fixture table.
- Add `tests/test_controls.py` with the twelve named tests. The names and
  intent are fixed; style is yours.
- Update `README.md` with the short subsection sketched in the brief
  (≤12 lines, no marketing copy).
- Leave `docs/adr/0005-compliance-control-mapping.md` status as Proposed.
  Cowork will flip it to Accepted post-review.

Quality gates (all must pass before opening the PR):

- pytest passes on Python 3.10 and 3.13: existing 17 tests + 12 new tests.
- ruff/black clean per existing project style.
- A wheel built from a fresh venv contains `data/controls/soc2.yaml`
  reachable via `importlib.resources`.
- Each commit ends with the trailer: `AI-Assisted: Codex`.

If anything in the brief looks wrong, contradicts the ADR, or is
infeasible — stop, do not work around it. Reply with a short PR-style
write-up of the issue and wait. Silent deviation defeats the whole
review handoff.

The PyYAML dependency in the brief is intentional but worth a sanity
check: if you'd rather hand-roll a tiny YAML subset parser to keep the
zero-dep footprint, flag the trade-off in the PR description and pick
one. Do not add any other runtime dependency.

Open the PR against `main` from `codex/readtheplan-soc2-controls`.
PR description must:

- Map each substantive decision back to an ADR section.
- List anything you skipped vs. the brief and why.
- Include the standard `AI-Assisted: Codex` trailer.

When CI is green and the PR is open, comment `@cowork ready for review`
on the PR. Cowork will review against the five specific checks at the
bottom of the brief (layering, schema fidelity, dedup order, backwards
compatibility, wheel data inclusion).

Out of scope for this PR — do not bundle even if convenient:

- GitHub Action wiring of `--framework`
- ISO 27001, HIPAA, PCI-DSS, NIST 800-53, CIS AWS catalogs
- Evidence envelope, signing, attestation changes
- Any rule-tier, rule_id, or explanation-string changes
- Customer-supplied control overlays
- Multi-framework simultaneous rendering

Anything that "obviously also needs to land" goes in the PR description
as a TODO for a follow-on task, not in this PR.
