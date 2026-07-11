# Codex brief — 2026-07-11 — Content-based plan identity hash (review finding 6, ADR 0014)

## Context

Phase 3 of the 2026-07-10 review remediation. Phases 1–2 merged as `c84c9c0`
(PR #144) and `486af4c` (PR #145).

This change is governed by an ADR: `docs/adr/0014-plan-identity-hash.md`,
committed on branch `red/plan-identity-hash` together with red tests in
`tests/test_plan_hash.py` (5 fail on `main@486af4c`, 3 canonicalization
guards pass). ADR revision 2026-07-11: per your deposed-object finding, the
sort key is `(address, type, actions)`. Implement exactly what the ADR
specifies; if you believe the ADR is wrong, stop and report back instead of
deviating.

## Instructions

```
git fetch origin red/plan-identity-hash
git checkout -b fix/plan-identity-hash origin/red/plan-identity-hash
```

Single change: rewrite `_compute_plan_hash` in `src/readtheplan/agent_gate.py`
per ADR 0014.

- Payload: `{"schema": "rtp-plan-hash-v2", "terraform_version": <str|null>,
  "changes": [{"address", "type", "actions"}, ...]}`.
- Changes sorted by `(address, type, actions)` — the actions tuple joins the
  sort key because same-address current/deposed pairs make `(address, type)`
  non-unique; `actions` order inside each change is preserved (replace
  semantics are identity-relevant).
- Serialize with `sort_keys=True`, `separators=(",", ":")`,
  `ensure_ascii=False`; hash the UTF-8 bytes.
- Return the full 64-char lowercase SHA-256 hex digest — no truncation.
- Excluded: `summary.path`, `risk`, `explanation`, `source`, change count.
- No migration of existing `evolution.db` rows (append-only audit trail; the
  generations are distinguishable by digest length).

Also add an assertion-based ADR test in `tests/test_adr_docs.py` following
the existing pattern there (assert the ADR documents the schema tag, the
full-digest decision, and the path exclusion).

## Gates (all must pass)

- `ruff check .`
- `pytest` — full suite including `tests/test_plan_hash.py` (8/8),
  coverage ≥ 78
- `scripts/regenerate-examples.sh` if any example output embeds a plan hash
- Site parity checks, Python 3.10 and 3.13

## PR

- Title: `fix: content-based plan identity hash (ADR 0014, review 2026-07-10, finding 6)`
- Note AI assistance in the PR body. No `AI-Assisted:` commit trailers.
- Do not modify or delete the red tests or the ADR; extend tests as needed.
