# Codex brief — 2026-07-11 — Install-safety & side effects (review findings 4–5 + PR #144 carry-overs)

## Context

Phase 2 of the 2026-07-10 review remediation. Phase 1 (findings 1–3) merged
as `c84c9c0` (PR #144). This brief covers findings 4–5 plus the non-blocking
items from the PR #144 review.

Red tests are on branch `red/install-safety` in
`tests/test_install_safety.py`. On `main@c84c9c0` all 6 fail — including a
reproduction of your clean-wheel probe (PR template corrupts JSON stdout on
run 3). Make all 6 pass without weakening any assertion.

## Instructions

```
git fetch origin red/install-safety
git checkout -b fix/install-safety origin/red/install-safety
```

### 1. Remove import side effects (finding 5)

File: `src/readtheplan/evolution.py` (module-level `evolution = EvolutionEngine()`
singleton at the bottom).

- Importing `readtheplan.evolution` or `readtheplan.cli` must not touch the
  filesystem. Replace the eager singleton with lazy construction (e.g. a
  `get_engine()` accessor or construction at call sites); `EvolutionEngine`
  may keep creating its data dir in `__init__`, but no instance may exist at
  import time. Update all importers of the `evolution` singleton.

### 2. Make `analyze --mode self-improving` real (finding 5)

File: `src/readtheplan/cli.py` (`_analyze`).

- The flag is currently parsed and ignored. When set, construct the engine
  and record the run + incidents the same way `_agent_gate` does (via
  `agent_gate_to_dict(..., mode=..., evolution_engine=...)` or an equivalent
  recording path). Surface suggested-rule notices on stderr or in the
  Markdown report — never interleaved with machine-readable output.

### 3. In-process candidate verification (finding 4)

File: `src/readtheplan/evolution.py` (`analyze_with_agents`, verification step).

- Verification must not spawn subprocesses and must not require pytest:
  pytest is a dev extra, and `PYTHONPATH=src` only exists in a source
  checkout, so the current shell-out breaks on installed wheels.
- Verify in-process: load the candidate module in an isolated namespace
  (same spec/exec technique as the Phase 1 approved-rule loader), then call
  the rule function directly with the mutating-change and
  no-op/read-only counterexample inputs that the generated validation file
  encodes. Keep writing `test_rule.py` into the candidate dir for human
  review and CI, but the runtime verdict must not depend on executing it via
  pytest.
- Verification failures set `verified=False`/score 0 as today; they must not
  raise or print to stdout.

### 4. Diagnostics never on stdout (finding 4)

Files: `src/readtheplan/evolution.py` (all `print(...)` calls: skip warnings,
grok errors, verification failures, PR template).

- stdout belongs to machine-readable CLI output. Route all evolution
  diagnostics to stderr (or the `logging` module with a stderr handler).
  Repeated `agent-gate --mode self-improving` runs must emit parseable JSON
  on stdout every run — the red test drives 4 runs against the same plan and
  parses each.

### 5. Carry-overs from PR #144 review (non-blocking then, in scope now)

- `src/readtheplan/mcp_server.py`: Terraform (`analyze_plan`, `agent_gate`)
  and CloudFormation (`agent_gate_cloudformation`) still resolve-then-read,
  which is racy; route their file reads through `_read_confined_bytes` so
  all handlers share the TOCTOU-resistant path. Existing MCP tests must stay
  green.
- `src/readtheplan/evolution.py`: `_evolve_decision` no longer uses its
  `risk` parameter — remove it or document why it stays.

## Gates (all must pass)

- `ruff check .`
- `pytest` — full suite including `tests/test_install_safety.py` (6/6),
  coverage ≥ 78
- Clean-wheel probe: build the wheel, install into a fresh venv WITHOUT dev
  extras, run `readtheplan agent-gate --mode self-improving <plan>` three
  times — every run must exit cleanly with valid JSON on stdout.
- `scripts/regenerate-examples.sh` if rule output changes
- Site parity checks, Python 3.10 and 3.13

## PR

- Title: `fix: install-safe self-improving mode and import side effects (review 2026-07-10, findings 4-5)`
- Note AI assistance in the PR body. No `AI-Assisted:` commit trailers.
- Do not modify or delete the red tests; extend with additional tests as
  needed.
