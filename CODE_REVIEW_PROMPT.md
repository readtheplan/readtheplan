# Code Review Prompt — readtheplan Top 3 Fixes

You are a senior code reviewer. Review the following changes in the readtheplan repo at `C:\Users\admin\Documents\coding\readtheplan`.

## What was implemented

### 1. CLI crash-path fixes (CLI-1, CLI-2)
- Binary plan input now shows a friendly error instead of `UnicodeDecodeError` traceback
- `analyze_plan_file()` call wrapped in try/except for `PlanError`
- `RecursionError` caught on deeply nested JSON
- **Files:** `src/readtheplan/cli.py`

### 2. Exit codes & gating (CLI-3)
- Added `--fail-on <tier>` argument to `analyze` subcommand
  - Accepts: safe, review, dangerous, irreversible
  - Exits 1 if any change at or above threshold
- `agent-gate` subcommand now returns:
  - 0 = proceed
  - 1 = warn
  - 2 = block
- `_flagged_changes()` now shows "…and N more" when truncated to 5
- **Files:** `src/readtheplan/cli.py`, `src/readtheplan/agent_gate.py`

### 3. Agent-gate JSON Schema + integration guide (GATE-1)
- `site/data/agent-gate-schema.json` — JSON Schema (Draft 2020-12) for `rtp-agent-gate-v1`
- `site/docs/agent-gate.md` — integration guide with examples for Claude Code, Codex, Cline
- `site/data/index.json` — updated with schema reference
- **Files:** `site/data/agent-gate-schema.json`, `site/docs/agent-gate.md`, `site/data/index.json`

## What to review

For each change, verify:

- **Correctness** — does the code work? Edge cases handled?
- **Completeness** — does it fully address the Fable 5 finding?
- **Style** — fits project conventions (type hints, imports, error messages)?
- **Tests** — are there test gaps? The changes need tests too.
- **Documentation** — does the README or CLI help text need updating?
- **Regression risk** — does anything break?

### Specific questions to answer

1. **Binary plan fix**: Does the error message actually help a new user? Should it also mention `-json` flag for `terraform plan` directly?
2. **`--fail-on`**: Is the implementation correct? Should it report ALL changes above threshold or just the first? Is stderr the right output channel?
3. **Exit codes**: Are 0/1/2 the right values? Does any existing CI/GitHub Action config rely on the old behavior (always 0)?
4. **Schema**: Does the JSON Schema accurately reflect all fields in `agent_gate_to_dict()`? Any missing fields or incorrect types?
5. **Integration guide**: Accurate and useful? Will Claude Code / Codex / Cline actually work with these examples?
6. **Missing**: What else should have been changed but wasn't? (e.g. docs, README, CHANGELOG, tests, CI config, CLI help text)
7. **Test coverage**: What tests should be added to make these changes maintainable?

## Deliverable

A review with:
1. **Verdict** — approve / approve with changes / reject
2. **Issues found** — each with severity (critical/high/medium/low/nit) and suggested fix
3. **Approved changes** — what's good and can stay
4. **Missing items** — what needs to be done that wasn't
5. **Test recommendations** — what tests to add

Be thorough. The author wants to ship quality code.
