# Codex task — pytest CI workflow

**Authoring agent:** Cowork (Claude)
**Implementation agent:** Codex
**Reviewer:** Cowork (Claude), via the `engineering:code-review` skill
**Branch:** `codex/readtheplan-pytest-workflow`
**Commit trailer:** `AI-Assisted: Codex`

---

## Problem

The repository now has 75 pytest tests across `controls`, `evidence`,
`signing`, `attestation`, `cli`, `plan`, `rules`, and a few support
files. None of them are run by any GitHub Actions workflow on PR.

`.github/workflows/test-action.yml` exercises the composite action
against three fixture files via a hard-coded shell harness — useful as
a smoke test, but it does not import the package, doesn't run pytest,
and doesn't catch regressions in `controls.py`, `evidence.py`,
`signing.py`, or any rule logic. PRs #3 through #7 each ran their full
test suites locally before pushing; that's the only thing that's been
keeping the project green.

The fix is small: add a real pytest workflow, run it on every PR, run
it across the supported Python versions (3.10 and 3.13), and add it to
the branch protection ruleset as a required check.

This brief covers shipping the workflow. Cowork adds it to the ruleset
post-merge.

## Files to write

```
.github/workflows/pytest.yml   (new)
```

Nothing else. Do **not** modify `test-action.yml` (it's a different
gate covering the composite action; both stay required), `pyproject.toml`,
or any source / test file. The workflow installs the package with its
existing `[test]` extra and runs `pytest` with no arguments.

## Exact workflow content

```yaml
name: pytest

on:
  push:
    branches: [main]
  pull_request:

jobs:
  pytest:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.13"]
    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
          cache-dependency-path: pyproject.toml

      - name: Install package and test extras
        run: |
          python -m pip install --upgrade pip
          python -m pip install -e ".[test]"

      - name: Run pytest
        run: pytest
```

Notes for the implementation:

- `name: pytest` — the workflow shows up under that name on PRs.
- Job ID `pytest`. With the matrix, GitHub generates one check per
  Python version, named `pytest (3.10)` and `pytest (3.13)`. Cowork will
  add both as required checks in the ruleset post-merge — leave the
  ruleset alone for this PR.
- `fail-fast: false` — let both Python versions run to completion even
  if one fails, so we see both signals.
- `cache: pip` and `cache-dependency-path: pyproject.toml` — uses the
  setup-python built-in pip cache keyed off the package's only
  declared dep manifest. No new actions, no extra config.
- No `permissions:` block. Default is read-only `contents: read` which
  is sufficient for pytest.

## Out of scope (do not bundle)

- Changing `test-action.yml` in any way.
- Adding a code coverage tool, codecov upload, or any reporting step.
- Adding lint / type-check / format steps. Those are local-only today
  and stay that way until a separate ADR.
- Modifying `pyproject.toml`'s dependency declarations.
- Adding `permissions:` blocks beyond default.
- Touching the branch protection ruleset (Cowork's responsibility,
  separately).

## Acceptance / definition of done

- [ ] Diff is exactly the new `.github/workflows/pytest.yml` file. No
      other changes.
- [ ] YAML parses cleanly (`python -c "import yaml; yaml.safe_load(open('.github/workflows/pytest.yml'))"`).
- [ ] On the PR, both `pytest (3.10)` and `pytest (3.13)` checks run
      and pass against the existing 75-test suite. No skipped tests due
      to environment differences (e.g., sigstore network tests should
      already be `skipif`-gated per PR #7's pattern).
- [ ] `test-action` continues to run and pass on the PR alongside the
      new pytest jobs.
- [ ] Commit message: `Add pytest workflow`. Trailer: `AI-Assisted: Codex`.
- [ ] PR opened against `main` from `codex/readtheplan-pytest-workflow`.

## Verification after merge (Cowork's job)

After this merges, Cowork will:

1. Add `pytest (3.10)` and `pytest (3.13)` to the ruleset's required
   status checks via the GitHub settings UI.
2. Open one tiny throwaway PR to verify all three required checks
   (`test-action`, `pytest (3.10)`, `pytest (3.13)`) fire on a docs-only
   change. Close without merging.

## Review handoff

When CI is green on the PR, comment `@cowork ready for review`.
Cowork verifies the diff is exactly the new workflow file, the YAML
parses, both matrix jobs run and pass, and `test-action` is unaffected.
Quick review pass; this is a one-file add.
