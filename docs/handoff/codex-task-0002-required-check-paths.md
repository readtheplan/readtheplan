# Codex task — make required CI workflows always run

**Authoring agent:** Cowork (Claude)
**Implementation agent:** Codex
**Reviewer:** Cowork (Claude), via the `engineering:code-review` skill
**Branch:** `codex/readtheplan-required-checks-always-run`
**Commit trailer:** `AI-Assisted: Codex`

---

## Problem

Branch protection on `main` requires two status checks: `test-action` and
`site`. Both workflows have `paths:` filters on their `pull_request:` (and
`push:`) triggers, so a PR that touches files outside those paths produces a
`pull_request` event that **never instantiates the workflow run**. The
required check then never reports, and the PR cannot be merged through the
standard UI flow — admin bypass becomes the only path.

PR #3 hit this directly: it touched `src/`, `tests/`, `docs/`, `pyproject.toml`,
`README.md` — `test-action` ran (because `src/**` matched) but `site` never
ran (no `site/**` change). Codex correctly flagged that `gh pr checks --required`
returned only `test-action`. Cowork's prior spec-only PR (`a4edfb0` on `main`)
hit the same shape.

## Fix

Remove the `paths:` filters from both workflows entirely so every PR
unconditionally triggers both required checks. The performance cost on this
project is negligible (small fixtures, fast Node build, public repo with
unlimited Actions minutes), and the simplicity is worth the rare extra run.

This is the simplest of the three options and the one with the fewest moving
parts. Two alternatives were considered and rejected:

- **Conditional-skip pattern** (workflow always triggers; heavy steps gated by
  a `paths-filter` action). Extra dependency, more YAML, easier to misconfigure.
- **Drop the checks from required.** Loses the merge gate when site/ or src/
  *does* change. Wrong direction.

## Files to write

```
.github/workflows/site.yml          (modify — drop paths from on.*.paths)
.github/workflows/test-action.yml   (modify — drop paths from on.*.paths)
```

Nothing else.

### Exact change — `.github/workflows/site.yml`

Replace the `on:` block. Keep the rest of the file identical.

Before:

```yaml
on:
  push:
    branches: [main]
    paths:
      - .github/workflows/site.yml
      - site/**
      - tests/test_site.py
  pull_request:
    paths:
      - .github/workflows/site.yml
      - site/**
      - tests/test_site.py
```

After:

```yaml
on:
  push:
    branches: [main]
  pull_request:
```

### Exact change — `.github/workflows/test-action.yml`

Same pattern. Replace the `on:` block.

Before:

```yaml
on:
  push:
    branches: [main]
    paths:
      - action.yml
      - .github/workflows/test-action.yml
      - pyproject.toml
      - src/**
      - tests/fixtures/**
  pull_request:
    paths:
      - action.yml
      - .github/workflows/test-action.yml
      - pyproject.toml
      - src/**
      - tests/fixtures/**
```

After:

```yaml
on:
  push:
    branches: [main]
  pull_request:
```

## Out of scope

- Adding caching, matrix builds, or other workflow optimizations.
- Renaming the workflows or job names. The branch protection ruleset
  references the existing job names (`test-action`, `site`) — do not rename.
- Adding new workflows.
- Modifying any non-workflow file.
- Touching the branch protection ruleset itself (Cowork owns that, separately).

## Acceptance / definition of done

- [ ] Diff is exactly the two `on:` blocks above. No other changes anywhere.
- [ ] Both YAMLs parse cleanly (you can verify with `actionlint` if installed,
      or just `python -c "import yaml; yaml.safe_load(open('<file>'))"`).
- [ ] Commit message: `Always run required CI workflows on every PR`. Trailer:
      `AI-Assisted: Codex`.
- [ ] PR opened against `main` from `codex/readtheplan-required-checks-always-run`.

## Verification after merge

After this PR merges, both required checks will fire on every subsequent PR.
A simple way to verify the gate is healthy:

1. Open a tiny throwaway PR that only modifies a comment in the README. Both
   `test-action` and `site` should run and report.
2. Cowork will close the throwaway PR after confirmation.

You don't need to do step 1 — Cowork will, post-merge.

## Review handoff

When CI on this PR is green, comment `@cowork ready for review`. Cowork will
verify the diff against this brief, the workflow YAML still parses, and the
job names still match the branch protection ruleset.
