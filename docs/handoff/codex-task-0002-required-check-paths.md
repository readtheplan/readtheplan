# Codex task — make required CI workflow always run

**Authoring agent:** Cowork (Claude)
**Implementation agent:** Codex
**Reviewer:** Cowork (Claude), via the `engineering:code-review` skill
**Branch:** `codex/readtheplan-required-checks-always-run`
**Commit trailer:** `AI-Assisted: Codex`

---

## Problem

Branch protection on `main` requires the `test-action` status check. The
workflow `.github/workflows/test-action.yml` has a `paths:` filter on its
`pull_request:` trigger, so a PR that touches files outside those paths
produces a `pull_request` event that **never instantiates the workflow run**.
The required check then never reports, and the PR cannot be merged through
the standard UI flow — admin bypass becomes the only path.

PR #3 partially hit this (its src/ changes did match the path filter, so
test-action ran). But Cowork's spec-only PRs (docs and ADR changes) and
README-only PRs would not match the existing path filter and would block the
merge gate. The pattern is fragile and grows worse as the project takes on
more docs/spec PRs.

Earlier draft of this brief also referenced `.github/workflows/site.yml`,
which does not exist on `main` (it lives on the unmerged
`codex/readtheplan-web-onboarding` branch, along with the rest of the site
source). Cowork has dropped `site` from the ruleset's required checks
correspondingly. Scope of this task is now **one file only**.

## Fix

Remove the `paths:` filter from `test-action.yml` entirely so every PR
unconditionally triggers the required check. The performance cost on this
project is negligible (small fixtures, fast Node-free test, public repo with
unlimited Actions minutes), and the simplicity is worth the rare extra run.

This is the simplest of the options considered. Two alternatives were
rejected:

- **Conditional-skip pattern** (workflow always triggers; heavy steps gated by
  a `paths-filter` action). Extra dependency, more YAML, easier to misconfigure.
- **Drop the check from required.** Loses the merge gate when src/ does
  change. Wrong direction.

## Files to write

```
.github/workflows/test-action.yml   (modify — drop paths from on.*.paths)
```

Nothing else. Do **not** add a new `site.yml` — the site code isn't on `main`
yet and adding a stub workflow would be misleading.

### Exact change — `.github/workflows/test-action.yml`

Replace the `on:` block. Keep the rest of the file identical.

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
- Renaming the workflow or job. The branch protection ruleset references the
  existing job name (`test-action`) — do not rename.
- Adding new workflows (including a stub `site.yml`).
- Modifying any non-workflow file.
- Touching the branch protection ruleset itself (Cowork owns that, separately).

## Acceptance / definition of done

- [ ] Diff is exactly the `on:` block change above. No other changes.
- [ ] `test-action.yml` parses cleanly (`python -c "import yaml; yaml.safe_load(open('.github/workflows/test-action.yml'))"`).
- [ ] Commit message: `Always run test-action on every PR`. Trailer:
      `AI-Assisted: Codex`.
- [ ] PR opened against `main` from `codex/readtheplan-required-checks-always-run`.

## Verification after merge

After this PR merges, `test-action` will fire on every subsequent PR. Cowork
will close the loop with one tiny throwaway PR (e.g., a comment-only edit in
README) to confirm the gate is healthy, then close it.

## Review handoff

When CI on this PR is green, comment `@cowork ready for review`. Cowork will
verify the diff against this brief, the workflow YAML still parses, and the
job name still matches the branch protection ruleset.

## Out-of-scope notes for follow-on tasks

Two related issues are explicitly *not* part of this task; they get their own
ADRs and briefs later:

1. **No pytest workflow exists.** The 38 pytest tests are not currently run
   by any GitHub Actions workflow. `test-action.yml` only smoke-tests t