# Codex launch prompt — task 0002 (required-check paths)

Paste the block below into Codex as a single message to start the
required-check fix. Companion brief at
[`codex-task-0002-required-check-paths.md`](codex-task-0002-required-check-paths.md).

---

You are picking up a small CI hygiene task on the readtheplan repo
(https://github.com/readtheplan/readtheplan), checked out at
`C:\Users\admin\Documents\coding\readtheplan`.

Cowork (Claude) has written a self-contained brief. Implement what the brief
specifies — no more, no less.

Read the brief first:

`docs/handoff/codex-task-0002-required-check-paths.md` (on `origin/main`).

Then execute:

- Cut branch: `codex/readtheplan-required-checks-always-run` from `main`.
- Modify exactly two files per the brief's "Files to write" section:
  - `.github/workflows/site.yml` — replace the `on:` block per the diff.
  - `.github/workflows/test-action.yml` — replace the `on:` block per the diff.
- Do NOT touch anything else, including job names, step content, or other
  workflow keys. Only the `on:` block.
- Verify both YAMLs still parse (e.g. `python -c "import yaml; yaml.safe_load(open('.github/workflows/site.yml'))"`).
- Commit message: `Always run required CI workflows on every PR`. Trailer:
  `AI-Assisted: Codex`.
- Open the PR against `main` from `codex/readtheplan-required-checks-always-run`.

If anything in the brief looks wrong, contradicts the existing branch
protection setup, or is infeasible — stop, do not work around it. Reply with
a short PR-style write-up of the issue and wait.

When CI is green and the PR is open, comment `@cowork ready for review`.
Cowork will verify the diff is exactly the two `on:` blocks specified, the
workflow YAML still parses, and the job names still match the ruleset.

Out of scope (do not bundle):

- Caching, matrix builds, or any other workflow optimization.
- Renaming workflows or job names.
- Adding new workflows.
- Modifying any non-workflow file (no README, no docs, no source).
- Touching the branch protection ruleset itself.

Anything that "obviously also needs to land" goes in the PR description as
a TODO for a follow-on task.

Note: PR #3 (the SOC 2 wedge) is currently blocked on this same issue —
admin bypass is the only path until this task lands. Cowork has approved
that PR; you can either merge it via bypass first and then start this, or
land this first so PR #3 can merge through the standard UI. Your call —
both are valid and the order doesn't affect correctness.
