# Codex launch prompt — task 0006 (pytest workflow)

Paste the block below into Codex as a single message. Companion brief at
[`codex-task-0006-pytest-workflow.md`](codex-task-0006-pytest-workflow.md).

---

You are picking up a small CI hygiene task on the readtheplan repo
(https://github.com/readtheplan/readtheplan), checked out at
`C:\Users\admin\Documents\coding\readtheplan`.

The repo has 75 pytest tests but no GitHub Actions workflow runs them.
This PR adds `.github/workflows/pytest.yml` that runs the full suite
on every PR across Python 3.10 and 3.13.

Read the brief first:

  docs/handoff/codex-task-0006-pytest-workflow.md  (on origin/main)

Then execute:

- Cut branch: codex/readtheplan-pytest-workflow (from main).
- Add exactly one file: .github/workflows/pytest.yml. Content is
  specified verbatim in the brief — copy it as-is.
- Do NOT modify .github/workflows/test-action.yml, pyproject.toml,
  or any source / test file. The workflow installs the package with
  its existing [test] extra and runs pytest with no arguments.
- Verify the YAML parses (python -c "import yaml; yaml.safe_load(open(...))").
- Commit message: "Add pytest workflow". Trailer: AI-Assisted: Codex.
- Open the PR against main from codex/readtheplan-pytest-workflow.

Quality gates:
- Both pytest (3.10) and pytest (3.13) matrix jobs run and pass on
  the PR against all 75 existing tests.
- test-action continues to run and pass alongside.
- No skipped tests due to environment (sigstore network tests are
  already skipif-gated from PR #7).

If anything in the brief looks wrong or contradicts existing CI
configuration — stop, do not work around it. Reply with a short
PR-style write-up of the issue and wait.

When CI is green, comment "@cowork ready for review".

Out of scope:
- Changing test-action.yml in any way
- Adding code coverage / codecov / reporting
- Adding lint / type-check / format steps
- Modifying pyproject.toml
- Adding permissions: blocks beyond default
- Touching the branch protection ruleset (Cowork handles separately)
```
