# readtheplan dogfood gate

`readtheplan dogfood` analyzes this repository's first-party delivery
configuration on pull requests and pushes to `main`. The action runs from the
checked-out source (`uses: ./`) so a pull request tests the exact action code it
changes.

The scan excludes tests, examples, generated content, documentation, and local
worktree/report directories through the `scan-excludes` action input. Each
non-empty line is passed to `readtheplan scan` as one repository-relative
`--exclude` glob. The input is rejected for tools other than `scan`.

The gate is deliberately a non-regression policy. Existing findings remain
visible in the uploaded JSON evidence, while
`.github/readtheplan-scan-baseline.json` defines:

- the maximum count allowed at each risk level;
- the maximum scan-error count; and
- the minimum number of successfully scanned files.

This prevents a new finding, a parser failure, or a coverage reduction from
being hidden by the current backlog. A change that intentionally alters the
inventory or classifications must include the corresponding baseline change
for explicit review. Never regenerate or raise the baseline automatically in
CI. Prefer fixing findings and lowering its ceilings.

Run the focused validation locally with:

```bash
python -m pytest tests/test_action_metadata.py tests/test_scan_baseline.py --no-cov
ruff check scripts/check_scan_baseline.py tests/test_scan_baseline.py
```

The workflow uploads `readtheplan-dogfood-<commit>` for 14 days. Treat the
artifact as review evidence, not as deployment authorization.
