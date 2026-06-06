# Brief: adoption + onboarding improvements (Cowork → Codex)

Prepared by Cowork. All changes in this changeset are **docs, examples, and one new
test** — no `src/readtheplan/*.py` implementation was changed. Codex's job here is to
verify, commit, and push.

## What changed and why

| File(s) | Change | Why |
| --- | --- | --- |
| `README.md` | Replaced the headline "How it looks" / EKS samples with **real CLI output** reproducible from bundled fixtures; fixed the GitHub Action ref `@v1` → `@v0.3.0` (no `v1` tag exists); switched Docker to a build-locally snippet (no image is published by CI); added "Who it's for", a "non-blocking by default" note for the Action, a "no Terraform handy" example line, a Troubleshooting section, and a link to the new authoring guide. | The top samples showed a `── Risk Summary ──` format the CLI never emits, and `@v1` / `docker run readtheplan/readtheplan` are broken copy-paste — the two highest-impact trust/onboarding blockers. |
| `CONTRIBUTING.md` | Real dev setup, test/lint commands, project-layout table, four concrete good-first-contributions, "add a test for behavior changes". | The old file promised guidance the README advertised but didn't deliver. |
| `docs/authoring-rules.md` (new) | One guide for overlays, resource rules, compliance mappings, and adapters, each with a copy-paste example and a test. | Users specifically need rule/overlay/contribution docs; none existed (only ADRs). |
| `site/index.html`, `site/docs/github-action/index.html` | `@v1` → `@v0.3.0`. | Site/README consistency. |
| `site/index.html` (homepage) | Fixed `readtheplan mcp --stdio`→`readtheplan mcp` (no such flag), dropped nonexistent MCP tool `list_frameworks` (real: `analyze_plan`, `agent_gate`, `agent_gate_cloudformation`), comparison `block/warn/ok`→`proceed/warn/block`, and the hero line implying `analyze --framework soc2` auto-writes evidence (it needs `--evidence`). | Live homepage contradicted the real CLI. Stylized hero *format* left as-is (design choice). Live site needs a redeploy to reflect these. |
| `examples/*/analysis.{md,json}`, `examples/02-.../evidence.json` | Regenerated via `scripts/regenerate-examples.sh`. | 5 of 6 committed outputs had drifted from the current rules engine (e.g. `aws_vpc_security_group_ingress_rule` create reclassified safe→review). These are the "expected output" users compare against. |
| `tests/test_examples_fresh.py` (new) | Regression test asserting `examples/*/analysis.{md,json}` match live CLI output. | Prevents the staleness above from recurring silently. |

## Verify (runnable)

```bash
pip install -e ".[dev]"
ruff check .
pytest -q                      # includes the new tests/test_examples_fresh.py
pytest -q tests/test_examples_fresh.py   # should be green after the regen in this changeset
```

`tests/test_examples_fresh.py` was authored to **fail on the pre-regen tree** (the red
test) and pass once examples are regenerated — both verified locally before hand-off.

## Commit / push

Conventional-commit split (or squash as you prefer):

```bash
git add README.md CONTRIBUTING.md docs/authoring-rules.md site/ examples/ tests/test_examples_fresh.py
git commit -m "docs: accurate CLI samples, fix broken @v1/docker refs, add authoring guide + example-freshness test"
```

Push to a branch and open a PR (push needs the usual admin bypass — hand back to the
human if the protected-branch push is blocked).

## Not done here (left for a follow-up, intentionally)

- No CLI/error-message behavior changes were needed; existing error strings are clear.
- No new resource rules added — `docs/authoring-rules.md` is the on-ramp for those as
  good-first-issues.
