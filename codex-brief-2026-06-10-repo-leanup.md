# Brief: repo lean-up for developer adoption (Cowork → Codex)

**Base:** `origin/main` @ `39a0a29`. Branch from main (do NOT base on `fix/cli-typeerror-on-json-array`).
**This brief file is an internal handoff artifact — do not commit it.**

All 10 internal docs deleted in Part 1 were ported to Notion on 2026-06-10 under
"readtheplan → Internal docs (moved from public repo, 2026-06-10)"
(https://app.notion.com/p/37b6949ef66b812e8044c4435451c2b7). Notion is the source of truth
for them now. They stay in git history — no history rewrite (consistent with the
2026-05-02 aborted-rewrite decision).

---

## Part 1 — remove internal business/ops docs from the public repo

```bash
git rm docs/product/readtheplan-oss-vs-saas-product-strategy.md \
       docs/product/saas-architecture.md \
       docs/product/paid-tier-feature-gating-design.md \
       docs/product/saas-launch-checklist.md \
       docs/briefs/adoption-improvements-codex-brief.md \
       docs/briefs/hosted-analyzer-security-gates-brief.md \
       docs/archive/pdf_export.py \
       docs/weekly-brief-runbook.md \
       docs/mcp-sales-demo.md \
       docs/architecture-review-findings-2026-06-07.md
```

Keep: `docs/adr/`, `docs/authoring-rules.md`, `docs/corpus/`, all of `docs/security/`.

### Known couplings to fix in the same commit (verified by grep, 2026-06-10)

1. `tests/test_adr_docs.py` — delete ONLY the function
   `test_architecture_review_findings_references_real_files` (lines ~9–43), which reads
   `docs/architecture-review-findings-2026-06-07.md`. Keep the file and its other
   4 tests (they cover ADRs 0001–0004, which stay).
2. `tests/test_site.py::test_weekly_brief_paid_output_loop_slice` — line 247 reads
   `docs/weekly-brief-runbook.md`; lines 308–313 assert on its content. Delete the
   `runbook = ...` read and those six `assert ... in runbook` lines. Keep all
   site-file assertions in that test unchanged.
3. `docs/adr/0013-hosted-analyzer-data-handling-boundary.md` References section
   (~line 139) lists `docs/weekly-brief-runbook.md`. Replace that bullet with:
   `- Weekly brief runbook (internal — moved to Notion, 2026-06-10)`.

## Part 2 — fix doc drift (each verified against the actual tree)

1. `README.md` line 8: coverage badge hardcodes `85%`. Actual gate is
   `fail_under = 78` in pyproject.toml. Change badge to `coverage-78%25-brightgreen`.
2. `README.md` lines 71 and 303: `30+ AWS resource types` → `40+ AWS resource types`
   (rules.py covers 42 distinct `aws_*` types; CONTRIBUTING.md already says 40+).
3. `CONTRIBUTING.md` line 29: `gate is fail_under=77` → `gate is fail_under=78`.

## Part 3 — make AGENTS.md / CLAUDE.md public-safe

Both currently contain only the internal Task-ops SOP referencing
`~/Documents/coding/TASK-OPS-SOP.md` (a path on the maintainer's machine) and
Notion/Hermes — broken and meaningless for outside contributors.

Replace the full contents of **both** files with:

```markdown
# Agent / AI-assistant notes

This is a pure-Python package (3.10+). Source in `src/readtheplan/`, tests in `tests/`.

- Setup: `pip install -e ".[dev]"`
- Test: `pytest` (coverage gate: fail_under=78)
- Lint: `ruff check .`
- After changing rules: `scripts/regenerate-examples.sh`
- Full contributor guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- If you used AI assistance in a PR, note it in the PR body (project norm).
```

(The maintainer keeps private agent instructions in untracked local files; nothing
to preserve here.)

## Part 4 — isolate the website inside the monorepo (split deferred)

1. Move the playground parity test under the site:
   ```bash
   git mv analysis/classifier-parity.test.js site/analysis/classifier-parity.test.js
   ```
   - Update its require path: `../site/playground/classifier.js` → `../playground/classifier.js`.
   - Update `.github/workflows/site.yml` line 41: `node analysis/classifier-parity.test.js`
     → `node site/analysis/classifier-parity.test.js`.
   - Remove the now-empty `analysis/` dir.
2. Add to `README.md`, directly under the "Documentation" heading, a short
   "Repository layout" note:
   ```markdown
   ### Repository layout

   The product is `src/readtheplan/` (CLI, rules engine, adapters) plus `action.yml`
   (GitHub Action). The `site/` directory is the readtheplan.dev website — it has its
   own build and is not part of the PyPI package. `benchmarks/` and `demo/` are
   evaluation/demo material, not runtime code.
   ```
3. Verify the sdist does not ship the website:
   ```bash
   python -m build --sdist && tar -tzf dist/readtheplan-0.3.0.tar.gz | grep -E 'site/|demo-video' && echo "FAIL: site leaked into sdist" || echo "OK"
   ```
   If site/ leaks in, add a `MANIFEST.in` with `prune site`, `prune benchmarks`, `prune demo`.

**Do not touch** the root `package.json` (npm name reservation, PyPI-first policy).

## Verify (runnable)

```bash
pip install -e ".[dev]"
ruff check .
pytest -q                                  # full suite incl. modified test_site.py
node site/analysis/classifier-parity.test.js
grep -rn 'docs/product\|docs/briefs\|weekly-brief-runbook\|architecture-review-findings\|mcp-sales-demo\|docs/archive' \
  README.md CONTRIBUTING.md SECURITY.md docs/ site/ tests/ .github/ src/ && echo "FAIL: stale reference" || echo "OK: no stale references"
```

## Commit / push

```bash
git checkout -b chore/repo-leanup origin/main
# ... changes ...
git commit -m "chore: move internal docs to Notion, fix doc drift, isolate site assets"
```

Push and open a PR. If the protected-branch push is blocked, hand back to the human
for the admin bypass. No `AI-Assisted:` trailer (post-2026-05-02 policy).

## Not in scope (deliberately)

- Site split into its own repo — deferred; decision was "keep monorepo, isolate better".
- npm package changes of any kind.
- Coverage increase to 85% (separate effort; the badge now reflects reality instead).
- README restructure beyond the layout note (duplicate "Sample CLI output" section
  is a candidate for a future docs pass).
