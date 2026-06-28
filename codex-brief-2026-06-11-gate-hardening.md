# Codex brief — gate hardening + release the rule fixes (2026-06-11)

**Author:** Cowork (Claude) · **For:** Codex (implements + runs all ops) · **Branch from:** `origin/main`
**Context:** Field test of PyPI `readtheplan==0.3.0` (see `FIELD_TEST-2026-06-11.md`) + source review (`ARCH_REVIEW-2026-06-11.md`).

All three items below were verified against **`origin/main`** today, not just the local tree:
- `cli.py:244` catches only `json.JSONDecodeError` — no `UnicodeDecodeError` handling (CLI-1 present).
- `cli.py:259` calls `analyze_plan_file(...)` outside any try/except on the analyze path (CLI-2 present).
- `cli.py` has zero `fail_on` / exit-code gating (CLI-3 present).
- `origin/main` already contains the `_security_group_candidates` rule, `MCP_ROOT`, and all 6 catalogs — **the rule fixes are done in code; they are simply unreleased.** The published wheel is stale.

Do the items in order. Each is independently shippable. Items 1–2 are PRs; item 3 is a release.

---

## Item 1 — Fix the crash paths on `analyze` (CLI-1, CLI-2). Priority: critical.

**Problem.** `readtheplan analyze <binary-tfplan>` and `analyze` on a plan whose `resource_changes` is the wrong type both exit with a raw Python traceback instead of the friendly error the README's troubleshooting section promises. Reproduced on the wheel *and* confirmed present in `origin/main` source.

**Scope (one PR):** in `src/readtheplan/cli.py`, function `_analyze`:
1. Around the `json.loads(plan_bytes)` block (~line 244), also catch `UnicodeDecodeError` and print the existing binary-plan hint, e.g.:
   `Error: {path} is not UTF-8 JSON. If this is a binary plan, run: terraform show -json tfplan > plan.json` → `return 1`.
2. Wrap the `analyze_plan_file(plan_data, ...)` call (~line 259) in `try/except PlanError` and print `f"Error: {exc}"` to stderr, `return 1` — mirror how `_agent_gate` already handles `PlanError`.
3. Do **not** change exit codes for the success path. No behavior change for valid plans.

**Codex prompt (paste verbatim):**
> On a branch off `origin/main`, in `src/readtheplan/cli.py` `_analyze`: (a) extend the `try` that does `json.loads(plan_bytes)` to also `except UnicodeDecodeError` and print `Error: <path> is not UTF-8 JSON. If this is a binary plan, run: terraform show -json tfplan > plan.json` to stderr and `return 1`; (b) wrap the `summary = analyze_plan_file(plan_data, ...)` line in `try/except PlanError as exc` printing `Error: {exc}` to stderr and `return 1`. Add tests in `tests/test_cli.py`: one feeding a non-UTF-8 bytes file (e.g. `b"\x00\xa6\xff"`), one feeding `{"resource_changes": "foo"}`, each asserting exit code 1 and that stderr contains `Error:` and no traceback. Run `ruff check . && pytest tests/test_cli.py -q` and report results. Conventional-commit message `fix(cli): friendly errors for binary and malformed plans on analyze`.

**Acceptance:** `pytest -q` green; both new cases exit 1 with `Error:` on stderr; no `Traceback` in output.

---

## Item 2 — Add `--fail-on <tier>` exit codes (CLI-3). Priority: high.

**Problem.** Neither `analyze` nor `agent-gate` exits non-zero on risky plans, so every non-GitHub CI (GitLab, Jenkins, Buildkite) and any shell hook must parse JSON. Threshold logic currently lives only in `action.yml` bash.

**Scope (one PR):**
1. Add `--fail-on {safe,review,dangerous,irreversible}` to the `analyze` subparser (default unset = today's behavior, exit 0).
2. After producing `summary`, if `--fail-on` is set and any change's risk tier is **>= the threshold** (use the existing `RISK_ORDER` from `rules.py` — do not hardcode ordering), exit `2`. Keep `1` reserved for hard errors (bad input, IO). Print one stderr line: `fail-on: <n> change(s) at or above <tier>`.
3. Document precedence in `--help`: `--fail-on` is independent of output format; it still prints the normal report first, then exits.
4. Update `README.md` Troubleshooting/Usage and `docs/` CLI reference with the new flag and the 0/1/2 contract. Update `CHANGELOG.md`.

**Decision (locked 2026-06-11 by Zhanybek): Option A.** Exit `2` when the threshold is tripped; keep exit `1` for hard errors (bad input, IO) and exit `0` on success. This lets scripts distinguish "tool broke" from "plan too risky" and matches `ci/readtheplan-gate.sh` (2=warn, 1=block).

**Codex prompt (paste verbatim):**
> On a branch off `origin/main`, add `--fail-on {safe,review,dangerous,irreversible}` to the `analyze` subparser in `src/readtheplan/cli.py`. Import `RISK_ORDER` from `readtheplan.rules`. After the summary is built and printed, if `--fail-on` is set, compute the count of changes whose `RISK_ORDER[risk] >= RISK_ORDER[threshold]`; if >0, print `fail-on: {count} change(s) at or above {threshold}` to stderr and `return 2`. Keep `return 1` for hard errors and `return 0` on success / flag unset. Add `tests/test_cli.py` cases: dangerous plan with `--fail-on dangerous` exits 2; same plan with `--fail-on irreversible` exits 0; safe plan with `--fail-on review` exits 0; and a malformed-input case still exits 1 (not 2). Update README Usage + Troubleshooting, `docs/` CLI reference, and `CHANGELOG.md` documenting the 0/1/2 contract. Run `ruff check . && pytest -q`. Commit `feat(cli): add --fail-on threshold gating with exit codes`.

**Acceptance:** all three new tests pass; existing tests unchanged; docs + changelog updated.

---

## Item 3 — Cut release 0.4.0 (the real headline). Priority: critical, do after 1–2 merge.

**Problem.** `pip install readtheplan` ships 0.3.0, which **predates** the `_security_group_candidates` rule, `MCP_ROOT` confinement, and 3 of the 6 catalogs. Result: the shipped tool classifies a security group opening `0.0.0.0/0` as `review`, while `main` (correctly) says `dangerous` — and that's the exact scenario the site's `terraform-security-group-0-0-0-0-risk` page advertises. Verified by running both side by side.

**Scope (release, not code):**
1. Land items 1 and 2 on `main` first.
2. Bump `version` in `pyproject.toml` to `0.4.0`. Move the `CHANGELOG.md` Unreleased section under a `## 0.4.0 — 2026-06-…` heading; call out the new security-group/ECS rules, `MCP_ROOT`, the 3 added catalogs (pci_dss, hitrust, fedramp_moderate), the crash fixes, and `--fail-on`.
3. Tag `v0.4.0` and let the `publish.yml` workflow build + publish to PyPI. **If the tag push needs admin bypass on a protected branch/tag rule, that single push is the only thing to hand back to Zhanybek** (per the ops convention).
4. Verify post-publish: in a clean venv, `pip install readtheplan==0.4.0` then assert the security-group case returns `dangerous` and `readtheplan analyze --framework pci_dss` loads.

**Codex prompt (paste verbatim, after 1–2 are on main):**
> Branch off `origin/main`. Bump `pyproject.toml` version to `0.4.0`. Rewrite the top of `CHANGELOG.md` into a `## 0.4.0` section listing: security-group `0.0.0.0/0` → dangerous rule, ECS service rules, `MCP_ROOT` path confinement for the MCP server, three new compliance catalogs (pci_dss, hitrust, fedramp_moderate), friendly errors for binary/malformed plans, and `--fail-on` threshold gating. Run `ruff check . && pytest -q`. Commit `chore(release): 0.4.0`. Then create and push tag `v0.4.0`. If the tag push is rejected by branch/tag protection, stop and report the exact command that needs admin bypass. After `publish.yml` succeeds, in a fresh venv run `pip install readtheplan==0.4.0` and confirm a security-group-opens-to-0.0.0.0/0 plan classifies as `dangerous` and `--framework pci_dss` works; report both.

**Acceptance:** `readtheplan==0.4.0` on PyPI; security-group case returns `dangerous`; all 6 frameworks load from the wheel.

---

## Notes / guardrails
- All file paths above exist on `origin/main` (verified 2026-06-11). No missing inputs.
- Don't touch `site/` claims in these PRs — once 0.4.0 ships, the site already matches `main`, so the doc-drift resolves itself. (If 0.4.0 slips, a separate doc-rollback PR would be needed; flag it, don't do it preemptively.)
- The local `chore/repo-leanup` branch (1 commit ahead of origin/main: the Notion-docs move) is unrelated to this work — branch from `origin/main`, not from local HEAD.
- `ci/readtheplan-gate.sh` and `ci/terraform-gate.example.yml` (delivered today) already give users a working exit-code gate on 0.3.x; once Item 2 ships, the script can be simplified to call `analyze --fail-on` directly. Leave that simplification as a follow-up.
