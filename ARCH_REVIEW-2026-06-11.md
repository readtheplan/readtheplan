# readtheplan — Architecture & DX Review

**Reviewer:** Claude (Fable 5), acting as senior product architect / DX consultant
**Date:** 2026-06-11 · **Tree reviewed:** branch `chore/repo-leanup` @ `32800f6` · v0.3.0
**Method:** full source read (all 14 modules), test-suite run with coverage, hands-on edge-case testing of the CLI in a Linux sandbox, site/docs/ADR review.

---

## Verdict in three sentences

The core is better than most v0.3 tools: a clean monotonic-escalation rules engine, a genuinely novel agent-gate contract, and real sigstore signing — not marketing vapor. The biggest risks are (1) crash-with-traceback error paths that will be many users' *first* impression, (2) a CLI that can't gate anything by exit code, forcing every non-GitHub CI user to write jq glue, and (3) a coverage number that flatters the test suite — the rules engine, your actual product, is the least-tested module. None of these is large to fix; all three throttle adoption today.

---

## 1. Component review

### 1.1 cli.py — solid plumbing, two crashes, one missing feature

**What's good:** subcommand structure is clean; flag interdependency checks (`--sign requires --evidence`, `--evidence requires --framework`) fail fast with clear messages; JSON errors include line/column; `--evidence -` stdout convention is right.

**Findings:**

**CLI-1 · Binary/non-UTF-8 plan file → raw `UnicodeDecodeError` traceback.** Critical · small fix.
Reproduced: `readtheplan analyze tfplan` (the *binary* plan, the most common newbie mistake — your own troubleshooting section documents people doing this) dies with a Python stack trace, not the helpful "you passed the binary plan" message the README promises. `_analyze` does `json.loads(plan_bytes)` and only catches `JSONDecodeError`; `json.loads(bytes)` raises `UnicodeDecodeError` first on non-UTF-8 input. Fix: catch `UnicodeDecodeError` (or decode with a try first) and print the existing "did you mean `terraform show -json`?" hint. This is the single highest-value 5-line diff in the repo.

**CLI-2 · `resource_changes` of wrong type → raw `PlanError` traceback.** High · small.
Reproduced with `{"resource_changes": "foo"}`. In `_analyze`, the `analyze_plan_file(plan_data, ...)` call at line 259 sits *outside* any try/except, so `PlanError` escapes as a traceback. (The `agent-gate` path catches it correctly; `analyze` doesn't.) Deeply nested JSON similarly escapes as `RecursionError`. Wrap the call.

**CLI-3 · No risk-threshold exit code in the CLI.** High · small.
`analyze` and `agent-gate` exit 0 even when the decision is `block` (verified). Threshold gating exists only inside `action.yml` bash glue, so GitLab/Jenkins/CircleCI/Buildkite users — and anyone wiring a pre-apply hook — must parse JSON themselves. Add `--fail-on <tier>` to `analyze` and make `agent-gate` exit 0/1/2 for proceed/warn/block (documented, semver-gated). This is the cheapest possible expansion of your addressable CI market.

**CLI-4 · `--version` shells out to git at runtime and can report the wrong commit.** Medium · small.
`_package_version()` runs `git rev-parse` with `cwd=<package parent>`. When readtheplan is pip-installed into a venv that lives *inside the user's own repo* (`.venv/` at repo root — extremely common), git walks up and happily reports the **user's app commit** as readtheplan's version. Surprising, wrong, and a subprocess on every `--version`. Bake the commit in at build time (e.g. setuptools-scm or a generated `_version.py`) and drop the subprocess.

**CLI-5 · No color, no TTY detection, no progress.** Low · medium. The Markdown-table default is a defensible, documented choice — but risk tiers in plain text bury the signal the tool exists to surface. Colorize the Risk column when `isatty()` (respect `NO_COLOR`). Tab completion is a nice-to-have behind `argcomplete`; nit.

### 1.2 plan.py — small and correct, with one inconsistency

The dual code path is sloppy: `load_plan()` has good empty-file/directory/not-an-object checks, but the CLI's `analyze` path reads bytes itself and bypasses them (an empty file produces a different error via a different path than `agent-gate`'s). One loader, one error surface. Medium · small.

Good: the `KNOWN_ACTIONS` guard (garbage actions → `review`, not `safe`) is exactly right and correctly ADR-referenced. Malformed change items degrade to `review` instead of crashing — right call.

**No `format_version` check at all.** The tool accepts any dict and silently produces "0 changes" for a file that isn't a plan at all (e.g. a `terraform output -json` dump or a state file). A warning when `format_version`/`resource_changes` are both absent would prevent silent false-"all safe" — which for a *risk* tool is the worst failure mode. High · small.

### 1.3 rules.py — good engine, narrow coverage, no escape hatch for unknowns

The architecture is right: action baseline → resource candidates → max-escalation, monotonic (rules never lower risk). The explanations are the best part of the product — they read like a senior SRE wrote them.

**RULES-1 · ~30 AWS types covered; everything else falls to the action baseline — silently.** High · medium.
`google_*`, `azurerm_*`, `kubernetes_*`, `helm_*`, `cloudflare_*`, and ~95% of `aws_*` types get only generic action heuristics. That's an acceptable v0.3 scope, but the output gives the reviewer *no signal* that a change was classified by fallback vs. by a resource-aware rule. An auditor reading "irreversible — Terraform will delete this resource" can't tell whether readtheplan *understood* `azurerm_key_vault` (it didn't — and Key Vault soft-delete actually makes that recoverable, so the tier is arguably wrong). Add a `rule_source: "resource-rule" | "action-baseline"` field to each change in JSON/evidence output. Honesty about coverage is a compliance feature.

**RULES-2 · Sensitive values are not handled.** Medium · small. Terraform masks sensitive attrs; `before/after` contain `true` markers in `before_sensitive`/`after_sensitive` which the engine never reads. Consequences: `_attribute_changed` on a masked attribute compares placeholder-to-placeholder and can miss real changes (e.g. an IAM policy delivered as sensitive). At minimum, flag changes whose compared attributes are masked as `review` with an explanation. The FABLE prompt asks about `(sensitive value)` strings — those literal strings only appear in *text* plan output, which you don't parse; the JSON-side equivalent is the `*_sensitive` structures, currently ignored.

**RULES-3 · Single-file rules engine won't scale.** Medium · large (but deferrable). 1,567 lines of hand-written if/elif per resource family. At 100+ resource types this becomes the contributor bottleneck — and "add a resource rule" is your #1 good-first-issue. Consider a declarative core (the overlay YAML schema is 80% of the way there) with Python escape hatches for the genuinely conditional rules (policy parsing, version-crossing). Don't do this now; do it before you accept the 20th rule PR.

**RULES-4 · `_DEPRECATED_RUNTIMES` is a hardcoded snapshot ("as of 2026-05").** It will rot. Move to a data file with a freshness test (you already have the examples-freshness pattern — reuse it). Low · small.

**Nit:** `_max_result` uses `>=`, so a later candidate at *equal* rank replaces an earlier explanation — candidate ordering silently decides what the user reads. Intentional? Document or use `>`.

### 1.4 controls.py — sound loader, but mappings are coarser than the marketing

Schema validation with JSONPath-style error locations is genuinely good. The catalogs: SOC 2 (63 mappings), ISO 27001:2022 (63), HIPAA (57), PCI DSS 4.0 (42), FedRAMP (43, keyed to NIST 800-53 r5), HITRUST (40).

**CTRL-1 · Mapping is (resource_type, action) → controls, ignoring risk tier and change content.** Medium · medium. Creating an S3 bucket and making it public can map to the same CC6.x set. Auditors will notice that the "evidence" doesn't distinguish them. Tier-aware mappings (or rule-triggered control additions) would make the evidence meaningfully stronger.

**CTRL-2 · Honesty gap on completeness.** High · small (it's a docs fix). "All Annex A controls mapped?" — no: ISO has 14 distinct control IDs across 63 mappings; Annex A 2022 has 93 controls. Same shape for the others (SOC 2: 9 distinct IDs; HIPAA: 10; FedRAMP: 18 of ~300+ Moderate controls). That's *fine* — IaC plans only touch a subset of any framework — but say so explicitly: "readtheplan maps the controls that infrastructure changes can affect; it is not a full-framework compliance tool." FedRAMP especially: shipping a `fedramp_moderate` catalog with 18 control IDs invites a bruising conversation with the first fed-adjacent prospect. Label it experimental or document the scoping rationale, and don't let the site's chat agent say "308 total control mappings" as if that means framework coverage.

### 1.5 evidence.py / attestation.py — well-built, one naming landmine

Envelope contents are right: schema tag, UTC timestamp, plan SHA-256, framework version, per-change controls, controls_touched rollup. Validation is strict. The header-attestation mini-format (`rtp-attest-v1`) is tight.

**EV-1 · "agent_attestation" is self-reported metadata, not an attestation.** Medium · small (rename + docs). Unsigned, the envelope is a JSON file anyone can edit; the `signature` field sits null. It becomes trustworthy only with `--sign`. Auditors and security reviewers are exactly the people who will poke this. Either rename the unsigned form ("analysis record") or have the docs say plainly: *unsigned envelopes prove nothing; signing is the tamper-evidence*. Also true of `plan_sha256`: it binds the envelope to a plan file, but nothing proves the plan came from `terraform plan` (acknowledged in ADR 0008? — make it user-facing).

### 1.6 signing.py — real sigstore, brittle edges

Keyless signing with bundle + Rekor, identity-pinned verification *required* (refusing to verify without `--certificate-identity` is the correct hard-line default — many tools get this wrong).

**SIGN-1 · Reaches into sigstore private API.** `from sigstore._internal.rekor.client import RekorClient` and `verifier._rekor = ...` will break on a minor sigstore bump; the pin `>=4,<5` doesn't protect against internal moves. Medium · medium — ask upstream for a public hook or vendor a thin client.
**SIGN-2 · 43% test coverage** on the module that backs your "audit-proof" claim, and `verify_envelope` requires the same canonicalization on both ends (`sort_keys`, `,`/`:` separators) — an untested re-serialization drift breaks every old signature. Add round-trip and *golden-envelope* tests (a checked-in signed envelope that must verify forever). High · medium.
**SIGN-3 · Identity UX.** CI verification needs an exact workflow-ref identity string; one typo = generic failure. Offer `--certificate-identity-regexp` (cosign parity) and a documented copy-paste block for GitHub OIDC. Low–medium · small.

### 1.7 agent_gate.py — your best idea; protect it with a spec

Deterministic risk→decision mapping, `allowed/prohibited_next_actions`, ready-to-post `pr_comment`, evidence checklist, auditor summary. Unknown risk strings conservatively map to `warn` — good. Empty plan → `proceed` — correct (a gate that errors on no-change plans would train people to bypass it).

**GATE-1 · The contract has no spec document.** `rtp-agent-gate-v1` is defined by implementation + one example JSON. If you want Claude Code/Codex/Cline to integrate, publish a versioned JSON Schema with stability guarantees ("`decision` is the only field you may branch on; everything else is informational"). High · small. *(Check: this overlaps ADR 0012's preview framing — the schema should live with the ADR but be published on the site.)*
**GATE-2 · `_flagged_changes` truncates to 5 with no indication.** A 50-dangerous-change plan shows 5 flagged resources in the PR comment with no "…and 45 more". An agent or human reading it underestimates blast radius. Small fix: add the count. Medium · small.
**GATE-3 · MCP timeout/rate-limit questions (FABLE prompt §5) are non-issues today** — local stdio, no network, sub-second on 10k resources. Document that explicitly as a selling point ("no timeout class of failures") rather than leaving agents' authors to wonder.

### 1.8 summary.py — fine. 36 lines, does one thing. The `zip()` over parallel lists is mildly fragile to refactors; nit.

### 1.9 attestation vs evidence — naming confusion is real

FABLE prompt asks "attestation — different from evidence, how?" and the honest answer is: `attestation.py` is a *plan-read receipt* (agent X read plan-hash Y at time Z), `evidence.py` is the *full analysis envelope* that embeds one. The names don't communicate that hierarchy, and `agent_attestation` inside the envelope vs. the standalone header format share a name but not a shape. A docs paragraph (or renaming to `plan_read_receipt`) would save every future integrator the same hour of source-reading I spent. Medium · small.

### 1.10 overlays.py — the design decision is right; one gap

Monotonic-only overrides (can escalate, never downgrade) answers the "custom rule collision" scenario cleanly: built-in floor wins, the higher risk always survives, explanations are appended not replaced. Verified hands-on: a `risk: safe` override on an RDS delete is silently ignored.

**OVL-1 · Silently ignored is the problem.** A platform team that writes a downgrade override gets no feedback that their YAML did nothing. Emit a warning to stderr ("override X would lower risk and was skipped — overlays can only escalate, see ADR 0010"). Medium · small.
**OVL-2 · No `address_regex`/glob matching and no action matching in `match` — `address_prefix` only goes so far for module-heavy repos (`module.foo[3].aws_db_instance.x`). Medium · medium.
**OVL-3 · `apply_overlay_to_catalog` reaches into `catalog._mappings` (private attr) — move that into a `ControlCatalog.with_additions()` method. Nit.

### 1.11 mcp_server.py — small, careful, under-documented

`MCP_ROOT` path-confinement with symlink resolution, structured error codes, no raw-plan logging — this is more security thought than most MCP servers get. Three tools: `analyze_plan`, `agent_gate`, `agent_gate_cloudformation`.

Gaps: `MCP_ROOT` is opt-in and undocumented outside docstrings (default = the agent can read any path the process can — document the env var prominently, consider warning when unset). The CFN tool oddly takes no `framework` arg while the CLI version does — inconsistency, small. No MCP resource/prompt surface — fine for preview.

### 1.12 adapters/ — right abstraction, second adapter will be the test

`BaseAdapter` (can_handle/extract/normalize + shared rules via `_metadata.before/after`) is a credible port surface; the CFN template-diff path even feeds real before/after into the deep rules. Weaknesses: Change-Set-format entries carry no before/after (AWS doesn't provide it — worth documenting that CFN Change Set analysis is action-level only); `Replacement: "Conditional"` → `review` is sensible but loses the "True" signal when `Details` exist; the `_TYPE_MAP` fallback `aws_rds_dbinstance`-style strings will never match rules or catalogs (harmless but dead). A Pulumi adapter (preview JSON has rich diffs) would be the proof the abstraction holds — and is a better next adapter than CDK (which synthesizes to CFN anyway, a docs recipe not an adapter).

---

## 2. Test suite

207 passing, ~12s, deterministic, no network. Quality is decent — table-driven, edge-casey in places (controls/overlays/evidence validation tests are thorough). The drift-prevention tests (`test_examples_fresh`, `test_adr_docs`, ADR/site contract tests, JS classifier parity in CI) are unusually mature for a project this size.

**TEST-1 · The coverage number is misleading: rules.py is at 71% with entire candidate families untested** — large swaths of ECS, LB, Lambda, network-topology, and observability rule branches (lines ~394–478, ~993–1254) have zero assertions. The 78% gate is met by thoroughly-tested *plumbing* subsidizing an under-tested *product core*. Severity high · medium effort. Recommendation: per-module coverage floors (`rules.py ≥ 90%`), or better, a table-driven test that iterates every resource family × action × trigger-attribute. signing.py at 43% — see SIGN-2.
**TEST-2 · Not tested anywhere:** binary input (would have caught CLI-1), the `analyze` traceback path (CLI-2), huge-plan smoke, non-UTF-8, deprecated-runtime list freshness, MCP_ROOT symlink escape attempts (the *feature* is tested; adversarial cases lightly).
**TEST-3 · No integration test against real `terraform show -json` output** across TF 1.6→1.9/OpenTofu. You parse so defensively that you'll likely survive format drift, but a corpus of real captured plans per version (even 5 files) turns "probably compatible" into a CI fact. Medium · medium. *(Format-version risk is genuinely low — `resource_changes[].change.actions` has been stable since TF 0.12 — but say that in docs with receipts.)*

---

## 3. Website & docs

Reviewed structurally (file tree, key pages, functions); not pixel-by-pixel.

- **Docs pages:** quickstart, CLI, GitHub Action, MCP (`site/mcp/`), plus repo-side `authoring-rules.md` — which is *excellent* and buried. It's your contributor funnel; surface it on the site nav. Medium · small.
- **Demo/playground:** the in-browser JS classifier with a Python-parity test in CI is the right call (most projects let the JS drift). 825 lines of JS reimplementation is still a tax — long-term, consider Pyodide or WASM to run the *actual* engine in-browser and delete the parity problem.
- **Blog:** an index and nothing else. Either write the three obvious posts (the four-tier taxonomy rationale; "your AI agent shouldn't terraform apply"; anatomy of an evidence envelope) or remove the nav link — an empty blog signals abandonment. The SEO resource pages (`terraform-s3-bucket-risk` etc.) are a smart wedge.
- **Chat agent (`functions/api/chat.js`):** three problems. (a) It proxies to **DeepSeek** — your homepage says "no uploads, no accounts"; a visitor pasting plan snippets into chat is shipping them to a third-party LLM with no disclosure. Add a notice or drop the feature. High · small. (b) The system prompt contains **factual errors the agent will confidently repeat**: `uses: readtheplan/readtheplan@v1` (no v1 tag exists — pins `@v0.3.0` everywhere else; this is the exact class of drift your freshness tests exist to catch — extend them to the chat prompt), and `terraform plan -out=/dev/stdout` piping, which is not how the tool works. (c) It advertises an Enterprise tier "in development" — see Positioning.
- **Pricing page:** exists with an Enterprise tier for a project with ~5 commits and one maintainer. Premature pricing pages *reduce* OSS trust. Either make it "Free & open source — enterprise conversations welcome, email us" or remove it until there's something to sell.

---

## 4. Developer experience & repo hygiene

Mostly strong: CODEOWNERS ✓, Dependabot (actions+pip+npm) ✓, issue templates ✓, PR template with DCO + AI-disclosure ✓, AGENTS.md ✓ (concise and actually useful), CONTRIBUTING with named good-first-issues ✓, conventional commits ✓.

- **Windows:** pure-Python, no platform-specific code paths spotted; `Path` used throughout. The ADR 0003 sample even shows a Windows path. No CI matrix entry for Windows/macOS though — pytest runs on ubuntu only. Add a 3-OS × {3.10, 3.13} matrix; it's cheap insurance for a `pip install` tool. Medium · small.
- **Ruff gate is nearly decorative** — `select = ["E9","F63","F7","F82"]` with an acknowledged backlog comment. The comment says 11 of 13 nits are auto-fixable: run the fix, ratchet to `E,F,I,UP`. Low · small.
- **README** is genuinely good — comparison table, honest "what's not in scope", reproducible examples. The coverage badge is hardcoded at 78% (will drift; generate it or drop it). The "Read the full story" link points to a personal repo (`texasich/sre-field-notes`) — fine, but verify it exists; a 404 in the README's emotional centerpiece would hurt.
- **Single maintainer everywhere** (CODEOWNERS `* @texasich`) — bus factor 1 is normal at this stage but worth an explicit SECURITY.md note about response-time expectations.

---

## 5. Compliance & security posture

- **"No uploads" holds** for CLI/Action/MCP — verified: zero network calls in the analysis path (`sign`/`verify` contact sigstore/Rekor, which docs should state plainly — an air-gapped user running `--sign` will be surprised; network-failure behavior of the *analysis* path is "no network used, nothing to fail," a genuine differentiator worth a docs line). The hosted analyzer is correctly fenced behind ADR 0013 (default-deny, Class-A forbid list, retention SLA — this ADR is better than most companies' actual DPAs) with `tests/hosted_security/` red-tests already in place *before* implementation. That sequencing — tests and boundary before feature — is the most reassuring thing in the repo. The chat endpoint is the one live contradiction (see above).
- **Catalog completeness vs. claims** — see CTRL-2. The gap isn't the catalogs, it's the adjectives near them.
- **Evidence tamper-proofing** — unsigned: none (see EV-1); signed: solid modulo SIGN-1/2. "How does an auditor verify?" needs a literal copy-paste page: the exact `readtheplan verify` invocation with identity pinning, what Rekor inclusion proves, and what it doesn't.

## 6. ADR disagreements (requested)

I read the ADR index and key ADRs (0003, 0013; others by title/summary). Two pushbacks:

1. **ADR 0013 sets release gates for a hosted analyzer that arguably shouldn't exist.** The differentiator this whole product leans on is *local-only*. A hosted analyzer — however well-boundaried — converts your sharpest competitive line ("Spacelift/env0 are SaaS; we aren't") into "we're also SaaS, but carefully." The ADR is excellent defensive work; my disagreement is strategic: the README already lists "SaaS dashboard" as out of scope, while site routes (`/analysis`, `/functions/api`, hosted-security gates) keep the option warm. Decide. If hosted stays on the roadmap, the differentiator should be reworded now ("local-first, hosted optional, plans never persisted") so launch day isn't a repositioning.
2. **ADR status hygiene:** 0003 and 0013 are marked "Proposed" while their content ships in v0.3.0 / gates CI. If it's implemented and enforced, it's Accepted. Auditors and contributors both read Status lines literally. Small fix.

(ADR 0003's four-tier taxonomy itself: no disagreement — four tiers with monotonic escalation is the right size. Five would invite bikeshedding, three loses the dangerous/irreversible split that justifies the product.)

## 7. Competitive positioning

The comparison table is the best on any tool site in this category, and the differentiator (plan-diff risk tiers + evidence + agent gate, local-only) is real — checkov/tfsec analyze *code posture*, you analyze *this specific apply's blast radius*. Two sharpenings:

- **Primary user is muddled across surfaces.** README speaks to five personas; the pricing page implies enterprise compliance buyers; the agent gate speaks to AI-tooling builders. The wedge with the least competition and the most growth is the **agent gate** — nobody else has a deterministic proceed/warn/block contract for coding agents, and the number of agents running `terraform apply` is only going up. Lead with it; let compliance evidence be the enterprise-expansion story, not the front door.
- **OPA/Sentinel is your real competitor objection** ("we already gate with policy-as-code"). The honest answer — readtheplan ships *opinionated curated rules + explanations + evidence* out of the box, vs. a blank policy language — should be an explicit docs/FAQ section, not left for the prospect to figure out.
- **Pricing:** see site note — don't run a pricing page before the open-source flywheel turns.

## 8. Scenario checklist (FABLE prompt §"Scenarios", condensed)

| # | Scenario | Result |
|---|---|---|
| 1 | Empty plan | ✅ "0 changes", exit 0, gate=proceed — correct |
| 2 | 10k resources | ✅ 0.35s, flat memory — a non-issue; say so in docs |
| 3 | Malformed | ⚠️ truncated JSON: good error; **binary: traceback (CLI-1); deep nesting: traceback** |
| 4 | CI exit codes | ❌ no thresholds in CLI (CLI-3); Action-only via bash glue |
| 5 | Agent/MCP timeout | ✅ non-issue (local, fast); document it |
| 6 | Multi-provider | ⚠️ parses fine; non-AWS = baseline-only with no indication (RULES-1) |
| 7 | Sensitive values | ❌ `*_sensitive` structures ignored (RULES-2) |
| 8 | Terragrunt | ✅ works (terragrunt emits standard plan JSON via `terragrunt show -json`); needs a docs recipe — zero code |
| 9 | TFC/TFE remote plans | ⚠️ JSON from TFC API's `plan-export`/`json-output` endpoint should parse; untested, undocumented — a docs recipe + one fixture |
| 10 | OpenTofu | ✅ parses; explanations still say "Terraform" — wire the existing `tool_name` plumbing to detect tofu version strings |
| 11 | Override collisions | ✅ higher risk wins, monotonic; ❌ silent no-op on downgrades (OVL-1) |
| 12 | Network failure | ✅ analysis path makes zero network calls; only `--sign`/`verify` need sigstore — document |
| 13 | TF 1.6–1.9 formats | ⚠️ likely fine (stable fields, defensive parsing) but unproven — version corpus (TEST-3) |

---

## Top 10 priorities, ranked by value ÷ effort

1. **Fix the crash-paths: binary plan, uncaught PlanError, RecursionError → friendly errors + tests (CLI-1, CLI-2).** A risk tool that stack-traces on the most common user error loses the user in their first 60 seconds. Highest adoption impact per line changed.
2. **Add `--fail-on <tier>` to `analyze` and meaningful exit codes to `agent-gate` (CLI-3).** Unlocks every non-GitHub CI system and shell-script gating with ~40 lines.
3. **Publish the `rtp-agent-gate-v1` JSON Schema + integration guide for Claude Code/Codex/Cline (GATE-1).** Your most defensible feature, currently spec'd only by example. This is the adoption wedge — make it trivially integrable.
4. **Warn on not-a-plan input (missing `format_version` + `resource_changes`) (plan.py).** Kills the silent false-"all safe" failure mode — the worst possible failure for this product category.
5. **Add `rule_source` (resource-rule vs action-baseline) to output (RULES-1).** One field; converts your biggest blind spot (coverage opacity) into honest signal, and quietly markets rule coverage as it grows.
6. **Raise rules.py to ≥90% via table-driven family×action×trigger tests; add signing golden-envelope round-trip (TEST-1, SIGN-2).** Protects the product core and the audit-proof claim from regression.
7. **Fix the chat agent: disclose the DeepSeek proxy (or drop chat), correct `@v1` and `/dev/stdout` falsehoods, fold the prompt into the freshness tests.** It's currently the only thing on the site contradicting both your privacy stance and your own docs.
8. **Docs recipes: Terragrunt, TFC API pull, OpenTofu note, air-gap/network-behavior statement, auditor verification walkthrough.** All zero-code, all answer real pre-adoption objections.
9. **CI matrix: {ubuntu, macos, windows} × {3.10, 3.13}; ratchet ruff.** Cheap insurance for a `pip install`-distributed tool.
10. **Honesty pass on compliance scope (CTRL-2) + pricing page rethink + ADR status hygiene.** Costs a day, protects the asset that makes a compliance tool viable: being more truthful than your marketing needs you to be.

*Deliberately not in the top 10:* declarative rules refactor (RULES-3 — right idea, wrong quarter), Pulumi adapter (do it after the gate spec ships), Pyodide playground, tab completion.
