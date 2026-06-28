# readtheplan — Field Test of the Published Package (PyPI v0.3.0)

**Date:** 2026-06-11 · **Tester:** Claude (Fable 5)
**Method:** `pip install readtheplan` (and `readtheplan[mcp]`) into a clean venv, then drove it through a real CI gate — replayed `action.yml`'s analyze/threshold step verbatim against the released wheel, ran the MCP server over JSON-RPC stdio, generated evidence envelopes, and diffed the published artifact against the `main` working tree.

This complements `ARCH_REVIEW-2026-06-11.md` (which reviewed source). **Everything here was run against the wheel a user actually gets from `pip install readtheplan`.**

---

## Headline finding: the published wheel is significantly behind `main`

The PyPI 0.3.0 artifact is **not** the code in the repo. Diff of installed package vs. `src/`:

| Module | Changed lines (wheel → main) | What's missing from the release |
|---|---|---|
| `rules.py` | 338 | The entire `__TOOL__` sentinel mechanism, ECS/SG/ECR/SQS/Glue/Lambda-deprecation rule families. **Released `rules.py` has 11 `*_candidates` families; `main` has 13** (no `_ecs_service_candidates`, no `_security_group_candidates`). |
| `mcp_server.py` | 146 | **`MCP_ROOT` path-confinement does not exist in the release** (0 references vs. 5 on main). The headline security feature of the MCP server is unreleased. |
| `cli.py` | 129 | `--version`, the `verify` identity flags (`--certificate-identity`, `--certificate-oidc-issuer`), CFN subcommand wiring. |
| `signing.py` | 95 | Identity-pinned verification path. |
| `plan.py` | 10 | The `dict`-input path used by overlays. |
| `data/controls/` | — | **Release ships 3 catalogs (soc2, iso27001, hipaa). `main` has 6** (adds pci_dss, hitrust, fedramp_moderate). |

**Why this matters more than any single bug:** the README, site, and docs describe `main`. A user who runs `pip install readtheplan` today gets a tool that, for example, **does not classify `aws_security_group` rules** (the site's own SEO landing page `terraform-security-group-0-0-0-0-risk` advertises exactly this) and **silently classifies a security-group change opening `0.0.0.0/0` as `review`, not `dangerous`** — confirmed by running it:

```
$ readtheplan analyze --format json sg-open-to-world.json
review | Terraform will update this resource in place. Review the changed attri…
```

That's the single most-cited example in the marketing, and the shipped tool gets it wrong because the rule isn't in the wheel.

**Severity: critical.** Recommendation: cut a `0.4.0` from current `main` immediately, or pull the doc/site claims back to what 0.3.0 actually does. The gap between "what we say" and "what `pip install` gives you" is the fastest way to lose a security-minded first user. This also explains the `@v1` references — there is no `v1` tag (`git tag` shows only `v0.0.2`, `v0.3.0`).

---

## What works well on the released wheel

- **CI threshold gating (Style A) is correct.** Replaying `action.yml`'s analyze step against 0.3.0:

  | Plan | Setting | Result | Correct? |
  |---|---|---|---|
  | dangerous-replacement | `fail-on-threshold: dangerous` | exit 1, `::error::found 2 dangerous changes` | ✅ |
  | small-create | `fail-on-threshold: dangerous` | exit 0, full outputs + step summary | ✅ |
  | small-create | `fail-on-any-change: true` | exit 1 | ✅ |
  | empty | `fail-on-threshold: review` | exit 0 | ✅ |

- **MCP server runs and is well-behaved.** `initialize` → `tools/list` → `tools/call` over stdio all succeed; exposes `analyze_plan`, `agent_gate`, `agent_gate_cloudformation`. `agent_gate` on an RDS-delete returned `block / irreversible / 5 required checks`. **But:** because `MCP_ROOT` isn't in the release, the server will read any path the process can — the path-confinement you built on `main` ships to nobody yet. An out-of-root path is only rejected incidentally (it failed as invalid JSON, not as a traversal block).

- **Evidence envelopes generate cleanly** with `--framework soc2 --evidence --run-id --reviewer-id`. The `plan.sha256` correctly equals `sha256sum plan.json` (verified: `873ecb53…`), so the envelope genuinely binds to the plan file. `controls_touched` rolls up as expected. `signature: null` when unsigned — reinforces review finding EV-1: the unsigned envelope is self-reported, not tamper-evident.

- **Performance / scale:** 10,000-resource plan analyzed in ~0.35s, flat memory. Empty plan → `proceed`. These are non-issues; market them as such.

## Bugs reproduced on the released wheel (not just in source)

1. **Binary plan → `UnicodeDecodeError` traceback** (CLI-1). Passing the raw `tfplan` — the mistake your own troubleshooting docs anticipate — stack-traces through `action.yml` too: the action surfaces a `::error::` *and* dumps the full Python traceback into the CI log. Confirmed end-to-end.
2. **Bad `resource_changes` type → `PlanError` traceback** on `analyze` (CLI-2). `agent-gate` handles it; `analyze` doesn't.
3. **No CLI exit-code gating** (CLI-3): `agent-gate` exits 0 even on `block`. Verified. This is what forces the wrapper script below.

## The deliverable: a gate that works *today*, on 0.3.0

Since the CLI can't gate by exit code, I wrote and tested `ci/readtheplan-gate.sh`. It runs `agent-gate`, maps the decision to exit codes (**0=proceed, 2=warn, 1=block**), writes `gate.json` + a ready-to-post `gate-comment.md`, **fails closed** on unknown decisions, and **pre-checks for the binary-plan footgun** so your pipeline gets a one-line hint instead of a traceback. Full validation run:

| Input | Mode | Decision | Exit | Correct? |
|---|---|---|---|---|
| dangerous-replacement + soc2 | default | block | 1 | ✅ |
| small-create | default | warn | 2 | ✅ |
| small-create | `--warn-ok` | warn | 0 | ✅ |
| empty | default | proceed | 0 | ✅ |
| binary tfplan | default | (caught pre-flight) | 1 + hint | ✅ |

Paired with `ci/terraform-gate.example.yml` — a complete GitHub Actions workflow showing both the official-action threshold gate and the agent-gate/exit-code style, plus PR-comment posting and evidence-artifact upload. The script is dependency-free bash+python3 and drops into GitLab/Jenkins/Buildkite unchanged.

## Recommended priority order (updated after field testing)

0. **Release `main` as 0.4.0 (or retract the doc claims).** This now outranks everything in the source review — the shipped tool misses its own flagship example (security-group `0.0.0.0/0`) and ships the MCP server without its `MCP_ROOT` guard. Nothing else matters if `pip install` gives users a tool that doesn't match the pitch.
1–10. As in `ARCH_REVIEW-2026-06-11.md`. The crash-path fix (CLI-1/2) and `--fail-on` exit codes (CLI-3) remain the top code changes; both are validated as still-broken on the wheel.

## Files delivered
- `ci/readtheplan-gate.sh` — portable, tested CI gate (exit-code contract, fail-closed, binary-plan guard).
- `ci/terraform-gate.example.yml` — full GitHub Actions pipeline (both gating styles + PR comment + evidence upload).
