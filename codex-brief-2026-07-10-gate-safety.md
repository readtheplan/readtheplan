# Codex brief — 2026-07-10 — Gate-safety hardening (review findings 1–3)

## Context

Your 2026-07-10 review of `main@22a6b54` flagged six issues. This brief covers
the three safety-critical ones. Findings 4–6 (install-safety, import side
effects, plan hash) follow in a separate brief after this merges.

Red tests encoding the required behavior are on branch
`red/gate-safety-hardening` in `tests/test_gate_safety_hardening.py`.
On `main@22a6b54` they fail 8/10 (two are guard tests). Your implementation
must make all 10 pass without weakening any assertion.

## Instructions

Start from the red branch so the tests are present:

```
git fetch origin red/gate-safety-hardening
git checkout -b fix/gate-safety-hardening origin/red/gate-safety-hardening
```

Make exactly these three changes; nothing else.

### 1. Disable generated-rule auto-activation

Files: `src/readtheplan/evolution.py` (~line 321 onward, `analyze_with_agents`),
`src/readtheplan/rules/_shared.py` (~line 527, `_load_auto_rules`).

- `_evolve_decision` must never return `auto-merge`. Maximum autonomous
  status is `pr-ready`; below threshold stays `disabled`.
- Rule generation must not write any file into the installed package
  (`src/readtheplan/rules/`) or the repository `tests/` tree. Confine all
  candidate artifacts (rule code, validation test, handoffs) to the engine
  `data_dir` (default `~/.readtheplan/`).
- `_load_auto_rules` in `_shared.py` must not create directories or
  `__init__.py` files at import time, and must not import arbitrary modules
  dropped into `rules/auto/`. Only rules explicitly approved via a new
  `readtheplan evolve approve <rule-id>` CLI command may be loaded, from an
  approved-rules store in the data dir (not the package dir).
- Replace the tautological generated validation test: the generated check
  must also assert the rule does NOT fire on a counterexample (e.g. a
  no-op/read-only change), so a rule that fires on everything scores 0.

### 2. Fix Kubernetes diff coverage

Files: `src/readtheplan/adapters/kubernetes.py` (~line 68,
`_get_properties_for_rules`; also Add/Remove payloads), `src/readtheplan/rules/k8s.py`
(~line 179, RBAC rule registration).

- `_get_properties_for_rules` currently keeps only `metadata.labels`,
  `metadata.annotations`, `spec`, and `data`. It must also carry top-level
  `rules` (Role/ClusterRole), `roleRef` and `subjects` (bindings),
  `stringData` and `binaryData` (Secret/ConfigMap), and `type` (Secret). A
  change confined to any of these fields must produce a Modify change, never
  an empty diff / `proceed`.
- Register `kubernetes_role` in the RBAC candidates rule alongside
  cluster_role / cluster_role_binding / role_binding.
- Add a wildcard check: a Role or ClusterRole whose `rules` grant
  `apiGroups: ["*"]` / `resources: ["*"]` / `verbs: ["*"]` (any of them on
  create or update) must classify at least `review`, never `safe`. Use the
  `_metadata.before/after` payload the adapter emits for Modify, and the
  Spec/rules payload for Add.

### 3. Enforce MCP_ROOT for the Kubernetes MCP handler

File: `src/readtheplan/mcp_server.py` (~line 166, `agent_gate_kubernetes`).

- Route `input_path` through the same `_resolve_path` used by `agent_gate`
  and `agent_gate_cloudformation`, so `MCP_ROOT` confinement raises
  `MCPToolInputError` with code `PATH_TRAVERSAL` for paths outside the root.

## Gates (all must pass)

- `ruff check .`
- `pytest` — full suite including `tests/test_gate_safety_hardening.py`
  (10/10), coverage ≥ 78
- `scripts/regenerate-examples.sh` (rules changed)
- Site parity checks (113)
- Python 3.10 and 3.13

## PR

- Title: `fix: gate-safety hardening — rule auto-activation, k8s diff coverage, MCP_ROOT (review 2026-07-10, findings 1-3)`
- Note AI assistance in the PR body (project norm). No `AI-Assisted:` commit
  trailers.
- Do not modify or delete the red tests; extend with additional tests as
  needed.
