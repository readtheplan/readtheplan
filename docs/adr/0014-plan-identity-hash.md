# ADR 0014: Content-Based Plan Identity Hash

## Status

Accepted

## Context

The self-improving gate records every run in the evolution database keyed by a
"plan hash" (`_compute_plan_hash` in `agent_gate.py`). The 2026-07-10 review
(finding 6) showed the hash covers only the plan file path, the change count,
and the Terraform version:

```
raw = f"{summary.path}:{len(summary.resource_changes)}:{summary.terraform_version}"
sha256(raw)[:16]
```

Materially different plans collide whenever they share those three values —
for example, any two three-change plans produced at the same path by the same
Terraform version. Conversely, the identical plan analyzed from two different
working directories hashes differently. Both defects corrupt run identity in
the evolution audit trail: incident patterns, run dedup displays, and future
outcome attribution all assume the hash identifies plan *content*.

## Decision

Replace the hash input with a canonical JSON digest of the plan's intrinsic
content, versioned by an embedded schema tag:

1. **Payload** — a JSON object with:
   - `"schema": "rtp-plan-hash-v2"`
   - `"terraform_version"`: the plan's Terraform version string (or null)
   - `"changes"`: the list of resource changes, each reduced to
     `{"address", "type", "actions"}`
2. **Canonicalization**
   - Changes are sorted by `(address, type, actions)` so input ordering is
     irrelevant. `address` alone is not unique: Terraform's JSON format keys
     changes by `address` plus `deposed`, and `PlanSummary` drops `deposed`,
     so two same-address changes (current + deposed object) can coexist;
     including the actions tuple in the sort key keeps the ordering total
     and prevents input order from leaking into the digest.
   - Within a change, `actions` keeps its original order: Terraform
     distinguishes `["delete", "create"]` from `["create", "delete"]`
     (destroy-before-create vs create-before-destroy), so action order is
     identity-relevant.
   - JSON is serialized with sorted keys, compact separators
     (`","`, `":"`), and `ensure_ascii=False`; the UTF-8 encoding is hashed.
3. **Digest** — full 64-character lowercase SHA-256 hex digest. No
   truncation: the hash is an identity key, not a display string; callers
   may truncate for display.

**Excluded from the hash** (with rationale):

- `summary.path` — machine-local noise; the same plan content must hash
  identically everywhere.
- `risk`, `explanation`, `source` — derived by the rule engine, not plan
  content; a rules upgrade must not change the identity of an unchanged plan.
- Change count — implicit in the change list.

## Consequences

- Existing `evolution.db` rows keep their legacy 16-character hashes; new
  runs produce 64-character hashes. Rows are an append-only audit trail, so
  no migration is performed; the two generations are distinguishable by
  length, and the embedded schema tag versions any future change.
- The same plan analyzed anywhere now aggregates under one identity,
  making incident patterns and run history meaningful across checkouts
  and CI runners.
- Plans differing only in `before`/`after` values (not addresses or
  actions) still collide, because `ResourceChange` does not carry those
  fields today. Likewise, a current/deposed pair with identical actions is
  indistinguishable until `deposed` is captured. Extending the payload with
  a value digest and a `deposed` marker is a compatible future change under
  a `rtp-plan-hash-v3` tag.
