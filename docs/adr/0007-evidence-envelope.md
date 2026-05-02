# ADR 0007: Evidence Envelope

## Status

Accepted

## Context

ADRs 0005 and 0006 give every Terraform resource change a control-ID
annotation under one of two compliance frameworks (SOC 2 or ISO 27001).
The output today is either a markdown table or a JSON object embedded in
the existing analyze output — useful at PR-review time, but not yet a
single document a compliance reviewer or a GRC platform can consume as
*the* evidence artifact for a change.

The downstream consumers all want roughly the same thing:

- **Auditors** (SOC 2 Type II, ISO 27001) want a self-contained document
  per change that records what changed, which controls were touched, who
  reviewed it, and a hash that ties it to the source plan.
- **GRC platforms** (Vanta, Drata, Tugboat Logic, ServiceNow GRC) accept
  JSON evidence webhooks; their schemas vary, but every one of them needs
  a stable, namespaced JSON shape on the readtheplan side.
- **Future signed attestation** (ADR 0008, upcoming) needs a fixed payload
  to sign. That payload should be the evidence envelope, not the raw
  analyze output, so the signature covers everything an auditor cares
  about — change set + controls + reviewer + plan hash — in one go.

`src/readtheplan/attestation.py` already defines a `PlanReadAttestation`
dataclass and a `plan_sha256` helper, both built for MVP-3 but not yet
wired into the analyze CLI. The envelope embeds that attestation as one
field rather than reinventing it.

## Decision

Introduce an **evidence envelope**: a versioned JSON document that wraps,
in one stable structure, everything a downstream consumer needs:

- The compliance framework view (controls per change, framework metadata)
- The plan-read attestation (agent ID, read time, plan hash, source)
- The reviewer identity (optional, human or agent)
- The plan summary (action counts, risk counts, change list)
- A schema version that downstream tools can pin against

The envelope is produced by a new `src/readtheplan/evidence.py` module
and surfaced via a new `--evidence <path>` flag on `analyze`. It is
**read-only relative to ADRs 0003, 0004, 0005, 0006, and the existing
`attestation.py` module** — purely additive, no behavior change to any
existing surface.

### Schema (rtp-evidence-v1)

```json
{
  "schema": "rtp-evidence-v1",
  "generated_at": "2026-05-02T18:24:11Z",
  "plan": {
    "source": "terraform-show-json",
    "sha256": "9f86d081…"
  },
  "framework": {
    "name": "soc2",
    "version": "2017-tsc",
    "schema_version": 1
  },
  "agent_attestation": {
    "agent": "readtheplan@0.0.2",
    "read_at": "2026-05-02T18:24:11Z",
    "plan_sha256": "9f86d081…",
    "source": "terraform-show-json",
    "run_id": "github-actions/12345",
    "signature": null
  },
  "reviewer": {
    "id": "texasich",
    "kind": "human"
  },
  "summary": {
    "resource_change_count": 3,
    "actions": {"create": 1, "delete/create": 1, "update": 1},
    "risks": {"safe": 1, "review": 1, "dangerous": 1},
    "controls_touched": ["A1.2", "C1.1", "CC6.1", "CC6.7", "CC8.1"]
  },
  "changes": [
    {
      "address": "aws_kms_key.customer_data",
      "type": "aws_kms_key",
      "actions": ["delete", "create"],
      "risk": "dangerous",
      "explanation": "...",
      "rule_id": "kms-replace",
      "controls": [
        {"id": "CC6.1", "title": "...", "rationale": "..."},
        {"id": "CC6.7", "title": "...", "rationale": "..."}
      ]
    }
  ]
}
```

Schema rules:

- **`schema`** is the literal string `"rtp-evidence-v1"`. Any future
  breaking change ships as `rtp-evidence-v2` and lives alongside v1
  during a deprecation window. Adding a non-required field is not a
  breaking change.
- **`generated_at`** is ISO 8601 in UTC with the `Z` suffix.
- **`plan.sha256`** is the SHA-256 of the raw plan JSON bytes — same
  algorithm as `attestation.plan_sha256` (re-used, not reimplemented).
- **`framework`** object is required; the envelope is meaningless without
  one. CLI enforces this — `--evidence` requires `--framework`.
- **`agent_attestation`** is the existing `PlanReadAttestation` dataclass
  serialized to a dict. `signature` is `null` until ADR 0008 lands.
- **`reviewer`** is optional and may be `null`. When set, `kind` is one
  of `"human"` or `"agent"`. Empty string is not allowed; either omit
  the object or set the id.
- **`summary.controls_touched`** is the sorted, deduplicated union of
  every control ID across `changes[*].controls`. Provided for fast
  "which controls did this change touch" lookups without re-walking
  the full change list.
- **`changes[]`** keeps the same shape as the existing JSON output of
  `analyze --format json --framework <name>`, deduplicated to stay
  consistent with that surface.

### CLI surface

```
readtheplan analyze --framework soc2 --evidence evidence.json plan.json
```

Behavior:

- `--evidence <path>` writes the envelope JSON to `<path>`. Use `-` for
  stdout.
- `--evidence` requires `--framework`. Without it, exit non-zero with a
  clear error message.
- `--agent-id <id>` (optional) sets the `agent_attestation.agent` value.
  Default: `"readtheplan@<package_version>"`.
- `--reviewer-id <id>` (optional) sets `reviewer.id`. If unset, the
  envelope's `reviewer` field is `null`. `--reviewer-kind <human|agent>`
  is also optional; defaults to `"human"`.
- `--run-id <id>` (optional) sets `agent_attestation.run_id`. Useful for
  CI environments — e.g. `--run-id "github-actions/${GITHUB_RUN_ID}"`.
- The existing `--format` flag does *not* change `--evidence`'s output —
  the envelope is always written as JSON regardless of `--format`.
  `--format` continues to control stdout (markdown vs JSON), and the
  envelope is an *additional* artifact written separately.

### Out of scope for this ADR

- Cryptographic signing (ADR 0008, next).
- Sigstore transparency log integration (ADR 0008).
- DSSE / in-toto bundling (ADR 0008).
- GRC platform webhooks (Vanta, Drata, ServiceNow GRC). The envelope is
  a stable shape; integrations bolt on later without changing it.
- Multi-framework evidence in one envelope. v1 is one framework per
  envelope. A future `rtp-evidence-v2` may add `frameworks: [...]`.
- PR-comment rendering of the envelope. Markdown rendering stays in the
  CLI's text format.
- Reading evidence envelopes (a `verify` subcommand). That belongs with
  signing in ADR 0008.

## Consequences

### Positive

- Gives auditors and GRC platforms one stable artifact instead of asking
  them to scrape the analyze output.
- Sets up signed attestation (ADR 0008) on a payload that already
  contains everything the signature should cover.
- Re-uses `attestation.PlanReadAttestation` and the existing rule /
  control output — no duplication, no parallel data structures.
- `controls_touched` summary field lets a dashboard render
  "10 changes, touched CC6.1 and CC8.1" without parsing every change.

### Negative

- One more output surface to maintain. Mitigation: schema version
  pinning, additive-only change policy.
- `--reviewer-id` opens a question of who the reviewer actually was. The
  CLI accepts whatever string the caller passes; trustworthy population
  is a CI / governance concern, not the tool's. Documented in README.
- The envelope is JSON, not signed JSON. Anyone can hand-edit the file
  and the contents are no longer "evidence." That gap is exactly what
  ADR 0008 closes.

### Maintenance contract

- The schema is versioned by the literal string `"rtp-evidence-v1"`.
  Breaking changes (renaming a field, changing semantics) require a v2
  schema and a deprecation window for v1.
- New optional fields can be added to v1 without bumping. Downstream
  consumers should ignore unknown fields.
- The `agent_attestation` field is contractually the serialized form of
  `PlanReadAttestation`; if that dataclass changes, this ADR's
  consequences need a re-read.

## Anchor

Same arc as ADRs 0005 and 0006 — the compliance-evidence pivot
articulated in the README and in `texasich/sre-field-notes` →
`notes/terraform-apply-is-roulette.md`. The envelope is the *artifact*
auditors actually walk away with. The framework catalogs are the *data*
that populates it.
