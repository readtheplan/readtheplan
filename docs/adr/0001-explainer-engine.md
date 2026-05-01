# ADR 0001: Explainer Engine

## Status

Proposed

## Context

`readtheplan` needs to explain Terraform plan risk in language a release
manager, auditor, or infrastructure reviewer can trust quickly.

There are three plausible approaches:

1. deterministic rules and templates;
2. LLM-generated explanations;
3. a hybrid where deterministic rules produce evidence and an LLM rewrites or
   expands the prose.

The first target audience is compliance-sensitive infrastructure teams. They
need output that is cheap to run in CI, reproducible across runs, easy to audit,
and safe to expose in GitHub Actions without sending plan data to a third-party
model by default.

## Decision

Use deterministic rules and templates for v0.1.

The explainer engine should:

- classify each Terraform `resource_changes[]` entry from structured JSON;
- use action-based taxonomy as the baseline;
- layer resource-aware rules on top;
- emit stable risk tiers and short plain-English explanations;
- avoid network calls and model dependencies in the default path.

LLM-generated explanations are deferred until after the deterministic rule
library covers the headline AWS patterns. If an LLM mode is added later, it must
be explicit opt-in and should consume structured rule output rather than raw
Terraform plans whenever possible.

## Consequences

### Positive

- CI output is deterministic and reproducible.
- The default tool remains free to run and easy to package.
- No Terraform plan data leaves the runner unless a future user explicitly opts
  into that behavior.
- Rule behavior can be tested with fixtures and reviewed like normal code.

### Negative

- Explanations may be less fluent than model-generated prose.
- Rule coverage grows incrementally, so early versions will miss some
  resource-specific nuance.
- Templates require careful writing to avoid vague or repetitive output.

### Neutral

- This does not prevent a later LLM layer.
- YAML customization remains a separate future decision.
