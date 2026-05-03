# ADR 0010: Customer-Supplied Rule Overrides

## Status

Proposed

## Context

The original MVP scope included YAML rule customization so teams can
express organization-specific review policy, such as "anything in
account 1234 is review." ADR 0004 established the built-in
resource-aware rule library, and ADR 0005 established framework-neutral
control catalogs. Those built-ins are intentionally conservative and
portable, but customers need a local layer for account, environment,
resource-name, and audit-scope differences.

This ADR adds a local overlay file that composes on top of built-in
risk classification and optional compliance catalogs. Built-in modules
remain unchanged; overlays are a wrapper around their output.

## Decision

Ship customer-supplied YAML overlays with schema `rtp-overlay-v1`.

```yaml
schema: rtp-overlay-v1
name: acme-prod-overlay
description: Acme Corp production environment overrides

risk_overrides:
  - match:
      resource_type: aws_kms_key
      address_prefix: aws_kms_key.prod_
    risk: irreversible
    explanation: Production KMS keys are tagged ePHI; deletion requires CISO sign-off
  - match:
      account_id: "1234567890"
    risk: review
    explanation: Sandbox account; all changes get human review

control_additions:
  framework: soc2
  mappings:
    - resource_type: aws_glue_job
      actions: [create, update, delete]
      controls:
        - id: CC6.1
          title: Logical and Physical Access Controls
          rationale: Glue jobs access ePHI in our pipeline
```

### Composition Order

Composition order is:

1. Built-in risk and catalog resolution.
2. Overlay control additions appended to a matching framework catalog.
3. Overlay risk overrides applied last to each resource change.

Risk overrides never downgrade. If an overlay specifies a lower risk
than the built-in result, the built-in result wins. Equal or higher risk
matches can append customer-specific explanation text.

### Multiple Files

`readtheplan analyze --rules-file <path>` is repeatable. Files are
loaded and applied in CLI order. Later overlays can add more controls or
escalate risk further, but still cannot downgrade.

### Schema Versioning

The schema string is the literal `rtp-overlay-v1`. Any breaking change
to match semantics, required fields, or composition order should ship as
a future v2 schema.

## Consequences

### Positive

- Completes the MVP customization item without changing built-in rule or
  catalog behavior.
- Lets customers encode local account and resource naming policy in a
  versioned file that can live beside Terraform code.
- Keeps compliance framework catalogs reusable while allowing
  customer-specific control additions.

### Negative

- Account matching depends on the plan or caller supplying an account
  identifier. Terraform plan JSON does not guarantee that field.
- Overlay files become part of the review contract and need code review
  like any other policy file.

## Out of Scope

- Removing controls.
- Downgrading built-in risk.
- Remote overlay URLs.
- Environment-variable-conditional overlays.
- New framework catalogs.
