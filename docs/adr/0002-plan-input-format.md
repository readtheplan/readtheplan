# ADR 0002: Plan Input Format

## Status

Proposed

## Context

Terraform exposes plan information in two common forms:

- human-readable text from `terraform plan`;
- structured JSON from `terraform show -json plan.tfplan`.

The human-readable format is optimized for terminal review. It is not a stable
machine contract and is difficult to parse safely across Terraform versions and
provider-specific output.

The JSON format exposes structured `resource_changes[]` entries, action arrays,
resource addresses, resource types, and before/after values. That is the data
needed by the action classifier and resource-aware rule library.

## Decision

Accept Terraform plan JSON only for v0.1.

The supported workflow is:

```bash
terraform plan -out plan.tfplan
terraform show -json plan.tfplan > plan.json
readtheplan analyze plan.json
```

The CLI should reject missing files, directories, empty files, invalid JSON, and
non-object top-level JSON. It should not attempt to parse text-only
`terraform plan` output.

## Consequences

### Positive

- The analyzer works from Terraform's structured data contract.
- Resource-aware rules can inspect action lists and before/after values without
  brittle string parsing.
- Error handling stays clear for CI and GitHub Actions.

### Negative

- Users must add the `terraform show -json` step.
- Copy-pasted text plans are out of scope for v0.1.

### Neutral

- A future text importer could be added as a separate command, but it should not
  weaken the JSON contract for `readtheplan analyze`.
