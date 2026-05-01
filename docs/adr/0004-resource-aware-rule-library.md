# ADR 0004: Resource-Aware Rule Library

## Status

Proposed

## Context

ADR 0003 defines the baseline action classifier for Terraform plan JSON:
`create` is `safe`, `update` is `review`, `delete/create` is `dangerous`, and
`delete` is `irreversible`.

That baseline is deterministic and useful, but it is intentionally blunt. The
README promise depends on resource-aware context: an in-place IAM trust policy
change, a public S3 bucket policy, and an RDS major-version upgrade are not
equivalent to generic updates.

## Decision

Add a default-on resource-aware rule layer on top of the action classifier.

The rule layer:

- receives one Terraform `resource_changes[]` entry at a time;
- starts from the ADR 0003 action-based risk;
- may escalate risk severity;
- must not silently downgrade `dangerous` or `irreversible`;
- emits a plain-English `changes[].explanation` string;
- can be disabled with `readtheplan analyze --no-rules` for action-only output.

Tier A covers the first high-blast-radius AWS resources:

| Resource type | Initial behavior |
| --- | --- |
| `aws_db_instance`, `aws_rds_cluster` | Explain replacements/deletes; escalate major `engine_version` updates to `dangerous`. |
| `aws_s3_bucket`, `aws_s3_bucket_acl`, `aws_s3_bucket_policy` | Explain bucket deletes; flag `force_destroy`; escalate public ACL or public bucket policy changes to `dangerous`. |
| `aws_kms_key` | Explain replacement and scheduled deletion risk for encrypted data. |
| `aws_iam_role`, `aws_iam_policy`, `aws_iam_role_policy` | Explain IAM authorization changes; escalate trust-policy edits and removed deny statements to `dangerous`. |
| `aws_route53_zone` | Explain hosted-zone replacement/deletion and DNS delegation risk. |
| `aws_eks_node_group` | Explain replacement/deletion as pod eviction, capacity churn, and cluster disruption risk. |

## JSON Compatibility

The existing stable fields from ADR 0003 remain unchanged:

- `resource_change_count`
- `actions`
- `risks`
- `changes[].address`
- `changes[].type`
- `changes[].actions`
- `changes[].risk`

This ADR adds one field:

- `changes[].explanation`: plain-English reason for the selected risk.

The new field is additive. Consumers that only read the MVP-1 fields can ignore
it.

## Consequences

### Positive

- Turns the CLI from a generic action summarizer into a useful plan reviewer for
  the first high-blast-radius AWS resources.
- Keeps behavior deterministic and auditable.
- Gives users a comparison path through `--no-rules`.
- Establishes the shape needed for later YAML overrides without committing to a
  config-file schema yet.

### Negative

- Rules are code-backed for now, not loaded from a user-editable YAML file.
- Tier A coverage is still incomplete relative to the README's full top-30 rule
  ambition.
- Some direct deletes remain over-classified as `irreversible` because the CLI
  has no verified backup or restore evidence.

### Neutral

- Plan-level risk is still derived from `changes[].risk`; it is not emitted as a
  separate field.
- LLM-generated explanations remain out of scope for v0.1.

## Acceptance Criteria

- Tier A rules have tests.
- `--no-rules` returns the action-only classifier result.
- Existing action counts and risk counts remain stable for the original fixture.
- GitHub Action output remains compatible with the JSON CLI contract.
