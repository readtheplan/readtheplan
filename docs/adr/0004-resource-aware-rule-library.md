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
- emits the selected `changes[].rule_id`;
- can be disabled with `readtheplan analyze --no-rules` for action-only output.
- can be extended with JSON/YAML organization overrides through
  `readtheplan analyze --rules-file <path>`.

Tier A covers the first high-blast-radius AWS resources:

| Resource type | Initial behavior |
| --- | --- |
| `aws_db_instance`, `aws_rds_cluster` | Explain replacements/deletes; escalate major `engine_version` updates to `dangerous`. |
| `aws_s3_bucket`, `aws_s3_bucket_acl`, `aws_s3_bucket_policy` | Explain bucket deletes; flag `force_destroy`; escalate public ACL or public bucket policy changes to `dangerous`. |
| `aws_kms_key` | Explain replacement and scheduled deletion risk for encrypted data. |
| `aws_iam_role`, `aws_iam_policy`, `aws_iam_role_policy` | Explain IAM authorization changes; escalate trust-policy edits and removed deny statements to `dangerous`. |
| `aws_route53_zone` | Explain hosted-zone replacement/deletion and DNS delegation risk. |
| `aws_eks_node_group` | Explain replacement/deletion as pod eviction, capacity churn, and cluster disruption risk. |

Tier B broadens coverage for the first `0.1.0` candidate with deterministic
blast-radius templates for network access controls, EBS volumes, Lambda, ECS,
load balancers, CloudFront, ACM certificates, Secrets Manager, SSM parameters,
VPC/subnet/NAT infrastructure, Cognito, DynamoDB, ElastiCache, RDS parameter
groups, Step Functions, EventBridge, SNS, SQS, API Gateway, Kinesis, OpenSearch,
IAM users, and IAM access keys.

Organization overrides are intentionally small. Each rule has a stable `id`,
optional fixed `risk` or `bump`, optional `explanation`, and a `match` block that
can use account IDs, tags, resource types, or address regexes. Overrides are
escalate-only when combined with the built-in classifier.

## JSON Compatibility

The existing stable fields from ADR 0003 remain unchanged:

- `resource_change_count`
- `risk_level`
- `actions`
- `risks`
- `changes[].address`
- `changes[].type`
- `changes[].actions`
- `changes[].risk`

This ADR adds two per-change fields:

- `changes[].explanation`: plain-English reason for the selected risk.
- `changes[].rule_id`: stable identifier for the action, built-in resource, or
  organization override rule that selected the emitted explanation.

The new fields are additive. Consumers that only read the MVP-1 fields can
ignore them.

## Consequences

### Positive

- Turns the CLI from a generic action summarizer into a useful plan reviewer for
  the first high-blast-radius AWS resources.
- Keeps behavior deterministic and auditable.
- Gives users a comparison path through `--no-rules`.
- Gives teams lightweight JSON/YAML overrides without becoming a general
  policy-as-code engine.

### Negative

- Tier B coverage is still coarse for several resource families and needs
  fixtures from real plans.
- YAML override support adds a small runtime dependency on PyYAML.
- Some direct deletes remain over-classified as `irreversible` because the CLI
  has no verified backup or restore evidence.

### Neutral

- Plan-level risk is derived from `changes[].risk` and emitted as `risk_level`.
- LLM-generated explanations remain out of scope for v0.1.

## Acceptance Criteria

- Tier A rules have tests.
- `--no-rules` returns the action-only classifier result.
- Existing action counts and risk counts remain stable for the original fixture.
- GitHub Action output remains compatible with the JSON CLI contract.
- Rule overrides have tests for tag matching and explanation rendering.
