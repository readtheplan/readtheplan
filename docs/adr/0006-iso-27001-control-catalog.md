# ADR 0006: ISO 27001:2022 Control Catalog

## Status

Proposed

## Context

ADR 0005 introduced a compliance control catalog as a separate, additive
output axis on top of ADRs 0003 (action classifier) and 0004 (resource-aware
rules). The first framework catalog shipped was SOC 2 TSC 2017
(`src/readtheplan/data/controls/soc2.yaml`), wired through
`readtheplan analyze --framework soc2`.

The catalog format was designed framework-neutral. ADR 0005 §"Initial
framework scope" lists ISO 27001 as the next framework. ISO 27001:2022 is
the current revision (replacing the 2013 / 2017 numbering); the standard
groups Annex A controls into four themes:

- A.5 Organizational controls
- A.6 People controls
- A.7 Physical controls
- A.8 Technological controls

The Technological controls (A.8.x) cover almost all infrastructure-change
concerns. Common European, UK, and ANZ buyers ask for ISO 27001 evidence
the same way US buyers ask for SOC 2 evidence. Adding ISO 27001 broadens
addressable demand at a marginal data-only cost — no code changes to the
loader or CLI required, just a second YAML catalog.

## Decision

Ship a second framework catalog at `src/readtheplan/data/controls/iso27001.yaml`
following the schema established by ADR 0005. Re-use the existing loader,
the `--framework` CLI flag, and the existing markdown / JSON rendering
without modification.

### Initial control scope

ISO 27001:2022 Annex A entries that are touched by IaC change. Limit the
initial mapping to the same eight Technological controls that cover the
resource set established in ADR 0004 / 0005:

| ID | Title | Why it shows up at change time |
|---|---|---|
| A.5.23 | Information security for use of cloud services | Cloud-resource lifecycle changes (VPC / EKS / etc) |
| A.8.5 | Secure authentication | IAM trust policies, role assumption boundaries |
| A.8.9 | Configuration management | Every IaC change |
| A.8.10 | Information deletion | Database / bucket / key destruction |
| A.8.16 | Monitoring activities | CloudTrail and audit-trail changes |
| A.8.18 | Use of privileged utility programs | IAM policies that grant administrative reach |
| A.8.20 | Network security | Security groups, route tables, NACLs |
| A.8.22 | Segregation of networks | VPC / subnet / EKS network changes |
| A.8.24 | Use of cryptography | KMS keys, encryption-at-rest configuration |
| A.8.32 | Change management | Universal — every entry in the catalog |
| A.8.34 | Protection of information systems during audit testing | CloudTrail removal/replacement |

Every catalog entry includes A.8.32 (Change management) as a baseline,
matching how the SOC 2 catalog includes CC8.1 on every entry.

### Initial resource scope

Identical to ADR 0005's SOC 2 catalog:

- `aws_kms_key`, `aws_kms_alias`
- `aws_db_instance`, `aws_rds_cluster`
- `aws_s3_bucket`, `aws_s3_bucket_policy`, `aws_s3_bucket_public_access_block`
- `aws_iam_role`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user`
- `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`
- `aws_route53_zone`, `aws_route53_record`
- `aws_eks_cluster`, `aws_eks_node_group`
- `aws_cloudtrail`

A change to any other resource type matches no mapping and emits empty
`controls`. Expansion happens later, not here.

### Out of scope for this ADR

- HIPAA, PCI-DSS, NIST 800-53, CIS AWS catalogs (one ADR each, in the
  ADR 0005 follow-on plan).
- Multi-framework simultaneous rendering. The CLI accepts one
  `--framework` at a time. A future ADR will revisit this if multiple
  frameworks per output is asked for.
- Customer-supplied control overlays (separate ADR; will reuse the existing
  `RuleOverride` pattern).
- Evidence envelope wrapping (separate upcoming ADR).
- Signed attestation (separate upcoming ADR; extends `attestation.py`).

## Consequences

### Positive

- Validates ADR 0005's "frameworks are additive YAML" claim. A new framework
  is purely a data file; no code changes.
- Doubles the addressable buyer pool (SOC 2 + ISO 27001 cover most US/EU
  compliance asks).
- Sets up the multi-framework rendering decision (deferred above) with real
  data on the table, not hypothetical.

### Negative

- Maintenance: ISO 27001 has revisions (the 2022 revision replaced 2013/2017
  numbering, and the next revision will likely renumber again). Mitigation:
  pin `framework_version: 2022` in the catalog. The schema supports this.
- Slight output duplication: a `aws_kms_key` replacement returns 5 SOC 2
  controls or 5 ISO 27001 controls depending on the flag. Reviewers
  comparing the two frameworks have to run the tool twice. This is the
  intentional "one framework per invocation" trade-off from ADR 0005.

### Auditor caveat (carried forward from ADR 0005)

Generated mappings are *one input* to a human's evidence package, not a
stand-alone artifact. README and product copy should say so explicitly,
same as for SOC 2.

## Anchor

Same as ADR 0005 — pairs with `texasich/sre-field-notes` →
`notes/terraform-apply-is-roulette.md`. The compliance-evidence pivot is
*the* narrative for why this tool exists.
