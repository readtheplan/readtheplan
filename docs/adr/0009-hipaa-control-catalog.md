# ADR 0009: HIPAA Security Rule Control Catalog

## Status

Proposed

## Context

ADR 0005 introduced the framework-neutral catalog format. ADR 0006
shipped ISO 27001:2022. This ADR adds the **HIPAA Security Rule**
(45 CFR Part 164, Subpart C — §164.302 through §164.318) as the third
framework, following the same purely-data pattern.

The HIPAA Security Rule organizes safeguards into three categories:

- **Administrative Safeguards** (§164.308) — change management,
  workforce security, contingency planning
- **Physical Safeguards** (§164.310) — facility access, workstation use,
  device and media controls
- **Technical Safeguards** (§164.312) — access control, audit controls,
  integrity, authentication, transmission security

For Terraform plan reviews against an ePHI environment, the
Technical Safeguards in §164.312 carry most of the weight, with three
Administrative cites that touch on change management and contingency,
plus one Physical cite covering deletion / media handling on cloud
storage.

The same buyer cohort that asks for SOC 2 evidence also asks for
HIPAA Security Rule evidence in healthcare-adjacent SaaS (telehealth,
care coordination, EHR integrations, payer billing platforms,
clinical research). Adding HIPAA broadens addressable demand without
any code changes — the loader and CLI from PR #3 / PR #5 already
handle any framework via `--framework <name>`.

## Decision

Ship `src/readtheplan/data/controls/hipaa.yaml` following the
established schema. Re-use the existing loader, the `--framework`
CLI flag, and the existing markdown / JSON / evidence-envelope
rendering without modification.

### Initial control scope

HIPAA Security Rule citations touched by IaC change. Limit the initial
mapping to ten citations covering the resource set established in
ADRs 0004 / 0005 / 0006:

| ID | Title | Why it shows up at change time |
|---|---|---|
| `164.308(a)(1)` | Security Management Process | Universal change-management evidence |
| `164.308(a)(4)` | Information Access Management | IAM, role/policy lifecycle |
| `164.308(a)(7)` | Contingency Plan | RDS, KMS, EKS — recovery posture |
| `164.310(d)` | Device and Media Controls | S3 / RDS deletion, KMS destruction |
| `164.312(a)(1)` | Access Control | Security groups, S3 policies, IAM |
| `164.312(a)(2)(iv)` | Encryption and Decryption | KMS lifecycle, S3 SSE-KMS |
| `164.312(b)` | Audit Controls | CloudTrail lifecycle |
| `164.312(c)(1)` | Integrity | S3 versioning, immutability |
| `164.312(d)` | Person or Entity Authentication | IAM trust policies, federation |
| `164.312(e)(1)` | Transmission Security | DNS, network ingress, TLS endpoints |

Every catalog entry includes `164.308(a)(1)` (Security Management
Process) as a baseline, mirroring how the SOC 2 catalog includes
`CC8.1` and the ISO 27001 catalog includes `A.8.32` on every entry.

### Initial resource scope

Identical to ADRs 0005 and 0006:

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

### ID format

Control IDs are formatted **without the `§` section sign**, e.g.
`164.312(a)(2)(iv)`. Auditors recognize the citation by its CFR
numbering; the section sign is implied by context and would only
introduce UTF-8 quoting friction in CSV / GRC integrations downstream.
The full title field (`Encryption and Decryption`) carries the
human-readable label. The rationale field cites the section explicitly
in prose where useful.

This matches the ID-format convention used by Vanta, Drata, and
Tugboat Logic for HIPAA Security Rule controls.

### Out of scope for this ADR

- HIPAA Privacy Rule (§164.500 et seq.) — out of IaC scope; Privacy
  Rule covers PHI handling policies, not infrastructure config.
- HIPAA Breach Notification Rule.
- HITRUST CSF mappings (HIPAA + ISO + NIST aggregator) — separate ADR.
- 42 CFR Part 2 (substance use treatment confidentiality) — separate
  ADR if requested.
- Multi-framework simultaneous rendering. The CLI accepts one
  `--framework` at a time, same as ADR 0006.

## Consequences

### Positive

- Third framework shipped, validating again that ADR 0005's "frameworks
  are additive YAML" claim holds at scale.
- Triples US-regulated buyer reach (SOC 2 + ISO 27001 + HIPAA covers
  most US healthcare/health-adjacent SaaS, plus the European/UK ISO
  27001 cohort).
- Sets up the eventual multi-framework rendering decision with three
  real catalogs on the table, not two hypotheticals.

### Negative

- HIPAA Security Rule has been amended several times (e.g. HITECH
  expansion, Omnibus Rule, the 2025 NPRM proposing significant
  revisions). Mitigation: pin `framework_version` to the current rule
  text in effect (`2013-omnibus`). When the proposed 2025 amendments
  finalize, ship a new `hipaa-2025.yaml` alongside `hipaa.yaml` rather
  than mutating the existing catalog.
- Auditor opinions on whether a tool-generated mapping satisfies
  Security Management Process documentation vary by Office for Civil
  Rights enforcement context. Same caveat as SOC 2 / ISO 27001:
  output is *one input* to a human's evidence package, not stand-alone.

### Auditor caveat

Same as ADR 0005 / ADR 0006 — generated mappings are *one input* to a
human's evidence package, not a stand-alone artifact. README and
product copy say so explicitly.

## Anchor

Same arc as ADRs 0005, 0006, 0007, 0008. The compliance pivot
articulated in `texasich/sre-field-notes` →
`notes/terraform-apply-is-roulette.md`. HIPAA is the third-largest
asks-shaped-like-this market after SOC 2 and ISO 27001 for cloud-
native SaaS.
