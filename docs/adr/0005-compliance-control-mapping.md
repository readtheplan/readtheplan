# ADR 0005: Compliance Control Mapping

## Status

Proposed

## Context

ADRs 0003 and 0004 give every Terraform resource change a deterministic risk tier
(`safe / review / dangerous / irreversible`) and a plain-English explanation.
That output is technically useful but it stops one step short of the audience
the README is selling to: auditors, compliance reviewers, and release managers
preparing evidence for SOC 2, HIPAA, ISO 27001, and PCI-DSS.

Those reviewers do not read Terraform actions. They read **control IDs**. A SOC 2
Type II audit asks for evidence against CC8.1 (Change Management). An ISO 27001
auditor asks for A.12.1.2 evidence. A HIPAA reviewer wants §164.312(a)(2)(iv)
on encryption. The current output forces a reviewer to translate
"`aws_kms_key.customer_data` deletion is dangerous" into "this change touches
SOC 2 CC6.1 and CC6.7 logical-access controls" by hand. That translation step
is exactly the gap the existing tools (tfsec, checkov, terrascan, Conftest, Snyk
IaC) leave open: they detect *misconfigurations*, not *compliance-control
exposure of approved changes*.

The competitive lane readtheplan can credibly own is **change-evidence for
compliance**, not misconfig detection. Owning that lane requires the tool to
emit control IDs alongside its existing risk tiers.

## Decision

Introduce a **compliance control catalog** as a separate, additive output axis
that runs in parallel with the existing rule library. The catalog maps
`(resource_type, action_set)` tuples to lists of control entries from one or
more compliance frameworks. ADRs 0003 and 0004 remain the single source of
truth for `risk` and `explanation`. Control IDs are an additional field on each
change, populated only when a framework is requested.

### Layering

```
plan.json
    │
    ▼
ADR 0003 action classifier  ──►  baseline risk
    │
    ▼
ADR 0004 resource-aware rules  ──►  rule_id, explanation, risk escalation
    │
    ▼
ADR 0005 control catalog       ──►  controls[]   (new, this ADR)
    │
    ▼
output (markdown / json)
```

The control catalog must **not** modify `risk`, `explanation`, or `rule_id`. It
is read-only relative to ADRs 0003 and 0004.

### Control catalog format

Static YAML files, one per framework, shipped with the package under
`src/readtheplan/data/controls/<framework>.yaml`. Schema:

```yaml
framework: soc2
framework_version: 2017-tsc
schema_version: 1
mappings:
  - resource_type: aws_kms_key
    actions: [delete, "delete/create"]
    controls:
      - id: CC6.1
        title: Logical and Physical Access Controls
        rationale: >
          Replacing or deleting a customer-data KMS key changes the access
          boundary on encrypted data at rest.
      - id: CC6.7
        title: Restriction of Information Asset Movements
        rationale: >
          Key destruction is an irreversible asset-movement event for any
          ciphertext that depended on the key.
```

Match semantics:

- `resource_type` matches Terraform's `resource_changes[].type` exactly.
- `actions` is a list of action strings in the same vocabulary as ADR 0003
  (`create`, `update`, `delete`, `delete/create`, `replace`, `read`, `no-op`).
  A change matches if its action is present in the list.
- A change can match multiple mappings; the resulting `controls` list is the
  union, deduplicated by `id`.
- A change that matches no mapping receives `controls: []` (omitted in
  markdown output, present as empty list in JSON).

### Initial framework scope

**SOC 2 (Trust Services Criteria, 2017)**, focused on the Common Criteria most
likely to be touched by infrastructure change:

- CC6.1 (Logical and Physical Access Controls)
- CC6.6 (Boundary Protection)
- CC6.7 (Restriction of Information Asset Movements)
- CC7.1 (System Operations — Detection of Configuration Changes)
- CC7.2 (System Monitoring)
- CC8.1 (Change Management)
- A1.2 (Availability — Recovery)
- C1.1 (Confidentiality — Identification and Maintenance)

ISO 27001, HIPAA, PCI-DSS, NIST 800-53, and CIS AWS get their own ADRs and
catalog files, in that order. Each framework lives in its own YAML file with
identical schema. The CLI accepts one framework at a time in this MVP; multi-
framework rendering is deferred.

### Initial resource scope

The same resources covered by ADR 0004's rule library:

- `aws_kms_key`, `aws_kms_alias`
- `aws_db_instance`, `aws_rds_cluster`
- `aws_s3_bucket`, `aws_s3_bucket_policy`, `aws_s3_bucket_public_access_block`
- `aws_iam_role`, `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user`
- `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`
- `aws_route53_zone`, `aws_route53_record`
- `aws_eks_cluster`, `aws_eks_node_group`
- `aws_cloudtrail`

A change to any other resource type matches no mapping and emits empty
`controls`. Expansion happens in subsequent PRs, not in this ADR.

### CLI surface

```
readtheplan analyze --framework soc2 plan.json
readtheplan analyze --framework soc2 --format json plan.json
```

- Default (no `--framework`): output unchanged. Backwards compatible.
- `--framework <name>`: loads `src/readtheplan/data/controls/<name>.yaml`.
  Unknown name exits non-zero with a clear error listing available frameworks.
- Markdown output: appends a "Controls" column after "Explanation". Cells render
  as a comma-separated list of control IDs (e.g. `CC6.1, CC8.1`).
- JSON output: each item in `changes[]` gains a `controls` array with full
  entries (`{id, title, rationale}`). The top-level `summary` JSON gains a
  `framework` field with `{name, version, schema_version}`.

### Out of scope for this ADR

- Cryptographic signing of evidence (ADR for MVP-3 attestation extension)
- Evidence envelope JSON (separate ADR — wraps multiple framework outputs plus
  attestation into one auditor-ready document)
- ISO 27001, HIPAA, PCI-DSS, NIST 800-53, CIS AWS catalogs (one ADR each)
- Multi-framework simultaneous rendering
- GRC integrations (Vanta, Drata, ServiceNow GRC)
- Multi-cloud (Azure, GCP) — explicitly out of scope project-wide
- Compliance-scope drift detection (comparing prior vs. planned state for
  control posture changes) — separate ADR
- Customer-supplied control overlays — separate ADR, will reuse the existing
  rule-override loader pattern from ADR 0004

## Consequences

### Positive

- Differentiates from tfsec/checkov/terrascan: those find misconfig
  *violations*; readtheplan emits *control-ID exposure for approved changes*.
  A reviewer can copy-paste readtheplan's output into a SOC 2 evidence ticket.
- Sets up the signed-attestation work in `attestation.py` to wrap a meaningful
  payload (a control-mapped change set), not just a plan hash.
- Each new framework is additive YAML data, not new code paths. Maintenance
  cost scales with framework count, not feature count.
- Zero impact on the existing `--no-rules` and rule-override flows.

### Negative

- Maintenance burden: when SOC 2 TSC publishes a new revision (e.g. 2024 TSC),
  the YAML must be revised. Mitigation: pin `framework_version` in the
  catalog and the JSON output so reviewers can see which version their
  evidence references.
- Risk of scope creep into "we are a GRC platform." Mitigation: keep the tool's
  promise narrow — readtheplan emits control-ID-tagged change descriptions; it
  does not maintain a control register, track remediation, or run audits.
- Auditor opinions vary on whether a generated mapping satisfies CC8.1 evidence
  on its own. The output is best understood as *one input* to a human's
  evidence package, not a stand-alone artifact. README and product copy should
  state this explicitly.

### Maintenance contract

- Catalog files in `src/readtheplan/data/controls/` are part of the package's
  versioned API. Removing or relabeling a control ID is a breaking change.
  Adding a control ID, a mapping entry, or a new framework file is not.
- Every catalog file must validate against the schema on package build.
  Schema validation lives next to the loader and runs as part of the existing
  pytest suite.

## Anchor

This ADR pairs with `texasich/sre-field-notes` →
`notes/terraform-apply-is-roulette.md`. The compliance-evidence pivot is the
narrative arc that makes "apply is roulette" a problem auditors are paying to
solve, not just one engineers complain about.
