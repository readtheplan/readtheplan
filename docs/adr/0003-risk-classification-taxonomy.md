# ADR 0003: Risk Classification Taxonomy

## Status

Proposed

## Context

`readtheplan` analyzes Terraform JSON plans produced by `terraform show -json`.
The current Python CLI is intentionally small, but it already emits risk
classification data that downstream tools can consume through:

```bash
readtheplan analyze --format json tests/fixtures/valid_plan.json
```

Current JSON output shape:

```json
{
  "path": "tests\\fixtures\\valid_plan.json",
  "terraform_version": "1.6.6",
  "resource_change_count": 3,
  "actions": {
    "create": 1,
    "delete/create": 1,
    "update": 1
  },
  "risks": {
    "dangerous": 1,
    "review": 1,
    "safe": 1
  },
  "changes": [
    {
      "address": "aws_s3_bucket.logs",
      "type": "aws_s3_bucket",
      "actions": ["create"],
      "risk": "safe",
      "explanation": "Terraform will create S3 bucket infrastructure..."
    },
    {
      "address": "aws_db_instance.main",
      "type": "aws_db_instance",
      "actions": ["delete", "create"],
      "risk": "dangerous",
      "explanation": "Terraform will replace this RDS instance..."
    },
    {
      "address": "aws_iam_role.app",
      "type": "aws_iam_role",
      "actions": ["update"],
      "risk": "review",
      "explanation": "Terraform will update IAM authorization..."
    }
  ]
}
```

Ground truth for the action baseline lives in `src/readtheplan/plan.py`:

- `ResourceChange.risk` is emitted as `changes[].risk`.
- `PlanSummary.risk_counts` is emitted as the aggregate `risks` object.
- `_risk_for_actions()` is the current classifier.

The default CLI now layers resource-aware rules on top of this baseline. That
additive rule layer is documented in
[`ADR 0004`](0004-resource-aware-rule-library.md). Use
`readtheplan analyze --no-rules` to inspect the action-only baseline described
here.

The CLI does not currently emit a plan-level `risk_level`, `risk_factors`,
`risk_justification`, or `irreversible_operations` field. Those may be added in a
future schema revision, but they are not part of the current contract.

## Decision

Use a four-tier taxonomy for every Terraform resource change:

1. `safe`
2. `review`
3. `dangerous`
4. `irreversible`

The order is severity order:

```text
safe < review < dangerous < irreversible
```

For MVP-1, risk is assigned per resource change from the Terraform action list.
For consumers that need a plan-level risk, the derived plan risk is the highest
severity present in `changes[].risk`. The CLI does not yet emit that derived
field directly.

## Current Action Classifier

Current behavior is intentionally action-based and deterministic:

| Terraform action set | Resource risk | Reason |
| --- | --- | --- |
| `["create"]` | `safe` | Adds a new resource without modifying or deleting existing state. |
| `["read"]` | `safe` | Refresh/read-only behavior. |
| `["no-op"]` | `safe` | No change requested. |
| `["update"]` | `review` | Mutates existing infrastructure and may affect behavior. |
| `["delete", "create"]` | `dangerous` | Replacement can cause downtime or data movement even when Terraform models it as recreate. |
| `["delete"]` | `irreversible` | Deletion may remove stateful or externally relied-on infrastructure. |
| missing, malformed, or unknown actions | `review` | Unknown input should require human judgment rather than being treated as safe. |

The action baseline does not inspect account, environment, backup state, blast
radius, IAM semantics, or compliance context. Resource-specific context is added
only by the ADR 0004 rule layer.

## Tier Boundaries

### `safe`

A change is `safe` when the action is additive, read-only, or explicitly no-op
and the current classifier sees no mutation of existing infrastructure.

Current examples:

- `create`
- `read`
- `no-op`

Boundary note: a `create` may become `review` or `dangerous` in MVP-2 if
resource-aware rules detect a sensitive resource, public exposure, or high blast
radius. MVP-1 does not have that context.

### `review`

A change is `review` when it mutates existing infrastructure or the classifier
cannot confidently classify the operation.

Current examples:

- `update`
- missing action metadata
- malformed action metadata
- unknown Terraform action values

Boundary note: `review` means "human judgment required," not "unsafe." It is the
default for ambiguity.

### `dangerous`

A change is `dangerous` when Terraform will replace a resource through a combined
delete/create action set.

Current examples:

- `delete/create`

Boundary note: replacement is not automatically irreversible because Terraform
intends to recreate the resource. It is still dangerous because replacement can
destroy data, change identities, force downtime, or disrupt dependencies.

### `irreversible`

A change is `irreversible` when the current action set is a direct delete.

Current examples:

- `delete`

Boundary note: the MVP-1 classifier treats all direct deletes as irreversible
because it has no verified backup, retention, or restore context. A later
resource-aware classifier may downgrade some deletes to `dangerous` when recovery
evidence exists, but that requires auditable supporting data.

## Aggregation

The current JSON contract exposes aggregate counts in `risks`, not a single
plan-level risk field.

Consumers that need an overall plan risk should derive it by max severity:

| Plan composition | Derived plan risk |
| --- | --- |
| no changes | `safe` |
| only `safe` changes | `safe` |
| `safe` + `review` | `review` |
| `safe` + `dangerous` | `dangerous` |
| `review` + `dangerous` | `dangerous` |
| any mix containing `irreversible` | `irreversible` |
| only unknown or malformed operations | `review` |

Multiple lower-risk operations do not automatically escalate by count alone in
MVP-1. Escalation requires detection of a higher-risk pattern. A later ADR may
define volume-based escalation once the rule library has enough context to avoid
noisy false positives.

## JSON Compatibility

Current stable fields:

- `resource_change_count`: integer count of resource changes.
- `actions`: object mapping normalized action-set strings to integer counts.
- `risks`: object mapping risk tier strings to integer counts.
- `changes`: array of per-resource objects.
- `changes[].address`: resource address string, or `"<unknown>"`.
- `changes[].type`: Terraform resource type string, or `"<unknown>"`.
- `changes[].actions`: array of action strings.
- `changes[].risk`: one of `safe`, `review`, `dangerous`, `irreversible`.
- `changes[].explanation`: plain-English reason for the selected risk.

The following fields are intentionally not part of the current contract:

- `risk_level`
- `risk_factors`
- `risk_justification`
- `irreversible_operations`

Future schema additions must be additive unless the package version is bumped
for a breaking change. Removing or renaming the stable fields above requires a
new ADR.

## Consequences

### Positive

- Keeps the taxonomy aligned with the actual Python CLI instead of an imagined
  future schema.
- Gives GitHub Actions and other automation a stable `changes[].risk` and
  `risks` contract to consume.
- Makes ambiguity conservative: malformed or unknown actions become `review`.
- Leaves room for MVP-2 resource-aware rules without breaking MVP-1 consumers.

### Negative

- The current action-only classifier is blunt.
- Direct deletes may be over-classified as `irreversible` when reliable recovery
  exists.
- Creates may be under-classified as `safe` when resource context would reveal
  exposure or blast-radius risk.

### Neutral

- Plan-level risk is derivable but not emitted directly yet.
- Resource-aware explanations are emitted per change; structured risk factors are
  still deferred.

## Acceptance Criteria

- Existing tests continue to pass.
- JSON output continues to expose `changes[].risk` and aggregate `risks`.
- The four risk strings remain exactly `safe`, `review`, `dangerous`,
  `irreversible`.
- Unknown or malformed action metadata remains `review`.
- MVP-2 rules may increase risk severity, but should not silently downgrade
  `dangerous` or `irreversible` without documented recovery evidence.
