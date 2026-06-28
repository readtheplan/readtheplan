# readtheplan API Reference

## Top-Level API

```python
from readtheplan import analyze, PlanSummary, ResourceChange
```

### `analyze(plan, *, use_rules=True) -> PlanSummary`

The primary public entry point. Analyzes a Terraform plan JSON and returns typed results.

**Args:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `plan` | `dict[str, Any]` or `str` or `Path` | required | Pre-parsed plan dictionary (e.g. from `json.loads`) or path to a `terraform show -json` output file |
| `use_rules` | `bool` | `True` | When True, applies built-in resource-aware risk rules on top of the action-based baseline |

**Returns:** `PlanSummary` — typed container with `.resource_changes`, `.risk_counts`, `.action_counts`.

**Example:**

```python
from readtheplan import analyze

# From a pre-parsed dict
plan = {
    "resource_changes": [
        {
            "address": "aws_s3_bucket.logs",
            "type": "aws_s3_bucket",
            "change": {"actions": ["create"]},
        }
    ],
}
summary = analyze(plan)
for c in summary.resource_changes:
    print(f"{c.address}: {c.risk}")

# From a file path
summary2 = analyze("plan.json")
print(summary2.risk_counts)
```

### `PlanSummary`

Typed container returned by `analyze()`.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `path` | `Path` | The original file path (or `Path("<inline>")` for dict input) |
| `terraform_version` | `str` or `None` | Version string from the Terraform plan |
| `resource_changes` | `tuple[ResourceChange, ...]` | Ordered list of per-resource changes |

**Properties:**

| Property | Return Type | Description |
|----------|-------------|-------------|
| `.action_counts` | `Counter[str]` | Count of each action pattern (e.g. `{"create": 1, "delete/create": 2}`) |
| `.risk_counts` | `Counter[str]` | Count of each risk tier (e.g. `{"safe": 1, "review": 3, "irreversible": 1}`) |

**Methods:**

| Method | Return Type | Description |
|--------|-------------|-------------|
| `.to_dict()` | `dict` | Serialize to a plain dict (same shape as `--format json` CLI output) |

### `ResourceChange`

A single resource change with its risk classification.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `address` | `str` | Terraform resource address (e.g. `"aws_s3_bucket.logs"`) |
| `resource_type` | `str` | Terraform resource type (e.g. `"aws_s3_bucket"`) |
| `actions` | `tuple[str, ...]` | Action set (e.g. `("create",)`, `("delete", "create")`) |
| `risk` | `str` | Risk tier: `"safe"`, `"review"`, `"dangerous"`, or `"irreversible"` |
| `explanation` | `str` | Human-readable explanation of why this risk was assigned |

**Risk ordering:** `safe (0) < review (1) < dangerous (2) < irreversible (3)`

---

## Rules API

```python
from readtheplan.rules import (
    register_rule,
    register_cross_cutting,
    RuleResult,
    apply_resource_rules,
)
```

### `register_rule(*resource_types: str)`

Decorator that registers a candidate function for one or more exact resource types.

**Args:** One or more resource type name strings (e.g. `"aws_kms_key"`, `"aws_db_instance"`, `"aws_rds_cluster"`).

**Signature of decorated function:** `(resource_type: str, action_set: set[str], change: dict) -> list[RuleResult]`

**Example:**

```python
from readtheplan.rules import register_rule, RuleResult

@register_rule("aws_efs_file_system")
def _efs_candidates(resource_type, action_set, change):
    if "delete" in action_set:
        return [RuleResult("irreversible", "Deleting an EFS file system...")]
    return []
```

### `register_cross_cutting(func)`

Decorator that registers a function to run for **every** resource type. The function self-filters internally by checking the `resource_type` argument (e.g. `resource_type.startswith("aws_")`).

**Example:**

```python
from readtheplan.rules import register_cross_cutting

@register_cross_cutting
def _platform_service_candidates(resource_type, action_set, change):
    if not resource_type.startswith("aws_"):
        return []
    # ... platform-specific logic
```

### `RuleResult`

A risk + explanation pair output by a rule function.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `risk` | `str` | One of `"safe"`, `"review"`, `"dangerous"`, `"irreversible"` |
| `explanation` | `str` | Human-readable explanation. Use `__TOOL__` as a sentinel — the engine substitutes the actual tool name (e.g. "Terraform", "CloudFormation") |

### `apply_resource_rules(*, resource_type, actions, change, baseline, tool_name="Terraform") -> RuleResult`

The engine entry point. Given a resource type, action set, and change metadata, runs all registered rules against it and returns the highest-risk result.

**Args:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `resource_type` | `str` | Provider resource type name |
| `actions` | `tuple[str, ...]` | Action set from the plan |
| `change` | `dict` | Change metadata (before/after attributes) |
| `baseline` | `RuleResult` | Starting risk (from action-based classifier or adapter) |
| `tool_name` | `str` | Tool name for `__TOOL__` substitution |

**Returns:** `RuleResult` — the maximum-risk result across baseline and all rule candidates.

---

## Internal Registry Data

```python
from readtheplan.rules._shared import _RULE_REGISTRY, _CROSS_CUTTING
```

| Module-level constant | Type | Description |
|-----------------------|------|-------------|
| `_RULE_REGISTRY` | `dict[str, list[Callable]]` | Maps resource type → list of registered rule functions (48 types) |
| `_CROSS_CUTTING` | `list[Callable]` | List of cross-cutting functions that run for every type (3 functions) |
| `RISK_ORDER` | `dict[str, int]` | Maps risk tier to integer rank: `safe=0`, `review=1`, `dangerous=2`, `irreversible=3` |
