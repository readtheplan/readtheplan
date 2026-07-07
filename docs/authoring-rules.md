# Authoring rules, controls, overlays, and adapters

readtheplan turns a Terraform/OpenTofu plan into a per-resource risk classification.
This guide covers the four ways to extend it, easiest first:

1. [Overlays](#overlays-no-code-customization) — per-org risk/control overrides, **no code**.
2. [Add a resource rule](#add-a-resource-rule) — built-in classification for a new AWS resource type.
3. [Add a compliance mapping](#add-a-compliance-mapping) — map a resource/action to a control.
4. [Add an adapter](#add-an-adapter) — support a non-Terraform input format.

## How classification works

For each resource change, `src/readtheplan/plan.py` builds an **action-based baseline**
(`safe` / `review` / … from the create/update/delete actions) and then asks
`rules.apply_resource_rules()` for **resource-aware candidates**. The result is the
**highest** risk across the baseline and all candidates:

```
safe (0) < review (1) < dangerous (2) < irreversible (3)
```

A rule never *lowers* risk below the action baseline — it only escalates and explains.
Explanations use the literal `__TOOL__` sentinel for the tool name (so the same string
works for "Terraform" and "OpenTofu"); the engine substitutes it at the end.

## Overlays (no-code customization)

Overlays let a platform/security team escalate risk or add controls **without forking**.
Pass one or more with `--rules-file` (repeatable):

```bash
readtheplan analyze --framework soc2 --rules-file acme-prod.yaml plan.json
```

An overlay is `rtp-overlay-v1` YAML. Matches can be by `resource_type`,
`address_prefix`, or `account_id`:

```yaml
schema: rtp-overlay-v1
name: acme-prod-overlay
description: Acme Corp production overrides

risk_overrides:
  - match: { resource_type: aws_lambda_function }
    risk: review
    explanation: Lambda handlers touch customer workflow data; app-owner review required.
  - match: { address_prefix: aws_kms_key.customer }
    risk: irreversible
    explanation: Production KMS keys require CISO sign-off before replacement.

control_additions:
  framework: soc2
  mappings:
    - resource_type: aws_lambda_function
      actions: [update]
      controls:
        - id: CC6.1
          title: Logical and Physical Access Controls
          rationale: Lambda handlers access customer workflow data.
```

A full working example lives at [`tests/fixtures/overlay_example.yaml`](../tests/fixtures/overlay_example.yaml).
Use overlays when the policy is **org-specific**; use a built-in rule (below) when it's
**generally true** of the resource type.

## Add a resource rule

Built-in rules live in provider modules under
[`src/readtheplan/rules/`](../src/readtheplan/rules/). Register each candidate function
with `@register_rule`; the registry in `rules/_shared.py` dispatches matching resource
types automatically.

**1. Write and register the candidate function.** Import `register_rule` from the public
rules API and pass one or more exact provider resource type names to the decorator. Every
registered function must accept `(resource_type, action_set, change)` and return a list of
`RuleResult`s, even when it does not use every argument.

```python
from readtheplan.rules import RuleResult, register_rule


@register_rule("aws_efs_file_system")
def _efs_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict,
) -> list[RuleResult]:
    if "delete" in action_set and "create" not in action_set:
        return [RuleResult(
            "irreversible",
            "__TOOL__ will delete an EFS file system. Stored data is destroyed unless a backup exists.",
        )]
    if "create" in action_set and "delete" in action_set:
        return [RuleResult(
            "dangerous",
            "__TOOL__ will replace an EFS file system, detaching mount targets and dropping data.",
        )]
    return []
```

There is no central `if`/`elif` dispatch chain to edit. To share one implementation across
several exact types, list them all in the decorator:

```python
@register_rule("aws_efs_mount_target", "aws_efs_access_point")
def _efs_attachment_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict,
) -> list[RuleResult]:
    ...
```

Guidance: use real provider resource type names; prefer `__TOOL__` over hard-coding
"Terraform"; keep explanations to one or two sentences of *what to check before applying*;
only escalate when the resource type genuinely warrants it (an unmatched type falls back to
the action baseline, which is fine).

**2. Add a test** in [`tests/test_rules.py`](../tests/test_rules.py):

```python
def test_efs_delete_is_irreversible():
    result = apply_resource_rules(
        resource_type="aws_efs_file_system",
        actions=("delete",),
        change={},
        baseline=RuleResult("dangerous", "baseline"),
    )
    assert result.risk == "irreversible"
    assert "EFS" in result.explanation
```

Run `pytest tests/test_rules.py -q`. Every behavior change needs a test.

## Add a compliance mapping

Control catalogs are plain YAML under
[`src/readtheplan/data/controls/`](../src/readtheplan/data/controls/) — one file per
framework (`soc2.yaml`, `iso27001.yaml`, `hipaa.yaml`, …). To map a resource/action to a
control, add (or extend) a `mappings` entry:

```yaml
framework: soc2
framework_version: 2017-tsc
schema_version: 1
mappings:
  - resource_type: aws_efs_file_system
    actions: [create]
    controls:
      - id: CC6.1
        title: Logical and Physical Access Controls
        rationale: A new file system establishes a new data-access boundary.
```

`actions` matches the plan's action set (e.g. `create`, `update`, `delete`,
`delete/create`, `replace`). The same resource type can have several entries for
different actions. Add a case to [`tests/test_controls.py`](../tests/test_controls.py)
asserting the control shows up for that resource/action, then regenerate the example
outputs (`scripts/regenerate-examples.sh`) since they include a SOC 2 column.

## Add an adapter

Adapters bring non-Terraform inputs (e.g. CloudFormation) into the same rules engine.
Subclass `BaseAdapter` in [`src/readtheplan/adapters/`](../src/readtheplan/adapters/) and
implement `adapter_name`, `can_handle`, `extract_changes`, and `normalize_change`; the
base `analyze()` template then runs the shared rules. Register it so `detect_adapter()`
can find it, and mirror the existing
[`cloudformation.py`](../src/readtheplan/adapters/cloudformation.py) /
[`tests/test_cfn_adapter.py`](../tests/test_cfn_adapter.py) pair. See
[ADR 0012](adr/0012-mcp-preview-adapter.md) for the design rationale.

## Checklist before you open a PR

- [ ] New/changed behavior has a test.
- [ ] `ruff check .` and `pytest` pass.
- [ ] If you changed classification or controls, ran `scripts/regenerate-examples.sh`.
- [ ] Explanations use `__TOOL__` and say what to verify before applying.
