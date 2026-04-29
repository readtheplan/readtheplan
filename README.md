# readtheplan

> Read the plan. Every time. For real.

`readtheplan` is a Terraform plan risk explainer. It reads `terraform plan` output, classifies each change as **safe / review / dangerous / irreversible** based on the action × resource type × what compliance context it touches, and posts a markdown summary your release manager (or auditor, or AI agent) can read in 30 seconds.

## status

🧪 **Alpha — v0.0.2.** First working release on PyPI. The MVP-1 CLI ships an action-based risk classifier (per [ADR 0003](docs/adr/0003-risk-classification-taxonomy.md)) and the MVP-4 composite GitHub Action wraps it. Resource-aware rule library (MVP-2) is next.

## why this exists

Terraform's plan/apply separation exists so a human reviews changes before they hit prod. In practice:

- the diff in code ≠ the diff in plan (renames show as destroy+create, provider bumps mutate untouched resources, `apply_immediately` flips have hidden timing implications)
- AI agents now write Terraform PRs — most don't read the plan critically, they apply because "the test passed"
- compliance reviewers (FinServ, healthcare, government) need a structured risk classification, not a 4,000-line text blob
- existing tools either show prettier plans (Spacelift, env0) or scan code for policy violations (tflint, tfsec, checkov). Nobody opinionates the **plan diff** with blast-radius context.

## philosophy

Anchored in this field note: **[terraform-apply-is-roulette](https://github.com/texasich/sre-field-notes/blob/main/notes/terraform-apply-is-roulette.md)**. If you've ever shipped a panic on `terraform validate` or watched a forward-fix cascade into a longer outage, this tool is built for you.

## planned MVP scope

1. CLI: `readtheplan analyze plan.json` → markdown table of changes with risk levels
2. plain-english explainer per resource type (top ~30 high-risk patterns covered out of the box: KMS, IAM, RDS replacements, S3 bucket destroys, EKS node-group replacements, route53 zone deletes, network ACL strips)
3. AI-agent attestation header — flag whether an agent claims to have read the plan
4. GitHub Action wrapper: install as `uses: readtheplan/action@v1`, posts a markdown PR comment
5. YAML rule customization: define org-specific rules ("anything in account 1234 is `review`")

## what's *not* in scope (and won't be)

- multi-cloud beyond AWS (initial focus)
- a SaaS dashboard (defer until revenue justifies)
- a policy-as-code engine (OPA / Sentinel already exist)
- competing with Spacelift / env0 / Snyk IaC on overlapping features

## license

MIT — see [LICENSE](./LICENSE).

## CLI JSON output

MVP-1 exposes a stable machine-readable contract for automation:

```bash
readtheplan analyze --format json plan.json
```

The JSON object includes:

- `resource_change_count`: total Terraform `resource_changes` entries.
- `actions`: counts keyed by Terraform action set, such as `create` or `delete/create`.
- `risks`: counts keyed by readtheplan risk tier.
- `changes`: one object per resource change with `address`, `type`, `actions`, and `risk`.

Invalid input is reported on stderr and exits non-zero.

## GitHub Action

This repository includes a composite GitHub Action at the repo root. It installs the
local Python package from the action checkout by default, runs the JSON CLI contract,
and exposes the parsed values as outputs.

```yaml
- name: Analyze Terraform plan
  id: readtheplan
  uses: readtheplan/readtheplan@v1
  with:
    plan-file: plan.json
    fail-on-changes: "false"

- name: Use readtheplan output
  run: |
    echo "${{ steps.readtheplan.outputs['summary-json'] }}"
    echo "${{ steps.readtheplan.outputs['resource-change-count'] }}"
```

Action outputs:

- `summary-json`: full JSON emitted by `readtheplan analyze --format json`.
- `resource-change-count`: total resource changes.
- `action-counts`: compact JSON object of action counts.
- `risk-counts`: compact JSON object of risk counts.

## contact

OSS contributions welcome. Author: [@texasich](https://github.com/texasich).
