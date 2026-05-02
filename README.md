# readtheplan

> Read the plan. Every time. For real.

`readtheplan` is a Terraform plan risk explainer. It reads `terraform plan` output, classifies each change as **safe / review / dangerous / irreversible** based on the action × resource type × what compliance context it touches, and posts a markdown summary your release manager (or auditor, or AI agent) can read in 30 seconds.

## status

🧪 **Alpha — v0.0.2 released.** The PyPI alpha ships the MVP-1 CLI and MVP-4 composite GitHub Action. Current `main` adds the first MVP-2 resource-aware AWS rules for RDS, S3, KMS, IAM, Route53, and EKS node groups on top of the action taxonomy in [ADR 0003](docs/adr/0003-risk-classification-taxonomy.md).

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
2. plain-english explainer per resource type (top ~30 high-risk patterns covered out of the box: KMS, IAM, RDS replacements, S3 bucket destroys, EKS node-group replacements, route53 zone deletes, network ACL strips) — Tier A shipped in `main`
3. AI-agent attestation header — flag whether an agent claims to have read the plan
4. GitHub Action wrapper: install as `uses: readtheplan/readtheplan@v1`, exposes summary outputs for workflows
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

Resource-aware rules are enabled by default. To inspect the action-only baseline
from ADR 0003:

```bash
readtheplan analyze --no-rules --format json plan.json
```

The JSON object includes:

- `resource_change_count`: total Terraform `resource_changes` entries.
- `actions`: counts keyed by Terraform action set, such as `create` or `delete/create`.
- `risks`: counts keyed by readtheplan risk tier.
- `changes`: one object per resource change with `address`, `type`, `actions`, `risk`, and `explanation`.

Invalid input is reported on stderr and exits non-zero.

### Compliance control IDs (preview)

`readtheplan analyze --framework <name> plan.json` annotates each change
with control IDs from a packaged compliance framework catalog.

Available frameworks:

- `soc2` — SOC 2 Trust Services Criteria 2017 (see ADR 0005)
- `iso27001` — ISO/IEC 27001:2022 Annex A (see ADR 0006)

Catalogs ship as data under `src/readtheplan/data/controls/`. HIPAA,
PCI-DSS, NIST 800-53, and CIS AWS catalogs are planned in subsequent
ADRs. The output is intended as one input to a human's evidence package,
not a stand-alone audit artifact.

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

The Action also writes a GitHub Step Summary with aggregate counts and a compact
change table using the same `explanation` text as the CLI.

## contact

OSS contributions welcome. Author: [@texasich](https://github.com/texasich).
