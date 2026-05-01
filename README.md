# readtheplan

> Read the plan. Every time. For real.

`readtheplan` is a Terraform plan risk explainer. It reads Terraform plan JSON,
classifies each change as **safe / review / dangerous / irreversible** based on
the action, resource type, and compliance context it touches, and posts a
markdown summary your release manager, auditor, or AI agent can read in 30
seconds.

## status

**Alpha - v0.0.2 released.** The PyPI alpha ships the MVP-1 CLI and MVP-4
composite GitHub Action. Current `main` is moving toward `0.1.0`: expanded AWS
resource-aware rules, plan-level `risk_level`, JSON/YAML organization
overrides, and the first AI-agent plan-read attestation helper.

## why this exists

Terraform's plan/apply separation exists so a human reviews changes before they
hit prod. In practice:

- the diff in code is not the diff in plan (renames show as destroy+create,
  provider bumps mutate untouched resources, `apply_immediately` flips have
  hidden timing implications)
- AI agents now write Terraform PRs; most don't read the plan critically, they
  apply because "the test passed"
- compliance reviewers need a structured risk classification, not a 4,000-line
  text blob
- existing tools either show prettier plans or scan code for policy violations;
  readtheplan opinionates the **plan diff** with blast-radius context

## philosophy

Anchored in this field note:
**[terraform-apply-is-roulette](https://github.com/texasich/sre-field-notes/blob/main/notes/terraform-apply-is-roulette.md)**.
If you've ever shipped a panic on `terraform validate` or watched a forward-fix
cascade into a longer outage, this tool is built for you.

## planned MVP scope

1. CLI: `readtheplan analyze plan.json` -> markdown table of changes with risk
   levels.
2. Plain-English explainer per resource type. Current `main` covers high-risk
   AWS patterns across RDS, S3, KMS, IAM, Route53, EKS, network access, EBS,
   Lambda, ECS, load balancers, CloudFront, ACM, Secrets Manager, SSM, VPC,
   subnets, NAT gateways, Cognito, DynamoDB, ElastiCache, Step Functions,
   EventBridge, SNS, SQS, API Gateway, Kinesis, and OpenSearch.
3. AI-agent attestation header: `readtheplan attest --agent-id codex plan.json`.
4. GitHub Action wrapper: install as `uses: readtheplan/readtheplan@v1` and
   expose summary outputs for workflows.
5. JSON/YAML rule customization for org-specific rules.

## what's not in scope

- multi-cloud beyond AWS for the first serious release
- a SaaS dashboard until revenue justifies it
- a policy-as-code engine; OPA and Sentinel already exist
- competing with Spacelift, env0, or Snyk IaC on overlapping features

## CLI

```bash
readtheplan analyze plan.json
readtheplan analyze --format json plan.json
readtheplan analyze --no-rules --format json plan.json
readtheplan analyze --rules-file readtheplan.rules.yaml --format json plan.json
```

The JSON object includes:

- `resource_change_count`: total Terraform `resource_changes` entries.
- `risk_level`: highest risk tier present in the plan.
- `actions`: counts keyed by Terraform action set, such as `create` or
  `delete/create`.
- `risks`: counts keyed by readtheplan risk tier.
- `changes`: one object per resource change with `address`, `type`, `actions`,
  `risk`, `rule_id`, and `explanation`.

Invalid input is reported on stderr and exits non-zero.

## Agent attestation

Agents can emit a deterministic header claiming they read a specific plan JSON
digest:

```bash
readtheplan attest --agent-id codex --run-id run-123 plan.json
```

The command prints:

```text
x-readtheplan-agent-read: rtp-attest-v1; agent=codex; read_at=...; plan_sha256=...; source=terraform-show-json; run_id=run-123
```

The v0.1 header is trust-but-flag: it binds an agent claim to exact plan bytes
and run metadata, but it is not yet a signed proof.

## GitHub Action

This repository includes a composite GitHub Action at the repo root. It installs
the local Python package from the action checkout by default, runs the JSON CLI
contract, and exposes parsed values as outputs.

```yaml
- name: Analyze Terraform plan
  id: readtheplan
  uses: readtheplan/readtheplan@v1
  with:
    plan-file: plan.json
    fail-on-changes: "false"
    rules-file: readtheplan.rules.yaml
    agent-id: codex

- name: Use readtheplan output
  run: |
    echo "${{ steps.readtheplan.outputs['summary-json'] }}"
    echo "${{ steps.readtheplan.outputs['resource-change-count'] }}"
    echo "${{ steps.readtheplan.outputs['risk-level'] }}"
    echo "${{ steps.readtheplan.outputs['attestation-header'] }}"
```

Action outputs:

- `summary-json`: full JSON emitted by `readtheplan analyze --format json`.
- `resource-change-count`: total resource changes.
- `action-counts`: compact JSON object of action counts.
- `risk-counts`: compact JSON object of risk counts.
- `risk-level`: highest risk tier present in the plan.
- `attestation-header`: `x-readtheplan-agent-read` header when `agent-id` is
  provided.

The Action also writes a GitHub Step Summary with aggregate counts and a compact
change table using the same `explanation` text as the CLI.

## license

MIT - see [LICENSE](./LICENSE).

## contact

OSS contributions welcome. Author: [@texasich](https://github.com/texasich).
