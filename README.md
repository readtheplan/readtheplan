# readtheplan

> Read the plan. Every time. For real.

`readtheplan` is a Terraform plan risk explainer. It reads `terraform plan` output, classifies each change as **safe / review / dangerous / irreversible** based on the action × resource type × what compliance context it touches, and posts a markdown summary your release manager (or auditor, or AI agent) can read in 30 seconds.

## status

🚧 **Pre-MVP.** This namespace is locked but no functional release exists yet. Watch / star to follow.

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

## contact

OSS contributions welcome once the v0.1 lands. Until then, this is a namespace placeholder. Author: [@texasich](https://github.com/texasich).
