# readtheplan

> **Read the plan. Every time. For real.**
>
> [![Version](https://img.shields.io/pypi/v/readtheplan?color=blue)](https://pypi.org/project/readtheplan/)
> [![Python](https://img.shields.io/pypi/pyversions/readtheplan)](https://pypi.org/project/readtheplan/)
> [![CI](https://github.com/readtheplan/readtheplan/actions/workflows/test-action.yml/badge.svg)](https://github.com/readtheplan/readtheplan/actions)
> [![Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)](https://github.com/readtheplan/readtheplan/actions)
> [![License](https://img.shields.io/github/license/readtheplan/readtheplan)](./LICENSE)
> [![Downloads](https://img.shields.io/pypi/dm/readtheplan)](https://pypi.org/project/readtheplan/)
> [![Discussions](https://img.shields.io/badge/discussions-welcome-blue)](https://github.com/readtheplan/readtheplan/discussions)
> [![Stars](https://img.shields.io/github/stars/readtheplan/readtheplan?style=social)](https://github.com/readtheplan/readtheplan)

**Terraform / OpenTofu plan risk analysis for humans, CI pipelines, and AI agents.** Classifies every change as safe, review, dangerous, or irreversible. Produces compliance evidence for SOC 2, ISO 27001, and HIPAA. Runs locally — no uploads, no accounts, no backend.

```bash
pip install readtheplan && readtheplan analyze plan.json
```

Requires Python 3.10+.

[Website](https://readtheplan.dev) · [Demo](https://readtheplan.dev/demo/) · [Docs](https://readtheplan.dev/docs/) · [Playground](https://readtheplan.dev/playground/) · [Contributing](CONTRIBUTING.md)

---

## Comparison: readtheplan vs. everything else

| Tool | Analyzes | Risk tiers | Compliance evidence | Agent gate | Local-only |
|------|----------|------------|---------------------|------------|------------|
| **readtheplan** | Plan diff | ✅ 4 tiers | ✅ SOC2/ISO/HIPAA | ✅ proceed/warn/block | ✅ |
| tflint | Code (HCL) | ❌ lint only | ❌ | ❌ | ✅ |
| tfsec | Code (HCL) | ❌ security only | ❌ | ❌ | ✅ |
| checkov | Code + plan | ⚠️ pass/fail | ⚠️ policy checks | ❌ | ✅ |
| Spacelift | Plan + state | ⚠️ visual only | ❌ | ⚠️ policy gates | ❌ SaaS |
| env0 | Plan + state | ⚠️ visual only | ❌ | ❌ | ❌ SaaS |
| Snyk IaC | Code (HCL) | ❌ security only | ❌ | ❌ | ❌ SaaS |
| infracost | Plan diff | ❌ cost only | ❌ | ❌ | ❌ SaaS |
| OPA/Sentinel | Policy engine | ⚠️ rule-based | ⚠️ | ⚠️ policy gates | ✅ |

**readtheplan is the only tool that:** classifies plan diffs by blast radius risk tier, annotates with compliance controls, produces auditable evidence envelopes, gates CI pipelines and AI agents, and runs entirely locally with no SaaS dependency.

---

## Why this exists

Terraform's plan/apply separation exists so a human reviews changes before they hit prod. In practice, nobody reads the 4,000-line text blob. Code diffs ≠ plan diffs. AI agents skip review. Compliance reviewers drown.

**I reviewed hundreds of Terraform plans manually before building this.** The same patterns kept killing us: a destroy+create that looked like an update, a KMS key rotation that nobody flagged, an IAM policy that quietly opened a bucket to the world. Every incident postmortem had the plan diff attached — and every one of them was reviewed and approved by a human who missed the signal.

[Read the full story →](https://github.com/texasich/sre-field-notes/blob/main/notes/terraform-apply-is-roulette.md)

## What it does

readtheplan reads `terraform plan` JSON (Terraform and OpenTofu) and classifies each change:

🟢 **safe** — no-op, tag update, read-only change
🟡 **review** — security group rule change, minor config drift
🟠 **dangerous** — instance replacement, IAM policy change, database modification
🔴 **irreversible** — data deletion, KMS key destruction, RDS instance termination

It applies **resource-aware rules** (30+ AWS resource types), **compliance framework mappings** (SOC 2, ISO 27001, HIPAA), and produces **auditable evidence envelopes** with sigstore-backed signed attestations.

## Quickstart

### CLI — 30 seconds to first result

```bash
# Install
pip install readtheplan

# Generate a plan (Terraform or OpenTofu)
terraform plan -out=tfplan -input=false
terraform show -json tfplan > plan.json

# Analyze it
readtheplan analyze plan.json

# With compliance framework
readtheplan analyze --framework soc2 plan.json

# Machine-readable JSON
readtheplan analyze --format json plan.json

# Optional signed evidence support
pip install "readtheplan[sign]"

# Optional local MCP preview
pip install "readtheplan[mcp]"
```

### Docker

```bash
docker run --rm -v $(pwd):/workspace readtheplan/readtheplan analyze plan.json
```

[![Docker](https://img.shields.io/badge/docker-readtheplan%2Freadtheplan-blue)](https://github.com/readtheplan/readtheplan/pkgs/container/readtheplan)

### Sample CLI output

```text
# readtheplan summary: plan.json
Resource changes: 3

## Risk
- dangerous: 1
- review: 1
- safe: 1

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| safe | create | aws_s3_bucket.logs | aws_s3_bucket | Terraform will create S3 bucket infrastructure. |
| review | update | aws_iam_role.deploy | aws_iam_role | Review trust policies, permission boundaries, and deny statements. |
| dangerous | delete/create | aws_kms_key.customer_data | aws_kms_key | KMS key identity changes can break decrypt access. |
```

### GitHub Action — gate your CI pipeline

```yaml
- name: Analyze Terraform plan
  id: rtp
  uses: readtheplan/readtheplan@v1
  with:
    plan-file: plan.json
    fail-on-threshold: dangerous
```

Downstream steps can consume compact outputs directly:

```yaml
- name: Use readtheplan JSON
  run: |
    echo '${{ steps.rtp.outputs.summary-json }}' > readtheplan-summary.json
    echo "Risk counts: ${{ steps.rtp.outputs.risk-counts }}"
```

[Full GitHub Actions workflow →](https://readtheplan.dev)

### AI agent gate — block unsafe auto-approvals

```bash
readtheplan agent-gate plan.json
```

Example JSON contract:

```json
{
  "schema": "rtp-agent-gate-v1",
  "decision": "block",
  "risk": "dangerous",
  "required_checks": [
    "rtp.check.change_record",
    "rtp.check.evidence_packet",
    "rtp.check.human_approval",
    "rtp.check.security_review"
  ],
  "allowed_next_actions": ["post_pr_comment", "request_human_review", "collect_evidence", "open_change_record"],
  "prohibited_next_actions": ["merge", "apply", "auto_approve", "auto_apply"],
  "risk_counts": {"safe": 1, "review": 1, "dangerous": 1, "irreversible": 0}
}
```

Wire this into coding-agent pipelines by making `decision` the stable gate: `proceed` may continue, `warn` requires reviewer acknowledgement, and `block` must stop merge/apply/auto-approval until the required checks are recorded.

### Compliance evidence sample

```json
{
  "schema": "rtp-evidence-v1",
  "framework": {"name": "soc2", "version": "2017-tsc"},
  "summary": {
    "resource_change_count": 3,
    "risks": {"safe": 1, "review": 1, "dangerous": 1},
    "controls_touched": ["CC6.1", "CC6.6", "CC8.1"]
  },
  "agent_attestation": {
    "agent": "readtheplan@0.3.0",
    "plan_sha256": "..."
  }
}
```

## Features

- **CLI-first** — single `pip install`, runs anywhere Python runs
- **GitHub Action** — copy-paste into any workflow
- **Resource-aware rules** — 30+ AWS resource types: KMS, IAM, RDS, S3, EKS, Lambda, networking, etc.
- **Compliance evidence** — SOC 2, ISO 27001, HIPAA control mappings with signed JSON envelopes
- **Agent gate** — deterministic proceed/warn/block decisions for CI and AI agents
- **Customer rule overlays** — org-specific risk escalations via YAML, no code changes needed
- **MCP preview** — local stdio tools for agent and IDE integrations
- **No uploads** — your Terraform plan JSON never leaves your machine
- **MIT licensed** — use it anywhere, no strings attached

## What's not in scope

- Multi-cloud beyond AWS (Terraform/OpenTofu only for now)
- SaaS dashboard (local-first by design)
- Hosted analyzer service until ADR 0013 security gates are implemented and enforced
- Policy-as-code engine (OPA/Sentinel exist for that)
- Competing with Spacelift/env0 on overlapping features

## Documentation

- [Website](https://readtheplan.dev) — setup generator, example output, intake
- [Docs](https://readtheplan.dev/docs/) — tutorials, API reference, examples
- [`examples/`](examples/) — sample plans with rendered output
- [`docs/adr/`](docs/adr/) — architecture decision records
- [Corpus feedback loop](docs/corpus/README.md) — scan real plans, improve rules

## Community

- [GitHub Discussions](https://github.com/readtheplan/readtheplan/discussions) — ask questions, share ideas
- [Issues](https://github.com/readtheplan/readtheplan/issues) — report bugs, request features
- [Good first issues](https://github.com/readtheplan/readtheplan/labels/good%20first%20issue) — start contributing
- [Security policy](SECURITY.md) — report vulnerabilities privately

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development environment setup
- How to run tests
- What makes a good first issue
- PR review process
- AI assistance disclosure policy

Good first issues are tagged [`good first issue`](https://github.com/readtheplan/readtheplan/labels/good%20first%20issue).

## Status

**v0.3 — stable CLI + GitHub Action.** The PyPI package ships the Python CLI and composite GitHub Action. Current `main` includes: resource-aware AWS risk rules, compliance framework annotations, evidence envelopes, signed attestation verification, customer rule overlays, MCP preview, examples, benchmarks, and the static onboarding site.

What's shipping next: CloudFormation/Pulumi adapters, PCI-DSS and NIST 800-53 catalogs, expanded AWS resource coverage.

## License

MIT — see [LICENSE](./LICENSE).

## Author

[@texasich](https://github.com/texasich) — OSS contributions welcome.
