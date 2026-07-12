# readtheplan

> **Read the plan. Every time. For real.**
>
> [![Version](https://img.shields.io/pypi/v/readtheplan?color=blue)](https://pypi.org/project/readtheplan/)
> [![Python](https://img.shields.io/pypi/pyversions/readtheplan)](https://pypi.org/project/readtheplan/)
> [![CI](https://github.com/readtheplan/readtheplan/actions/workflows/test-action.yml/badge.svg)](https://github.com/readtheplan/readtheplan/actions)
> [![Coverage](https://img.shields.io/badge/coverage-78%25-brightgreen)](https://github.com/readtheplan/readtheplan/actions)
> [![License](https://img.shields.io/github/license/readtheplan/readtheplan)](./LICENSE)
> [![Downloads](https://img.shields.io/pypi/dm/readtheplan)](https://pypi.org/project/readtheplan/)
> [![Discussions](https://img.shields.io/badge/discussions-welcome-blue)](https://github.com/readtheplan/readtheplan/discussions)
> [![Stars](https://img.shields.io/github/stars/readtheplan/readtheplan?style=social)](https://github.com/readtheplan/readtheplan)

**Infrastructure change risk analysis for humans, CI pipelines, and AI agents.** Review cloud plans, Kubernetes manifests, Docker Compose workloads, Nomad scheduler plans, configuration-management code, and CI pipelines through one deterministic local risk gate. Runs locally — no uploads, no accounts, no backend.

```bash
pip install readtheplan && readtheplan analyze plan.json
```

Requires Python 3.10+.

[Website](https://readtheplan.dev) · [Demo](https://readtheplan.dev/demo/) · [Docs](https://readtheplan.dev/docs/) · [Playground](https://readtheplan.dev/playground/) · [Contributing](CONTRIBUTING.md)

---

## Comparison: readtheplan vs. everything else

| Tool | Analyzes | Risk tiers | Compliance evidence | Agent gate | Local-only |
|------|----------|------------|---------------------|------------|------------|
| **readtheplan** | Plans + config/pipelines | ✅ 4 tiers | ✅ SOC2/ISO/HIPAA | ✅ proceed/warn/block | ✅ |
| tflint | Code (HCL) | ❌ lint only | ❌ | ❌ | ✅ |
| tfsec | Code (HCL) | ❌ security only | ❌ | ❌ | ✅ |
| checkov | Code + plan | ⚠️ pass/fail | ⚠️ policy checks | ❌ | ✅ |
| Spacelift | Plan + state | ⚠️ visual only | ❌ | ⚠️ policy gates | ❌ SaaS |
| env0 | Plan + state | ⚠️ visual only | ❌ | ❌ | ❌ SaaS |
| Snyk IaC | Code (HCL) | ❌ security only | ❌ | ❌ | ❌ SaaS |
| infracost | Plan diff | ❌ cost only | ❌ | ❌ | ❌ SaaS |
| OPA/Sentinel | Policy engine | ⚠️ rule-based | ⚠️ | ⚠️ policy gates | ✅ |

**readtheplan brings one review contract to infrastructure changes:** classify blast-radius risk, annotate compliance controls, produce auditable evidence, gate CI pipelines and AI agents, and keep the source material local.

---

## Who it's for

- **Infrastructure authors** — see the blast radius of a plan, manifest, playbook, recipe, or pipeline before it runs.
- **Platform / DevOps teams** — standardize risk tiers and org-specific escalations across repos with rule overlays (no forks, no code changes).
- **CI maintainers** — drop the GitHub Action into any pipeline to gate pull requests on `dangerous` / `irreversible` changes.
- **Security & compliance reviewers** — SOC 2, ISO 27001, HIPAA, PCI DSS, FedRAMP Moderate, and HITRUST control mappings plus signed, auditable evidence envelopes for every change.
- **AI-agent workflows** — a deterministic `proceed` / `warn` / `block` gate that stops an agent from auto-applying unsafe infrastructure.

---

## Why this exists

Terraform's plan/apply separation exists so a human reviews changes before they hit prod. In practice, nobody reads the 4,000-line text blob. Code diffs ≠ plan diffs. AI agents skip review. Compliance reviewers drown.

**I reviewed hundreds of Terraform plans manually before building this.** The same patterns kept killing us: a destroy+create that looked like an update, a KMS key rotation that nobody flagged, an IAM policy that quietly opened a bucket to the world. Every incident postmortem had the plan diff attached — and every one of them was reviewed and approved by a human who missed the signal.

[Read the full story →](https://github.com/texasich/sre-field-notes/blob/main/notes/terraform-apply-is-roulette.md)

## What it does

readtheplan analyzes structured Terraform/OpenTofu plans and infrastructure-tool inputs, then classifies each operation:

🟢 **safe** — no-op, tag update, read-only change
🟡 **review** — security group rule change, minor config drift
🟠 **dangerous** — instance replacement, IAM policy change, database modification
🔴 **irreversible** — data deletion, KMS key destruction, RDS instance termination

Terraform/OpenTofu analysis applies **resource-aware rules** across AWS, GCP,
Azure, Kubernetes, Cloudflare, GitHub, and GitLab. Every adapter feeds the same six **compliance
framework mappings** with an exact-first change-management baseline and
deterministic agent-gate schema; native plan analysis can also produce
**auditable evidence envelopes** with sigstore-backed signed attestations.

### Supported infrastructure tools

| Tool | Command | Analysis level |
|------|---------|----------------|
| Terraform / OpenTofu | `readtheplan analyze plan.json` | Structured plan diff plus AWS, GCP, Azure, Kubernetes, Cloudflare, GitHub, and GitLab resource-aware rules |
| Terraform configuration | `readtheplan terraform-config main.tf` | HCL/JSON providers, backends, modules, resources/data, provisioners, lifecycle, remote state, imports/moves/removals, secrets, and static exposure |
| Terragrunt | `readtheplan terragrunt terragrunt.hcl` | HCL/JSON root modules, hooks, CLI arguments, remote state, includes, dependencies/mocks, generated files, inputs, assumed identity, engines, and evaluation functions |
| CloudFormation | `readtheplan cloudformation changes.json` | Structured change set or template diff |
| Serverless Framework | `readtheplan serverless serverless.yml` | Framework/tool version, deployment identity/artifacts, IAM, functions, events, plugins, variables, packaging, and embedded CloudFormation |
| AWS SAM | `readtheplan sam template.yaml` | Transforms/macros, Globals, functions/code, policies, event ingress, APIs, state machines, nested apps, Connectors, builds, and lifecycle policies |
| Azure Bicep / ARM | `readtheplan azure whatif.json` | Structured deployment What-If with FullResourcePayloads old/new state |
| Kubernetes / Argo / Flux / Tekton / Gateway API / cert-manager / External Secrets / Istio / Kyverno / Gatekeeper / KEDA / Knative | `readtheplan kubernetes rendered.yaml` | Rendered JSON/YAML, multi-doc, RBAC, workloads, GitOps, workflows/events, routing/mesh, admission policy, certificates/trust, secret sync, event-driven scaling, and serverless rules |
| Helm source | `readtheplan helm Chart.yaml` | Chart metadata, values, and Go-template source with dependencies, hooks, dynamic evaluation, exposure, privilege, and secret rules |
| Kustomize source | `readtheplan kustomize kustomization.yaml` | Resources/bases, remote pinning, patches, generators, image overrides, Helm inflation, plugins, and transforms |
| Crossplane | `readtheplan crossplane resources.yaml` | Packages/functions, image policy, runtime configuration, XRDs, Compositions, provider credentials, managed-resource lifecycle, and composite selection |
| Pulumi | `readtheplan pulumi preview.json` | Structured preview digest or streaming events + resource-aware rules |
| Ansible | `readtheplan ansible playbook.yml` | Structured plays/tasks/blocks/handlers/roles plus privilege, delegation, check-mode, error, secret-environment, include, identity, and supply-chain semantics |
| Salt | `readtheplan salt state.sls` | Structured SLS states, destructive functions, command/module execution, secrets, includes, and Jinja rendering |
| Jenkins | `readtheplan jenkins Jenkinsfile` | Declarative/scripted step, agent image/arguments, shared-library, credential, trigger, dynamic Groovy, artifact, and workspace analysis |
| Chef | `readtheplan chef default.rb` | Recipe resources/actions, remote artifacts, identities, schedules, notifications, guards, permissions, and cookbook includes |
| Puppet | `readtheplan puppet site.pp` | Built-in/custom resources, state, identities, classes, lookups/templates, virtual/exported resources, collectors, refresh relationships, and sources/permissions |
| GitHub Actions | `readtheplan github-actions workflow.yml` | Token permissions, action pinning, secrets, environments, and run steps |
| GitLab CI | `readtheplan gitlab-ci .gitlab-ci.yml` | Includes, tokens, downstream pipelines, environments, and scripts |
| CircleCI | `readtheplan circleci .circleci/config.yml` | Orbs, SSH keys, executors, remote Docker, and run steps |
| Azure Pipelines | `readtheplan azure-pipelines azure-pipelines.yml` | Repositories, templates, variable groups, pools, containers, environments, service connections, tasks, and scripts |
| Bitbucket Pipelines | `readtheplan bitbucket-pipelines bitbucket-pipelines.yml` | Images, runners, OIDC, deployments, services, caches, scripts, pipes, artifacts, imports, and secured-variable references |
| Buildkite | `readtheplan buildkite pipeline.yml` | Commands, dynamic uploads, plugins, agents/queues, secrets, artifacts, triggers, approvals, retries, concurrency, and effective agent policy |
| Atlantis | `readtheplan atlantis atlantis.yaml` | Repo/server configuration, mutation requirements, custom workflows, hooks, override permissions, locks, autoplan, policy checks, and execution ordering |
| Docker Compose | `readtheplan docker-compose compose.yml` | Images, builds, commands, host namespaces, capabilities, mounts, devices, secrets, and ports |
| Dockerfile / Containerfile | `readtheplan dockerfile Dockerfile` | Base images, stages, commands, build secrets, copied credentials, runtime users, health, and build-context boundaries |
| Nomad | `readtheplan nomad plan-response.json` | Structured scheduler diff, allocation replacement/stops, placement failures, drivers, images, and commands |
| Packer | `readtheplan packer inspect.txt` | Builders, provisioners, post-processors, sensitive/unresolved variables, and inspect limitations |
| Vagrant | `readtheplan vagrant Vagrantfile` | Boxes, providers, provisioners, networks, synced folders, triggers, host commands, and Ruby boundaries |
| cloud-init | `readtheplan cloud-init user-data.yml` | Users, SSH, packages, files, commands, storage, power state, includes, scripts, and merged configuration |
| systemd | `readtheplan systemd example.service` | Commands, identities, capabilities, credentials, sandboxing, filesystems, devices, sockets, timers, mounts, restart behavior, and merged-unit boundaries |
| NGINX | `readtheplan nginx nginx.conf` | Includes, modules, listeners, TLS, upstreams, authentication, headers, filesystem exposure, and inherited configuration |
| HAProxy | `readtheplan haproxy haproxy.cfg` | Runtime identity, listeners, TLS verification, upstreams, routing, traffic mutation, management APIs, Lua/program execution, and runtime state |
| Envoy | `readtheplan envoy envoy.yaml` | Bootstrap/config dumps, listeners, admin, clusters, TLS validation, xDS, runtime layers, secrets, filters, Lua/Wasm, authorization, and active runtime boundaries |
| Traefik | `readtheplan traefik traefik.yml` | YAML/JSON/TOML static and dynamic config, entry points, providers, API/dashboard, ACME, plugins, routers, middleware, services, and TLS |
| Caddy | `readtheplan caddy Caddyfile` | Caddyfile/native JSON, sites/listeners, admin API, automatic/on-demand TLS, proxy trust, upstreams, authentication, filesystems, application execution, and modules |
| Grafana | `readtheplan grafana grafana.ini` | Server/auth/security INI plus provisioning YAML/JSON for data sources, dashboards, alerting, plugins, deletion, credentials, and access control |
| Grafana Loki | `readtheplan loki loki.yml` | Authentication/tenancy boundaries, listeners/TLS, storage/schema, clustering, tenant limits, runtime overrides, ruler egress, retention/deletion, and query paths |
| HashiCorp Vault | `readtheplan vault vault.hcl` | HCL/JSON server config, listeners, TLS/proxy trust, storage/HA, seals, plugins, telemetry, service registration, memory locking, and user lockout |
| HashiCorp Consul | `readtheplan consul consul.hcl` | HCL/JSON agent config, quorum/bootstrap, listeners, ACLs, TLS/gossip encryption, service mesh, discovery, services/checks, remote execution, and dynamic config |
| Prometheus | `readtheplan prometheus prometheus.yml` | Scrape jobs, discovery, targets, auth/TLS, relabeling, rule files, remote read/write, Alertmanager delivery, and OTLP ingestion |
| Alertmanager | `readtheplan alertmanager alertmanager.yml` | Routing, receivers, notification integrations, credentials, TLS, templates, inhibition/time intervals, and event export |
| OpenTelemetry Collector | `readtheplan otel-collector config.yaml` | Receivers, processors, exporters, connectors, extensions, pipelines, public diagnostics, TLS/auth, credentials, host/file access, and merged config providers |

The scripted configuration adapters deliberately classify unexpanded includes and unknown
constructs as `review`; they do not execute playbooks, pipelines, recipes, or manifests.
The CI workflow adapters preserve GitHub's YAML `on` key correctly and require
immutable references for reusable third-party code.
Buildkite analysis distinguishes exact plugin versions from floating refs and
surfaces dynamic pipeline uploads plus agent-hook, queue-policy, and interpolation boundaries.
Atlantis analysis covers both repository and server-side YAML so custom workflow
authorization and requirement overrides are evaluated alongside repo-defined commands.
Salt parses static SLS YAML and conservatively scans Jinja-templated state files;
render-time execution-module calls are dangerous and generated state remains review.
Docker Compose parsing follows Docker's documented trust boundary without resolving
external files. Nomad consumes the JSON response from the job plan HTTP API so
scheduler decisions remain structured rather than being inferred from HCL text.
Packer consumes saved output from `packer inspect` or
`packer inspect -machine-readable`; it enumerates executable components without
running a build and explicitly reminds reviewers that inspect is not validation.
Vagrantfiles are scanned as Ruby source without evaluation; known DSL operations,
host-command escape hatches, and merged configuration boundaries remain visible.
cloud-init user-data is parsed without executing guest code; scripts, boothooks,
commands, credentials, and first-boot system changes use the same gate contract.
systemd units are parsed statically without invoking the manager; repeated/reset
directives, activation targets, omitted hardening, and merged drop-ins remain visible.
NGINX and HAProxy configurations are parsed without loading modules, includes,
certificates, state files, Lua, or starting either proxy.
Envoy accepts bootstrap YAML/JSON and admin config dumps so statically declared
resources and active xDS-delivered runtime state share the same review contract.
Traefik analysis joins static provider/entry-point trust with dynamic routing,
middleware, service, and certificate configuration across YAML, JSON, and TOML.
Prometheus and Alertmanager analysis tracks telemetry ingestion/egress and alert
routing together without loading rule/template files or contacting integrations.
OpenTelemetry Collector analysis validates component definitions against activated
service pipelines and surfaces multi-file/provider boundaries without starting a collector.
Dockerfile analysis understands multi-stage builds, heredocs, BuildKit secret/SSH
mounts, and runtime metadata without invoking Docker or sending a build context.
Crossplane analysis parses package and resource manifests without pulling package
images, executing Composition functions/providers, contacting external APIs, or
resolving controller runtime state.
Serverless Framework and AWS SAM source analysis does not resolve variables,
download artifacts, execute plugins/builders/macros, package code, or synthesize
CloudFormation; each remains an explicit review or blocking trust boundary.
Kubernetes controller analysis understands Argo Workflows/Events, Gateway API,
cert-manager/trust-manager, External Secrets, Istio, Kyverno, Gatekeeper, KEDA,
and Knative API groups without contacting controllers, resolving runtime status,
or reading referenced Secrets.

## How it looks

Here's readtheplan analyzing one of the bundled example plans. Reproduce it after cloning with `readtheplan analyze examples/01-small-create/plan.json`:

<details open>
<summary><b>Terminal output (click to expand)</b></summary>

```text
$ readtheplan analyze examples/01-small-create/plan.json
# readtheplan summary: examples/01-small-create/plan.json
Terraform version: 1.8.5
Resource changes: 3

## Actions
- create: 2
- update: 1

## Risk
- review: 1
- safe: 2

## Changes
| Risk | Actions | Resource | Type | Explanation |
| --- | --- | --- | --- | --- |
| safe | create | aws_kms_key.app_config | aws_kms_key | Terraform will create a new resource without changing existing state. |
| review | update | aws_iam_role.deploy | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. |
| safe | create | aws_cloudwatch_log_group.api | aws_cloudwatch_log_group | Terraform will create a new resource without changing existing state. |
```
</details>

The default output is Markdown by design — paste it straight into a PR comment or an audit ticket.

And with a compliance framework:

<details>
<summary><b>With SOC 2 controls (click to expand)</b></summary>

```text
$ readtheplan analyze --framework soc2 examples/01-small-create/plan.json
...
## Changes
| Risk | Actions | Resource | Type | Explanation | Controls |
| --- | --- | --- | --- | --- | --- |
| safe | create | aws_kms_key.app_config | aws_kms_key | Terraform will create a new resource without changing existing state. | CC6.1, CC8.1 |
| review | update | aws_iam_role.deploy | aws_iam_role | Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk. | CC6.1, CC8.1 |
| safe | create | aws_cloudwatch_log_group.api | aws_cloudwatch_log_group | Terraform will create a new resource without changing existing state. | CC7.1, CC7.2, CC8.1 |
```
</details>

### Example: an EKS node group replacement

Replacing an EKS node group forces pod evictions, so readtheplan classifies it `dangerous` (an in-place update is `review`). This change ships in [`examples/03-multi-resource`](examples/03-multi-resource/) — reproduce it with `readtheplan analyze --framework soc2 examples/03-multi-resource/plan.json`:

```text
| Risk      | Actions       | Resource                   | Type               | Explanation                                                                                                     |
| --------- | ------------- | -------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------- |
| review    | update        | aws_eks_cluster.platform   | aws_eks_cluster    | Terraform will update this resource in place. Review the changed attributes and rollout timing before applying.  |
| dangerous | delete/create | aws_eks_node_group.workers | aws_eks_node_group | Terraform will replace an EKS node group. Expect pod evictions, capacity churn, and possible cluster disruption. |
```

Try the [interactive playground](https://readtheplan.dev/playground/) to see readtheplan analyze sample plans in your browser — no install required.

## Quickstart

### CLI — 30 seconds to first result

```bash
# Install
pip install readtheplan

# No Terraform handy? After cloning the repo, analyze a bundled example:
#   readtheplan analyze examples/01-small-create/plan.json

# Generate a plan (Terraform or OpenTofu)
terraform plan -out=tfplan -input=false
terraform show -json tfplan > plan.json

# Analyze it
readtheplan analyze plan.json

# With compliance framework
readtheplan analyze --framework soc2 plan.json

# Machine-readable JSON
readtheplan analyze --format json plan.json

# Print the report, then exit 2 when dangerous or irreversible changes exist
readtheplan analyze --fail-on dangerous plan.json

# Optional signed evidence support
pip install "readtheplan[sign]"

# Optional local MCP preview
pip install "readtheplan[mcp]"
```

## Usage

### 1) Basic plan parsing

```bash
readtheplan analyze plan.json
```

### 2) JSON output for automation

```bash
readtheplan analyze --format json plan.json > readtheplan-summary.json
```

### 3) Custom severity filter (dangerous + irreversible only)

```bash
readtheplan analyze --format json plan.json \
  | jq '.changes[] | select(.risk == "dangerous" or .risk == "irreversible")'
```

### 4) Gate any CI system by risk tier

```bash
readtheplan analyze --fail-on dangerous plan.json
```

`--fail-on` accepts `safe`, `review`, `dangerous`, or `irreversible`. It always
prints the selected text or JSON report first, then exits `2` if any change is
at or above the threshold. Exit `1` remains reserved for invalid input, I/O,
and other hard errors; exit `0` means analysis succeeded without tripping the
threshold.

### 5) Framework-annotated review for audits

```bash
readtheplan analyze --framework soc2 plan.json
```

### Docker

Build the bundled `Dockerfile` and run locally — your plan JSON stays on the mounted workspace and never leaves the container:

```bash
docker build -t readtheplan .
docker run --rm -v "$(pwd):/workspace" readtheplan analyze plan.json
```

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
  uses: readtheplan/readtheplan@v0.3.0   # pin to a released tag or a full commit SHA
  with:
    plan-file: plan.json
    fail-on-threshold: dangerous          # gate on dangerous / irreversible changes
```

**By default the action only reports — it never fails your build.** Add `fail-on-threshold` (`safe` | `review` | `dangerous` | `irreversible`) to turn findings into a gate, or `fail-on-any-change: true` for strict zero-diff policies.

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

Example JSON contract (abbreviated — the real command also emits `reason`, a ready-to-post `pr_comment`, an `evidence_checklist`, and an `auditor_summary`):

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

## Troubleshooting

- **`readtheplan: command not found`** — the entry point installed to a directory not on your `PATH` (common with `pip install --user`). Run `python -m readtheplan.cli analyze plan.json`, or add the reported scripts directory to your `PATH`.
- **`Error: invalid JSON in plan.json`** — you passed the binary plan or the human-readable `terraform plan` text. readtheplan reads the JSON from `terraform show -json tfplan > plan.json` (run `terraform plan -out=tfplan` first).
- **`Error: plan file does not exist`** — the plan JSON is the last argument: `readtheplan analyze <path-to-plan.json>`.
- **`--evidence requires --framework` / `--sign requires --evidence`** — evidence envelopes are framework-scoped and signing operates on an envelope. Add `--framework soc2` (and `--evidence out.json`) accordingly.
- **CI exit codes** — `analyze --fail-on <tier>` returns `0` when the threshold is clear, `2` when one or more changes meet or exceed it, and `1` for hard errors such as invalid JSON or unreadable input. The normal report is printed before exit `2`.
- **No `Controls` column** — pass `--framework <name>` (`soc2`, `iso27001`, `hipaa`, …); without it readtheplan only classifies risk.
- **Python version** — requires Python 3.10+ (`python --version`).

## Features

- **CLI-first** — single `pip install`, runs anywhere Python runs
- **GitHub Action** — copy-paste into any workflow
- **Resource-aware rules** — first-party AWS, GCP, Azure, Kubernetes, Cloudflare, GitHub, and GitLab semantics for identity, data, compute, networking, edge security, source governance, CI/CD trust, traffic, and observability
- **Compliance evidence** — SOC 2, ISO 27001, HIPAA, PCI DSS, FedRAMP Moderate, and HITRUST mappings with signed JSON envelopes
- **Agent gate** — deterministic proceed/warn/block decisions for CI and AI agents
- **Customer rule overlays** — org-specific risk escalations via YAML, no code changes needed
- **MCP preview** — local stdio tools for agent and IDE integrations
- **No uploads** — plans, manifests, playbooks, recipes, and pipelines stay on your machine
- **MIT licensed** — use it anywhere, no strings attached

## What's not in scope

- Full language interpretation for dynamic Jenkins, Chef, or Puppet code (unknown constructs require review)
- SaaS dashboard (local-first by design)
- Hosted analyzer service until ADR 0013 security gates are implemented and enforced
- Policy-as-code engine (OPA/Sentinel exist for that)
- Competing with Spacelift/env0 on overlapping features

## Documentation

### Repository layout

The product is `src/readtheplan/` (CLI, rules engine, adapters) plus `action.yml`
(GitHub Action). The `site/` directory is the readtheplan.dev website — it has its
own build and is not part of the PyPI package. `benchmarks/` and `demo/` are
evaluation/demo material, not runtime code.

- [Website](https://readtheplan.dev) — setup generator, example output, intake
- [Docs](https://readtheplan.dev/docs/) — tutorials, API reference, examples
- [`examples/`](examples/) — sample plans with rendered output
- [Authoring rules & overlays](docs/authoring-rules.md) — add resource rules, control mappings, overlays, and adapters
- [Infrastructure support matrix](docs/support-matrix.md) — input formats, maturity, limitations, and shared CI outputs
- [Cross-tool GitHub Actions example](ci/multi-tool-gates.example.yml) — one gate contract across supported ecosystems
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

**v0.3 — stable CLI + GitHub Action.** The PyPI package ships the Python CLI and composite GitHub Action. Current development includes resource-aware AWS risk rules, compliance framework annotations, evidence envelopes, signed attestation verification, customer rule overlays, infrastructure adapters, MCP preview, examples, benchmarks, and the static onboarding site.

What's shipping next: deeper adapter coverage, cloud-native delivery workflows,
PCI-DSS and NIST 800-53 catalogs, and expanded cloud resource rules.

## License

MIT — see [LICENSE](./LICENSE).

## Author

[@texasich](https://github.com/texasich) — OSS contributions welcome.
