# Infrastructure support matrix

readtheplan uses one four-tier risk vocabulary and one agent-gate contract across
multiple infrastructure ecosystems. Support depth differs by input format; this
matrix makes those boundaries explicit.

| Ecosystem | Input | Command | Analysis depth | Maturity |
|---|---|---|---|---|
| Terraform / OpenTofu | `terraform show -json` plan | `readtheplan analyze plan.json` | Native plan diff, old/new state, resource-aware rules, evidence and signing | Stable |
| CloudFormation | Change Set JSON or old/new template wrapper | `readtheplan cloudformation changes.json` | Structured operations; template wrappers include deep old/new properties | Built-in |
| Azure Bicep / ARM | Deployment What-If JSON | `readtheplan azure whatif.json` | FullResourcePayloads operations and old/new resource state; conservative ResourceIdOnly handling | Built-in |
| Kubernetes | JSON/YAML, `kind: List`, multi-doc YAML, or diff wrapper | `readtheplan kubernetes rendered.yaml` | Workload, RBAC, secret, network, storage, custom-resource, and control-plane rules | Built-in |
| Helm | Rendered manifests from `helm template` | `readtheplan kubernetes rendered.yaml` | Same analysis as Kubernetes; chart template execution stays outside readtheplan | Rendered workflow |
| Kustomize | Rendered manifests from `kubectl kustomize` | `readtheplan kubernetes rendered.yaml` | Same analysis as Kubernetes | Rendered workflow |
| Crossplane | Rendered Kubernetes custom resources | `readtheplan kubernetes rendered.yaml` | Known Kubernetes kinds use deep rules; controller-dependent custom resources require review | Conservative |
| Argo CD | Application, ApplicationSet, and AppProject YAML | `readtheplan kubernetes argocd.yaml` | Automated-prune, wildcard project-boundary, source/destination, and deletion semantics | Built-in |
| Flux CD | Source, Kustomization, HelmRelease, image automation, and notification YAML | `readtheplan kubernetes flux.yaml` | Source trust/immutability, pruning/force, remote targets, decryption, Helm remediation, Git writes, webhook triggers, and deletion semantics | Built-in |
| Pulumi | Preview digest JSON or streaming JSON events | `readtheplan pulumi preview.json` | Structured operations, old/new inputs, provider normalization, deep resource rules | Built-in |
| Ansible | Playbook YAML | `readtheplan ansible playbook.yml` | Structured plays, tasks, nested blocks, handlers, and roles | Built-in |
| Jenkins | Jenkinsfile | `readtheplan jenkins Jenkinsfile` | Conservative recognized-step scanner; arbitrary execution and credentials block | Conservative |
| Chef | Recipe Ruby source | `readtheplan chef default.rb` | Conservative resource/action scanner; arbitrary execution blocks | Conservative |
| Puppet | Manifest source | `readtheplan puppet site.pp` | Conservative resource/state scanner; execution and destructive state block | Conservative |
| GitHub Actions | Workflow YAML | `readtheplan github-actions workflow.yml` | Token permissions, action/reusable-workflow pinning, secret inputs, environments, and run steps | Built-in |
| GitLab CI | `.gitlab-ci.yml` | `readtheplan gitlab-ci .gitlab-ci.yml` | Remote/project includes, scripts, tokens, downstream triggers, and deployment environments | Built-in |
| CircleCI | `.circleci/config.yml` | `readtheplan circleci .circleci/config.yml` | Orbs, machine executors, SSH keys, remote Docker, reusable steps, and run commands | Built-in |
| Docker Compose | Compose YAML | `readtheplan docker-compose compose.yml` | Images, builds, commands, privileges, host namespaces, capabilities, mounts, devices, secrets, external files, and published ports | Built-in |
| HashiCorp Nomad | `/v1/job/:id/plan` JSON response | `readtheplan nomad plan-response.json` | Scheduler diff, allocation placement/replacement/stops, failures, task drivers, images, commands, and secret-bearing fields | Built-in |
| HashiCorp Packer | Human or `-machine-readable` inspect output | `readtheplan packer inspect.txt` | Builders, provisioners, post-processors, sensitive/unresolved variables, and explicit inspect limitations | Conservative |

## Maturity meanings

- **Stable**: primary native format with evidence/signing and the broadest rule corpus.
- **Built-in**: first-party parser, CLI, tests, compliance gate, examples, and documented limitations.
- **Rendered workflow**: a supported upstream tool produces the artifact consumed by a built-in gate.
- **Conservative**: syntax-aware static analysis that never executes user code; unknown or dynamic behavior requires review.

## Shared automation contract

The GitHub Action accepts `tool` and `input-file` for every built-in CLI gate:

```yaml
- uses: readtheplan/readtheplan@<release-tag-or-commit-sha>
  with:
    tool: pulumi
    input-file: preview.json
    framework: soc2
    fail-on-threshold: dangerous
```

Outputs are normalized across native summaries and agent gates:

- `summary-json`: the complete source result;
- `change-count`: number of analyzed changes;
- `risk-counts`: compact risk-count JSON;
- `action-counts`: action counts for native Terraform/OpenTofu analysis, `{}` for gate adapters.

The deprecated `plan-file` input remains an alias for `input-file`, and
`resource-change-count` remains an alias for `change-count`.

The action installs its bundled Python source by default so its metadata and CLI
always come from the same tag or commit. Set `install-source: readtheplan` only
when intentionally selecting the latest PyPI release instead.

Every built-in adapter accepts the same six packaged compliance catalogs: SOC 2,
ISO 27001, HIPAA, PCI DSS, FedRAMP Moderate, and HITRUST. Exact resource mappings
provide detailed controls where available; an exact-first framework baseline ensures
new providers, pipeline steps, and custom resources still receive change-management
evidence instead of an empty control set. CloudFormation, Azure, Kubernetes, and
Pulumi expose the same optional `framework` parameter through their MCP tools.

## Deliberate boundaries

- readtheplan does not execute Jenkins, Chef, Puppet, Ansible, Helm, Kustomize,
  Pulumi, GitHub Actions, GitLab CI, CircleCI, Docker Compose, Nomad, Packer, or provider code.
- Generate plans and rendered artifacts with the upstream tool in the trust
  boundary where that tool already runs, then pass the artifact to readtheplan.
- Dynamic includes, plugins, controller behavior, and custom code cannot always
  be resolved statically. Those cases must remain `review` rather than receiving
  false-safe classifications.
- AWS CDK currently flows through synthesized CloudFormation. Terragrunt flows
  through Terraform/OpenTofu plan JSON. A separate adapter is unnecessary unless
  those tools expose additional structured semantics worth preserving.
- Argo CD and Flux receive first-party GitOps semantics. Other controller custom
  resources remain conservative because their reconciliation effects depend on
  code and runtime configuration outside the submitted manifest.
- Docker Compose analysis deliberately does not resolve `include`, `extends`,
  `env_file`, secret files, build contexts, or Dockerfiles. Those external trust
  boundaries remain review or dangerous.
- Nomad analysis accepts the structured plan response returned by the HTTP API.
  Generate it inside the existing Nomad trust boundary; readtheplan never contacts
  the cluster or submits a job.
- Packer analysis accepts `packer inspect` output and never starts a build. Inspect
  enumerates components but does not validate plugin-specific configuration, so
  the gate always retains an explicit review finding and recommends separate
  `packer validate` execution in the caller's trust boundary.
