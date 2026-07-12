# Infrastructure support matrix

readtheplan uses one four-tier risk vocabulary and one agent-gate contract across
multiple infrastructure ecosystems. Support depth differs by input format; this
matrix makes those boundaries explicit.

| Ecosystem | Input | Command | Analysis depth | Maturity |
|---|---|---|---|---|
| Terraform / OpenTofu | `terraform show -json` plan | `readtheplan analyze plan.json` | Native plan diff, old/new state, resource-aware rules, evidence and signing | Stable |
| CloudFormation | Change Set JSON or old/new template wrapper | `readtheplan cloudformation changes.json` | Structured operations; template wrappers include deep old/new properties | Built-in |
| Serverless Framework | `serverless.yml` service source | `readtheplan serverless serverless.yml` | Framework/tool version, deployment identity and artifacts, IAM, functions, events, plugins, external variables, packaging, extensions and embedded CloudFormation | Built-in |
| AWS SAM | SAM template YAML/JSON | `readtheplan sam template.yaml` | Transforms/macros, Globals, functions/code sources, policies, event ingress, APIs, state machines, nested apps, Connectors, custom builds and lifecycle policies | Built-in |
| Azure Bicep / ARM | Deployment What-If JSON | `readtheplan azure whatif.json` | FullResourcePayloads operations and old/new resource state; conservative ResourceIdOnly handling | Built-in |
| Kubernetes | JSON/YAML, `kind: List`, multi-doc YAML, or diff wrapper | `readtheplan kubernetes rendered.yaml` | Workload, RBAC, secret, network, storage, custom-resource, and control-plane rules | Built-in |
| Helm | `Chart.yaml`, values YAML, Go-template source, or rendered manifests | `readtheplan helm Chart.yaml` / `readtheplan kubernetes rendered.yaml` | Dependencies, hooks, dynamic evaluation, files, generated secrets, images, exposure and privilege before rendering; rendered objects receive Kubernetes rules | Built-in |
| Kustomize | `kustomization.yaml` or rendered manifests | `readtheplan kustomize kustomization.yaml` / `readtheplan kubernetes rendered.yaml` | Resources/bases, remote pinning, patches, generators, images, Helm inflation, plugins and transforms before rendering; rendered objects receive Kubernetes rules | Built-in |
| Crossplane | Package and resource YAML/JSON | `readtheplan crossplane resources.yaml` | Packages/functions, OCI mutability, image policy, runtime configuration, XRDs, Compositions, MRD activation, provider credentials, managed-resource lifecycle and composite selection | Built-in |
| Argo CD | Application, ApplicationSet, and AppProject YAML | `readtheplan kubernetes argocd.yaml` | Automated-prune, wildcard project-boundary, source/destination, and deletion semantics | Built-in |
| Flux CD | Source, Kustomization, HelmRelease, image automation, and notification YAML | `readtheplan kubernetes flux.yaml` | Source trust/immutability, pruning/force, remote targets, decryption, Helm remediation, Git writes, webhook triggers, and deletion semantics | Built-in |
| Tekton | Task, Pipeline, Run, and Triggers YAML | `readtheplan kubernetes tekton.yaml` | Scripts/commands, image provenance, privileged settings, identities, workspaces, remote resolvers, event ingress, resource templates, and bindings | Built-in |
| Pulumi | Preview digest JSON or streaming JSON events | `readtheplan pulumi preview.json` | Structured operations, old/new inputs, provider normalization, deep resource rules | Built-in |
| Ansible | Playbook YAML | `readtheplan ansible playbook.yml` | Structured plays, tasks, nested blocks, handlers, and roles | Built-in |
| Salt | SLS YAML/Jinja state | `readtheplan salt state.sls` | State modules/functions, destructive operations, execution modules, credential-like Pillar/SDB inputs, includes/extends, and dynamic renderer boundaries | Built-in |
| Jenkins | Jenkinsfile | `readtheplan jenkins Jenkinsfile` | Conservative recognized-step scanner; arbitrary execution and credentials block | Conservative |
| Chef | Recipe Ruby source | `readtheplan chef default.rb` | Conservative resource/action scanner; arbitrary execution blocks | Conservative |
| Puppet | Manifest source | `readtheplan puppet site.pp` | Conservative resource/state scanner; execution and destructive state block | Conservative |
| GitHub Actions | Workflow YAML | `readtheplan github-actions workflow.yml` | Token permissions, action/reusable-workflow pinning, secret inputs, environments, and run steps | Built-in |
| GitLab CI | `.gitlab-ci.yml` | `readtheplan gitlab-ci .gitlab-ci.yml` | Remote/project includes, scripts, tokens, downstream triggers, and deployment environments | Built-in |
| CircleCI | `.circleci/config.yml` | `readtheplan circleci .circleci/config.yml` | Orbs, machine executors, SSH keys, remote Docker, reusable steps, and run commands | Built-in |
| Azure Pipelines | `azure-pipelines.yml` | `readtheplan azure-pipelines azure-pipelines.yml` | Repository/container resources, templates, variable groups, inline secrets, pools, deployment environments, service connections, tasks, scripts, and protected-resource boundaries | Built-in |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` | `readtheplan bitbucket-pipelines bitbucket-pipelines.yml` | Images, self-hosted runners, OIDC, deployments, services, Docker daemon access, caches, scripts, pipes, artifacts, custom variables, imports, and external settings | Built-in |
| Docker Compose | Compose YAML | `readtheplan docker-compose compose.yml` | Images, builds, commands, privileges, host namespaces, capabilities, mounts, devices, secrets, external files, and published ports | Built-in |
| Dockerfile / Containerfile | Dockerfile source | `readtheplan dockerfile Dockerfile` | Frontends, base-image pinning, stages, commands/heredocs, BuildKit mounts, secret ARG/ENV, COPY/ADD, users, health, deferred instructions, and context boundaries | Built-in |
| HashiCorp Nomad | `/v1/job/:id/plan` JSON response | `readtheplan nomad plan-response.json` | Scheduler diff, allocation placement/replacement/stops, failures, task drivers, images, commands, and secret-bearing fields | Built-in |
| HashiCorp Packer | Human or `-machine-readable` inspect output | `readtheplan packer inspect.txt` | Builders, provisioners, post-processors, sensitive/unresolved variables, and explicit inspect limitations | Conservative |
| HashiCorp Vagrant | Vagrantfile Ruby source | `readtheplan vagrant Vagrantfile` | Boxes, providers, provisioners, networks, synced folders, triggers, host commands, and unresolved Ruby/configuration merging | Conservative |
| cloud-init | Cloud-config YAML, scripts, boothooks, includes, or MIME user-data | `readtheplan cloud-init user-data.yml` | Packages, users, SSH trust, files, commands, storage, power state, external content, templates, and merged configuration | Built-in |

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
evidence instead of an empty control set. Every file-backed built-in gate exposes
the same optional `framework` parameter through its MCP tool.

## Deliberate boundaries

- readtheplan does not execute Jenkins, Chef, Puppet, Ansible, Salt, Helm, Kustomize,
  Crossplane packages, providers, or Composition functions,
  Serverless Framework plugins or AWS SAM builds/transforms,
  Pulumi, GitHub Actions, GitLab CI, CircleCI, Azure Pipelines, Bitbucket Pipelines,
  Docker Compose, Dockerfiles, Nomad, Packer,
  Vagrant, cloud-init user-data, or provider code.
- Generate plans and rendered artifacts with the upstream tool in the trust
  boundary where that tool already runs, then pass the artifact to readtheplan.
- Dynamic includes, plugins, controller behavior, and custom code cannot always
  be resolved statically. Those cases must remain `review` rather than receiving
  false-safe classifications.
- Crossplane analysis recognizes control-plane APIs and common managed/composite
  resource conventions without pulling OCI packages, resolving provider-specific
  schemas, invoking functions, or contacting Kubernetes or external cloud APIs.
  Package signature-verification feature flags, RBAC, admission, provider runtime
  state, and external-resource state remain deployment-side trust boundaries.
- Serverless Framework and AWS SAM analysis parses source without resolving
  variables, loading external files, downloading code/application artifacts,
  executing plugins or custom builders, or applying CloudFormation macros. Run
  the corresponding synthesized CloudFormation change set through the existing
  CloudFormation gate for operation-level confirmation before deployment.
- AWS CDK currently flows through synthesized CloudFormation. Terragrunt flows
  through Terraform/OpenTofu plan JSON. A separate adapter is unnecessary unless
  those tools expose additional structured semantics worth preserving.
- Argo CD, Flux, and Tekton receive first-party controller semantics. Other custom
  resources remain conservative because their reconciliation effects depend on
  code and runtime configuration outside the submitted manifest.
- Tekton analysis covers Pipeline and Triggers API groups without contacting the
  cluster or resolving remote Tasks. Resolver installation/configuration, RBAC,
  admission, ServiceAccount credentials, and EventListener network exposure remain
  external trust boundaries that must be verified in the target cluster.
- Docker Compose analysis deliberately does not resolve `include`, `extends`,
  `env_file`, secret files, build contexts, or Dockerfiles. Those external trust
  boundaries remain review or dangerous.
- Dockerfile analysis parses instructions, continuations, and common heredocs but
  never invokes a frontend or builder. The build context, `.dockerignore`, supplied
  arguments/secrets, remote cache, and BuildKit entitlements remain explicit review
  boundaries; callers can additionally run `docker build --check` upstream.
- Azure Pipelines analysis parses YAML without expanding templates or contacting
  Azure DevOps. Approvals/checks, variable-group authorization, environments,
  agent-pool permissions, and service-connection permissions live outside YAML
  and therefore remain an explicit protected-resource review boundary.
- Bitbucket Pipelines analysis parses YAML aliases and nested pipeline structures
  without contacting Bitbucket or executing Pipes. Secured variables, deployment
  permissions, SSH keys, runner registration, and workspace/repository dynamic
  pipeline providers live outside YAML and remain an explicit review boundary.
- Nomad analysis accepts the structured plan response returned by the HTTP API.
  Generate it inside the existing Nomad trust boundary; readtheplan never contacts
  the cluster or submits a job.
- Packer analysis accepts `packer inspect` output and never starts a build. Inspect
  enumerates components but does not validate plugin-specific configuration, so
  the gate always retains an explicit review finding and recommends separate
  `packer validate` execution in the caller's trust boundary.
- Salt analysis parses static SLS YAML with duplicate-key rejection. Jinja-templated
  SLS files receive conservative line-based state discovery plus an unresolved
  renderer finding; calls such as `salt['cmd.run'](...)` during rendering block.
- Vagrant analysis scans the documented Ruby DSL without executing it. Arbitrary
  Ruby, plugins, box Vagrantfiles, provider configuration, and configuration from
  the Vagrant home directory remain an explicit review boundary.
- cloud-init analysis requires a documented user-data header, rejects duplicate
  cloud-config keys, and never executes guest code. MIME parts remain a review
  boundary until decoded, and callers should additionally run `cloud-init schema`
  inside their existing validation environment.
