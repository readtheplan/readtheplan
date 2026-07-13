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

**Infrastructure change risk analysis for humans, CI pipelines, and AI agents.** Review cloud plans, Kubernetes manifests, Docker Compose workloads, Nomad jobspecs and scheduler plans, configuration-management code, and CI pipelines through one deterministic local risk gate. Runs locally — no uploads, no accounts, no backend.

```bash
pip install readtheplan && readtheplan scan .
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
Azure, the complete HashiCorp Kubernetes and Helm provider catalogs, Cloudflare,
Datadog, Grafana, New Relic, PagerDuty, GitHub, GitLab, HashiCorp Vault, and HCP Terraform/TFE. Every adapter feeds the same six **compliance
framework mappings** with an exact-first change-management baseline and
deterministic agent-gate schema; native plan analysis can also produce
**auditable evidence envelopes** with sigstore-backed signed attestations.

### Supported infrastructure tools

| Tool | Command | Analysis level |
|------|---------|----------------|
| Project auto-discovery | `readtheplan scan .` | Recursively discovers high-confidence infrastructure inputs by canonical path or distinctive content, routes specialized formats such as Crossplane, SAM, Serverless Framework, JCasC, Pulumi, Azure What-If, and Carvel to their native analyzers, skips dependency/build directories and symlinks, and returns one deterministic aggregate gate with per-file results and validation errors |
| Terraform / OpenTofu | `readtheplan analyze plan.json` | Structured plan diff plus plan format/integrity flags, deferred changes, drift, root outputs, checks, provider action invocations, state-forget operations, and AWS, GCP, Azure, complete HashiCorp Kubernetes/Helm, New Relic, PagerDuty, Cloudflare, Datadog, Grafana, GitHub, GitLab, HashiCorp Vault, and HCP Terraform/TFE resource-aware rules without exposing plan values |
| Terraform configuration | `readtheplan terraform-config main.tf` | HCL/JSON providers, backends, modules, resources/data, provisioners, lifecycle, remote state, imports/moves/removals, secrets, and static exposure |
| Terraform Stacks | `readtheplan terraform-stack stack.tfdeploy.hcl` | Native `.tfcomponent.hcl` and `.tfdeploy.hcl` analysis for module/provider provenance, component and deployment fan-out, removals/destroy/import, auto-approval, OIDC identities, variable stores, cross-Stack data, secrets, and static HCP runtime boundaries |
| Terraform / OpenTofu dependency lock | `readtheplan terraform-lock .terraform.lock.hcl` | Strict provider source/version selection, constraint context, h1/zh checksum validity and coverage, custom/local origins, pre-releases, unknown hash schemes, and signer/platform/module/read-only-mode boundaries |
| Terraform / OpenTofu state | `readtheplan terraform-state state.json` | Stable `show -json` and read-only raw v4 snapshots; value-safe outputs/resources, sensitivity gaps, failed checks, tainted/deposed instances, current posture, and storage/freshness boundaries |
| Terragrunt | `readtheplan terragrunt terragrunt.hcl` | HCL/JSON root modules, hooks, CLI arguments, remote state, includes, dependencies/mocks, generated files, inputs, assumed identity, engines, and evaluation functions |
| Terramate | `readtheplan terramate terramate.tm.hcl` | Project/stack configuration and .tmgen analysis for safeguards, execution environment, imports/vendor, globals, stack graphs/watch paths, HCL/file generation, scripts/commands, cloud sync, output sharing/mocks, secrets, bundles, and non-evaluation boundaries |
| Spacelift runtime configuration | `readtheplan spacelift .spacelift/config.yml` | Repository and single-stack runtime overrides, schema precedence, hooks, environment/secrets, runner-image provenance, project/sparse-checkout scope, Terraform/OpenTofu workflow and version selection, Terragrunt execution/state ownership, module tests, and non-execution boundaries |
| CloudFormation | `readtheplan cloudformation changes.json` | Structured change set or template diff |
| AWS CDK | `readtheplan cdk cdk.out/manifest.json` | Versioned Cloud Assembly and asset manifests: stacks, context, roles, artifact graphs, templates, file/Docker assets, executable producers, build secrets/SSH/networking, destinations, and deployment boundaries |
| Serverless Framework | `readtheplan serverless serverless.yml` | Framework/tool version, deployment identity/artifacts, IAM, functions, events, plugins, variables, packaging, and embedded CloudFormation |
| AWS SAM | `readtheplan sam template.yaml` | Transforms/macros, Globals, functions/code, policies, event ingress, APIs, state machines, nested apps, Connectors, builds, and lifecycle policies |
| Azure Bicep source | `readtheplan bicep main.bicep` | Static resources/modules, target scopes, RBAC/policy/locks, Deployment Scripts, public access, secure parameters/outputs, external files, and compiler boundaries |
| Azure Bicep / ARM What-If | `readtheplan azure whatif.json` | Structured deployment What-If with FullResourcePayloads old/new state |
| Kubernetes / Argo / Flux / Tekton / Gateway API / cert-manager / External Secrets / Istio / Kyverno / Gatekeeper / KEDA / Knative / Cluster API / Karpenter | `readtheplan kubernetes rendered.yaml` | Rendered JSON/YAML, multi-doc, RBAC, workloads, GitOps, workflows/events, routing/mesh, admission policy, certificates/trust, secret sync, scaling/serverless, and cluster/machine/node lifecycle rules |
| Helm source | `readtheplan helm Chart.yaml` | Chart metadata, values, and Go-template source with dependencies, hooks, dynamic evaluation, exposure, privilege, and secret rules |
| Helmfile | `readtheplan helmfile helmfile.yaml.gotmpl` | State and lock analysis for repositories, releases, chart versions, environments, kube contexts, values/secrets, Go-template execution, hooks, kubectlApply, post-renderers, nested states, lifecycle safety, dependency integrity, and non-execution boundaries |
| Kustomize source | `readtheplan kustomize kustomization.yaml` | Resources/bases, remote pinning, patches, generators, image overrides, Helm inflation, plugins, and transforms |
| Crossplane | `readtheplan crossplane resources.yaml` | Packages/functions, image policy, runtime configuration, XRDs, Compositions, provider credentials, managed-resource lifecycle, and composite selection |
| Pulumi | `readtheplan pulumi preview.json` | Structured preview digest or streaming events + resource-aware rules |
| Pulumi project / stack / policy | `readtheplan pulumi-project Pulumi.yaml` | Strict project, stack, ESC, secrets-provider, package/plugin, runtime, backend, Pulumi YAML resource, and policy-pack metadata analysis without execution |
| Ansible | `readtheplan ansible roles/web/tasks/main.yml` | Strict playbook, reusable role-task, and handler YAML analysis covering blocks, handler scope/notifications, imports/includes, privilege, delegation, check/error controls, Jinja lookups (controller commands/state, files, environment, network, secrets, custom plugins, unsafe evaluation), secret environments, identity, and supply-chain semantics |
| Ansible project / executable content / inventory / Controller export / Event-Driven Ansible / content policy / execution environment / Molecule | `readtheplan ansible-project plugins/modules/deploy.py` | Checked-in Python/PowerShell custom modules, Python controller plugins and `module_utils`, including command/network/filesystem/privilege/deserialization/TLS/secret/check-mode findings and controller-vs-target execution boundaries; also Automation Controller/AWX assets, EDA rulebooks, controller transport, Galaxy dependencies, inventory, collection/role metadata, Ansible-lint policy, Builder/Navigator isolation, and Molecule providers/sequences/verifiers |
| Salt | `readtheplan salt state.sls` | Structured SLS states, destructive functions, command/module execution, secrets, includes, and Jinja rendering |
| Salt project | `readtheplan salt-project master` | Master/minion trust and execution settings, roots and remote sources, reactors/schedules, top targeting, Salt SSH rosters, credentials, and unresolved project boundaries |
| Nix / NixOS | `readtheplan nix flake.nix` | Flake inputs and lock graphs, cache/daemon trust, fetch provenance, impure evaluation, NixOS users/SSH/firewall/services/systemd/kernel/containers/secrets, and module-merge boundaries |
| Microsoft DSC / PowerShell DSC | `readtheplan dsc configuration.dsc.yaml` | DSC v3 JSON/YAML resources, nested adapters, secrets, dependencies, software/content sources, and legacy PowerShell DSC resources, node targeting, LCM pull/remediation/reboot policy, credentials, and MOF compilation boundaries |
| CFEngine | `readtheplan cfengine promises.cf` | Policy bundles and promise types, inputs/bundlesequence, commands/files/packages/services/users/storage/access, server trust, executor schedules, dynamic functions, secrets/dependencies, strict Augments JSON, autorun extensions, and MPF boundaries |
| OPA / Rego / Conftest | `readtheplan opa policy.rego` | Rego network/runtime/debug capabilities, fail-open decisions, exceptions, data dependencies and tests; bundle roots, revisions, Wasm and signature metadata; Conftest paths and invocation boundaries, without policy execution |
| HashiCorp Sentinel | `readtheplan sentinel policy.sentinel` | Policy imports, HTTP/runtime/Terraform data, fail-open main rules, parameters and secrets; CLI policy/module sources, enforcement levels, executable plugins, mocks, test assertions, and runtime boundaries without execution |
| SOPS | `readtheplan sops .sops.yaml` | Creation rules, path scopes, KMS/Vault/age/PGP identities, key groups and Shamir thresholds, encryption selectors, MAC coverage, destination rules, and encrypted YAML/JSON/dotenv/INI documents without decryption or key-service access |
| Jenkins | `readtheplan jenkins Jenkinsfile` | Declarative/scripted step, agent image/arguments, shared-library, credential binding and Groovy secret-interpolation sinks, trigger, dynamic Groovy, artifact, and workspace analysis |
| Jenkins Configuration as Code | `readtheplan jenkins-jcasc jenkins.yaml` | Controller realms/authorization, credentials, executors, agents/clouds, trusted/untrusted Shared Libraries, immutable/default/override policy, implicit loading, changelog/cache/SCM/fork trust, script approvals, Job DSL, endpoints, TLS, and plugin boundaries |
| Jenkins project / Groovy | `readtheplan jenkins-project init.groovy.d/10-security.groovy` | Plugin Installation Manager catalogs, Jenkins Job Builder YAML/JSON, Shared Library `vars/*.groovy` / `src/**/*.groovy`, and controller init/boot-failure Groovy hooks; controller APIs, security realms/authorization, credentials, identities, plugins, agents/clouds, jobs, lifecycle, dependency loading, commands, mutable globals, CPS/serialization, filesystem/network access, and trust/runtime boundaries |
| TeamCity | `readtheplan teamcity .teamcity/settings.kts` | Kotlin DSL commands, credentials, VCS roots, triggers, dependencies, agents, integrations, cleanup, images, artifacts, and settings-generation code |
| Chef cookbook content / custom Ohai | `readtheplan chef cookbooks/base/ohai/cloud_inventory.rb` | Recipes, attributes, custom resources, libraries, legacy providers/definitions, ERB templates, and custom Ohai plugins/shared libraries; resources/actions, precedence, collection blocks, automatic attributes, built-in/core collisions, sensitive node data, hints/dependencies, commands, network/metadata/filesystem access, mutation, unsafe deserialization, TLS bypass, and runtime boundaries without executing Ruby |
| Chef project / dependencies / runtime | `readtheplan chef-project habitat/plan.sh` | Policyfiles/locks, Berksfiles and dependency graphs, cookbook metadata, Infra Client, Workstation/knife, Solo, Server, Test Kitchen configuration, and Chef Habitat plans/lifecycle hooks; migration, trust, credentials, provenance, graph integrity, execution, lifecycle, drivers/transports, privilege, bootstrap, TLS/LDAP/database controls, and Ruby/ERB/shell/template boundaries |
| Chef InSpec | `readtheplan inspec controls/main.rb` | Profile metadata, dependency locks, controls, custom-resource libraries, and YAML/JSON/CSV waivers; platform scope, provenance/integrity, gems, inputs, inheritance/skips, command and remote resources, expiry, secrets, and Ruby/transport/runtime boundaries |
| Puppet | `readtheplan puppet site.pp` | Built-in/custom resources, state, identities, classes, lookups/templates, virtual/exported resources, collectors, refresh relationships, and sources/permissions |
| Puppet project / Server policy / runtime / deployment / Bolt / extensions | `readtheplan puppet-project modules/site/facts.d/cloud_inventory.py` | Forge/Git modules, metadata, Hiera, agent settings, per-environment code/cache policy, PuppetDB failover/persistence, Puppet Server authorization/mTLS/CA/JRuby/routes, r10k/Code Manager, Bolt automation, Ruby facts/functions/types/providers/report processors, and `facts.d` executable or JSON/YAML/text external facts; surfaces code execution, core-fact overrides, commands, network/filesystem/system mutation, unsafe deserialization, secrets, timeouts, and server/agent runtime boundaries without execution |
| GitHub Actions | `readtheplan github-actions workflow.yml` | Token permissions, action pinning, secrets, environments, and run steps |
| GitLab CI | `readtheplan gitlab-ci .gitlab-ci.yml` | Includes, tokens, downstream pipelines, environments, and scripts |
| CircleCI | `readtheplan circleci .circleci/config.yml` | Orbs, SSH keys, executors, remote Docker, and run steps |
| Azure Pipelines | `readtheplan azure-pipelines azure-pipelines.yml` | Repositories, templates, variable groups, pools, containers, environments, service connections, tasks, and scripts |
| Bitbucket Pipelines | `readtheplan bitbucket-pipelines bitbucket-pipelines.yml` | Images, runners, OIDC, deployments, services, caches, scripts, pipes, artifacts, imports, and secured-variable references |
| Buildkite | `readtheplan buildkite pipeline.yml` | Commands, dynamic uploads, plugins, agents/queues, secrets, artifacts, triggers, approvals, retries, concurrency, and effective agent policy |
| Travis CI | `readtheplan travis-ci .travis.yml` | Imports, elevated workers, services, command phases, deployments, secrets, caches, conditions, and matrix failure policy |
| Drone CI | `readtheplan drone-ci .drone.yml` | Multi-document pipelines, runner selection, images, commands, host volumes, privileged containers, secrets, services, and failure policy |
| Woodpecker CI | `readtheplan woodpecker-ci .woodpecker.yml` | Workflows, runner selection, images/plugins, commands, host volumes, privileges, secrets, services, and dependencies |
| Concourse CI | `readtheplan concourse pipeline.yml` | Resources/types, variable sources, tasks, privileged execution, images, mutations, child pipelines, runtime variables, hooks, and soft failures |
| Bamboo Specs | `readtheplan bamboo bamboo-specs/bamboo.yml` | Multi-document plans/deployments, permissions, repositories, variables, triggers, jobs/tasks, agents, Docker, artifacts, and cleanup |
| AWS CodeBuild | `readtheplan codebuild buildspec.yml` | Build phases/commands, identities, plaintext and managed secrets, exported variables, failure policy, runtimes, batches, artifacts, reports, caches, and proxies |
| Google Cloud Build | `readtheplan cloud-build cloudbuild.yaml` | Step images/commands, Secret Manager/KMS values, service accounts, substitutions, volumes, failure policy, artifacts, published images, worker options, and logging |
| AWS CodePipeline | `readtheplan codepipeline codepipeline.json` | Pipeline/action IAM roles, artifact stores/flows, source/build/test/deploy/invoke/approval actions, provider configuration, triggers, variables, regions, and execution modes |
| Atlantis | `readtheplan atlantis atlantis.yaml` | Repo/server configuration, mutation requirements, custom workflows, hooks, override permissions, locks, autoplan, policy checks, and execution ordering |
| Docker Compose | `readtheplan docker-compose compose.yml` | Images, builds, commands, host namespaces, capabilities, mounts, devices, secrets, and ports |
| Docker Buildx Bake | `readtheplan docker-bake docker-bake.hcl` | HCL/JSON and Compose-backed build graphs, contexts, inheritance/matrices, secret and SSH forwarding, entitlements, caches, outputs/publication, source policies, attestations, and evaluation boundaries |
| Dockerfile / Containerfile | `readtheplan dockerfile Dockerfile` | Base images, stages, commands, build secrets, copied credentials, runtime users, health, and build-context boundaries |
| Nomad | `readtheplan nomad job.nomad.hcl` | HCL/JSON jobspecs plus structured scheduler plans: task drivers, commands/images, artifacts/templates, identities, Vault/Consul, services/networking, storage, secrets, placement, rollout, replacement, and stops |
| Packer | `readtheplan packer image.pkr.hcl` | Native HCL/JSON templates or inspect output: plugin/core constraints, variables/locals/data, builders/communicators/base images, provisioners, post-processors, publishing, secrets, functions, and non-execution boundaries |
| Skaffold | `readtheplan skaffold skaffold.yaml` | Config dependencies, build backends/artifacts/hooks, manifest renderers, deploy engines/flags, verification, custom actions, profiles, port forwarding, secrets, and non-execution boundaries |
| DevSpace | `readtheplan devspace devspace.yaml` | Imports/dependencies, POSIX pipelines/functions/commands, image builders, Helm/Kubernetes deployments, live development mutation/sync/ports/SSH, hooks, profiles, registry credentials, plugins, and non-execution boundaries |
| Tilt | `readtheplan tilt Tiltfile` | AST-backed Tiltfile scanning for host commands, extensions, image builders, Compose/Kubernetes deploys, Helm/Kustomize, custom deployers, live updates, file/environment access, ports, secrets, and dynamic Starlark boundaries |
| CUE | `readtheplan cue deploy_tool.cue` | Source/tool/module/local-module analysis for OCI dependencies, replacements, workflow capabilities/tasks, process/file/HTTP/OS operations, imports, secrets, embedding, injection, generated configuration, and evaluation boundaries |
| Jsonnet / Tanka | `readtheplan tanka environments/prod/main.jsonnet` | Jsonnet source, Tanka Environment, and jsonnet-bundler manifest/lock analysis for imports, ext-vars/TLAs, native callbacks, Helm/Kustomize rendering, Kubernetes targets, kubeconfig/cluster scope, secrets, dependency provenance/integrity, and non-evaluation boundaries |
| Carvel (ytt, vendir, kbld, imgpkg, kapp) | `readtheplan vendir vendir.yml` | Sandboxed ytt templates/data/overlays/libraries; vendir fetch sources and locks; kbld image search/build/override/publish; imgpkg digest locks; kapp rebase, ownership, ordering, lifecycle annotations, and live-cluster boundaries |
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
SOPS analysis never decrypts data or contacts KMS, Vault, age, PGP, or remote key services;
it inspects policy, recipient metadata, integrity coverage, and plaintext leakage locally.
The CI workflow adapters preserve GitHub's YAML `on` key correctly and require
immutable references for reusable third-party code.
Buildkite analysis distinguishes exact plugin versions from floating refs and
surfaces dynamic pipeline uploads plus agent-hook, queue-policy, and interpolation boundaries.
Atlantis analysis covers both repository and server-side YAML so custom workflow
authorization and requirement overrides are evaluated alongside repo-defined commands.
Salt parses static SLS YAML and conservatively scans Jinja-templated state files;
render-time execution-module calls are dangerous and generated state remains review.
Docker Compose parsing follows Docker's documented trust boundary without resolving
external files. Nomad accepts HCL/JSON jobspec source or the JSON response from the job plan HTTP API so
scheduler decisions remain structured rather than being inferred from HCL text.
Packer accepts native `.pkr.hcl`/`.pkr.json`, legacy JSON, saved `packer inspect`, or
`packer inspect -machine-readable`; source mode inspects configuration while inspect
mode enumerates executable components and explicitly reminds reviewers that inspect
is not validation. Neither mode initializes plugins or runs a build.
Skaffold Config YAML is parsed without resolving imported configs, building images,
rendering manifests, executing hooks/actions, or contacting Kubernetes clusters.
DevSpace YAML is parsed without resolving imports, dependencies, variables, expressions,
or profiles and without executing pipelines, hooks, plugins, builds, or deployments.
Tiltfiles receive AST-backed static analysis with a conservative source fallback; neither
mode evaluates Starlark, loads extensions, runs commands/builds, or contacts infrastructure.
CUE source is scanned without evaluation or unification; modules are not downloaded and
workflow tasks, file access, HTTP requests, process execution, and exports never run.
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
Docker Bake analysis never invokes Docker or Buildx, reads `.env` or secret files, fetches
contexts or caches, contacts builders/registries, or publishes artifacts; HCL/JSON and
Compose build definitions are inspected as a static build graph.
Crossplane analysis parses package and resource manifests without pulling package
images, executing Composition functions/providers, contacting external APIs, or
resolving controller runtime state.
Serverless Framework and AWS SAM source analysis does not resolve variables,
download artifacts, execute plugins/builders/macros, package code, or synthesize
CloudFormation; each remains an explicit review or blocking trust boundary.
Kubernetes controller analysis understands Argo Workflows/Events, Gateway API,
cert-manager/trust-manager, External Secrets, Istio, Kyverno, Gatekeeper, KEDA,
Knative, Cluster API, and Karpenter API groups without contacting controllers,
resolving runtime status, provisioning infrastructure, or reading referenced Secrets.

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

# Scan an entire repository and auto-select the matching analyzers
readtheplan scan .

# Add compliance checks and omit generated paths
readtheplan scan --framework soc2 --exclude 'generated/**' .

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

### 6) Let a local MCP agent scan the whole infrastructure repository

```bash
pip install "readtheplan[mcp]"
MCP_ROOT=/absolute/path/to/repository readtheplan mcp
```

Ask the MCP client to call `agent_gate_project` with the repository path. It
auto-discovers the same inputs as `readtheplan scan .`, opens every candidate
through the descriptor-verified `MCP_ROOT` boundary, and analyzes an isolated
temporary snapshot. Optional `framework`, `excludes`, `max_files`, and
`max_file_bytes` arguments keep agent scans scoped and deterministic. Source
contents and analyzer error text are not included in the aggregate result.

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
- **Resource-aware rules** — first-party AWS, GCP, Azure, complete HashiCorp Kubernetes/Helm, New Relic, and PagerDuty catalogs, Cloudflare, Datadog, Grafana, GitHub, GitLab, HashiCorp Vault, and HCP Terraform/TFE semantics for identity, data, compute, networking, edge security, incident response, source governance, CI/CD trust, traffic, secrets, security, and observability
- **Plan-integrity gates** — Terraform/OpenTofu plan format compatibility, errored/not-applyable/incomplete plans, deferrals, out-of-band drift, root-output sensitivity, failed or unknown checks, state detachment, and Terraform provider actions are first-class findings even when the resource diff is empty
- **Compliance evidence** — SOC 2, ISO 27001, HIPAA, PCI DSS, FedRAMP Moderate, and HITRUST mappings with signed JSON envelopes
- **Agent gate** — deterministic proceed/warn/block decisions for CI and AI agents
- **Customer rule overlays** — org-specific risk escalations via YAML, no code changes needed
- **MCP preview** — local stdio tools for agent and IDE integrations
- **No uploads** — plans, manifests, playbooks, recipes, and pipelines stay on your machine
- **MIT licensed** — use it anywhere, no strings attached

## What's not in scope

- Full language interpretation for dynamic Jenkins, Chef, or Puppet code (unknown constructs require review)
- Terraform/OpenTofu plan analysis consumes only the submitted stable JSON representation and never runs a provider, refreshes state, contacts a backend, or invokes a planned action. Plan values, check messages, action configuration, and deferred/drift before/after payloads are intentionally omitted from derived output; live credentials, remote state, policy results, apply-time checks, provider behavior, and post-plan drift remain external boundaries
- Chef cookbook content is inspected statically and never executes Ruby or ERB; dynamic dispatch, metaprogramming, effective attribute resolution, helper/partial loading, resource call sites, rendered targets, external secrets/state, and generated files remain review boundaries
- Chef Ohai analysis never loads or runs plugin Ruby; cookbook sync/install state, plugin paths and ordering, same-name definitions in other files, optional/disabled/minimal plugin settings, platform selection, hints, environment/filesystem/API values, collection timeouts, automatic-attribute allow/block policy, Chef Server persistence/search visibility, and downstream recipe behavior remain runtime boundaries
- Chef runtime configuration is analyzed statically; merged fragments, command-line/environment overrides, plugins, external secrets, generated service state, and Ruby conditions remain review boundaries
- Test Kitchen analysis never evaluates ERB or loads Ruby plugins; effective project/local/global YAML merges, `KITCHEN_*` path overrides, environment values, driver state, credentials, cookbook/verifier content, and live cloud, hypervisor, container, SSH, or WinRM systems remain review boundaries
- Chef Habitat analysis never executes plans or lifecycle hooks, builds HART packages, renders hook templates or `default.toml`, loads packages, or contacts Builder or Supervisor services; environment and target resolution, origin keys and signatures, transitive packages and install hooks, scaffolding, Supervisor flags, and live service behavior remain review boundaries
- Automation Controller/AWX export analysis is offline and does not import assets, contact controller APIs, decrypt credential placeholders, sync projects or inventories, validate execution-environment availability, resolve natural keys against existing objects, or prove that omitted resources and relationships will be pruned
- Event-Driven Ansible rulebook analysis never starts event sources, loads source/filter plugins, evaluates conditions, resolves runtime variables or Vault values, launches playbooks/modules/Controller templates, or contacts Automation Controller; Decision Environment contents, inventories, credentials, activation scaling/restart policy, network controls, referenced automation content, and live event-system behavior remain review boundaries
- Ansible playbook, reusable task-file, and handler analysis never executes Ansible or lookup plugins, renders Jinja, evaluates conditions or lookup results, expands imported or included content, loads role/collection plugins, or resolves inventory and Vault values. It statically classifies literal `lookup`/`query`/`q` and `with_*` capability boundaries, while plugin code, dynamic names, arguments, results, controller state, caller hosts, inherited variables/tags/privilege, module search paths, embedded custom code, handler insertion/collisions/notification routing, CLI selection, and live task results remain review boundaries
- Jenkins plugin catalogs are analyzed offline; update-center metadata, transitive dependencies, advisories, checksums, core compatibility, installed plugins, and installer flags remain external review inputs
- Jenkins Job Builder analysis never loads includes, renders Jinja/templates, imports component plugins, generates XML, or contacts Jenkins; effective defaults/macros, installed plugins, credentials, permissions, and controller state remain review boundaries
- Jenkins Shared Library analysis is static and never executes Groovy or contacts Jenkins/SCM; library trust, SCM ownership/revision, implicit loading, version overrides, folder permissions, sandbox approvals, replay, CPS transformation, resources, credentials, plugins, and runtime values remain review boundaries
- Jenkins controller-hook analysis never starts Jenkins or executes Groovy; hook ordering, core/plugin versions, controller filesystem/environment, existing configuration and credentials, initialization/failure state, runtime exceptions, and rollback remain review boundaries
- Jenkins JCasC library analysis distinguishes trusted and untrusted global libraries but does not resolve folder libraries/overrides, fetch SCM revisions, inspect repository permissions, read controller caches, or evaluate plugin-specific retriever/trait behavior
- Bolt project, inventory, YAML plan, task-metadata, and supported task-implementation analysis is static and never runs Bolt, evaluates Puppet expressions, resolves plugins, executes tasks/commands/scripts/nested plans, transfers files, or applies resources; configuration precedence, installed module/plugin provenance, metadata-to-implementation selection, bundled files, compiled binaries and unsupported implementation languages, resolved dynamic inventory, external secrets, target facts/variables/state, interpreter/library versions, transport behavior, plan cache, and live results remain runtime boundaries
- Puppet external-fact analysis never executes `facts.d` content; executable bits, pluginsync, agent identity/platform, Facter configuration and precedence, environment values, output parsing, duplicate definitions, compiled binaries, unsupported interpreters, timeouts, and downstream Puppet Server/PuppetDB visibility remain runtime boundaries
- r10k and Code Manager deployment analysis is static; remote branches, Git/Forge responses, credential files, resolved Puppetfiles/modules, filesystem contents, hooks, environmentpath matching, orchestration, and live server state remain runtime boundaries
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
