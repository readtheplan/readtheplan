# Changelog

## [Unreleased]

### Changed
- Terraform-provider GitHub Action dogfood now runs as a bounded parallel matrix,
  preserving every provider-specific output assertion while shortening the CI critical path.
- Self-improving evolution analysis now stays local and deterministic;
  candidate generation never spawns external model tooling.

### Added
- Native Ansible lookup analysis across the CLI, GitHub Action, project scan, and MCP. Static
  playbook, task, handler, play-variable, and role-parameter inspection now distinguishes
  controller-side command and state-changing lookups from filesystem, environment/configuration,
  network and secret-store access plus dangerous custom/collection and dynamically selected
  controller plug-ins; it also surfaces
  `allow_unsafe`, weakened lookup error handling, secret output without `no_log`, and lookup counts
  without executing plugins or exposing lookup arguments.
- Native Terraform/OpenTofu plan-integrity findings across the CLI, GitHub Action, project scan,
  evidence, and MCP. Stable JSON analysis now validates supported plan format versions and
  surfaces errored, not-applyable, and incomplete plans, deferred changes, out-of-band drift,
  root-output changes and sensitivity regressions, failed/error/unknown checks, state-forget
  operations, and Terraform 1.14+ provider action invocations while omitting raw plan values,
  check messages, and action configuration from derived output.
- Puppet Bolt task-implementation gates across the CLI, GitHub Action, project scan, and MCP.
  Bounded, non-executing inspection now recognizes shell, PowerShell, Python, and Ruby task
  programs (including extensionless shebang scripts) and surfaces target execution, dynamic code
  and process launches, destructive changes, network/remote access, privilege and permission
  changes, system/filesystem mutation, unsafe deserialization, parameter/secret handling, and
  explicit metadata/interpreter/target-state boundaries.
- Jenkins controller Groovy-hook gates across the CLI, GitHub Action, project scan, and MCP.
  Bounded, non-executing inspection now recognizes `init.groovy(.d)` and
  `boot-failure.groovy(.d)` and surfaces controller APIs, security/authorization, credentials,
  identities, plugins, agents/clouds, jobs, lifecycle, commands, filesystem/network access,
  runtime configuration, literal secrets, and explicit hook-order/runtime boundaries.
- Chef cookbook-content and custom-Ohai gates across the CLI, GitHub Action, project scan, and MCP.
  Bounded, non-executing inspection now covers recipes, attributes, custom resources, libraries,
  legacy providers/definitions, ERB templates, and Ohai plugins/shared libraries, including
  resources/actions, precedence, collection blocks, automatic attributes, built-in/core
  collisions, sensitive node data, hints/dependencies, commands, network/cloud metadata,
  filesystem/environment access, mutation, unsafe deserialization, TLS bypass, and explicit
  call-site/render/node/persistence boundaries.
- Native Terraform/OpenTofu dependency-lock gates across the CLI, GitHub Action,
  and MCP. Strict `.terraform.lock.hcl` parsing now covers duplicate or malformed
  blocks, exact provider selection, constraints, origin registries, pre-release
  versions, h1/zh checksum validity and coverage, unknown schemes, custom/local
  origins, and explicit signer/platform/module/read-only-mode boundaries.
- Native CFEngine gates across the CLI, GitHub Action, and MCP. Non-executing
  policy scanning covers bundles, promise types, policy inputs and execution
  order, commands/files/packages/services/users/storage/access, dynamic
  functions, server trust, executor schedules, secrets, and dependencies;
  strict Augments JSON parsing covers autorun, added inputs/bundles, nested
  Augments, credentials, and Masterfiles Policy Framework boundaries.
- Native Microsoft DSC and PowerShell DSC gates across the CLI, GitHub Action,
  and MCP. Strict DSC v3 JSON/YAML parsing and non-executing PowerShell source
  scanning cover nested resource adapters, destructive and executable resources,
  software/content provenance, secrets, dependency ordering, node targeting,
  resource-module pinning, LCM pull/remediation/reboot policy, plaintext MOF
  credentials, and explicit runtime/compilation boundaries.
- Native Nix/NixOS gates across the CLI, GitHub Action, and MCP. Strict
  `flake.lock` graph parsing plus conservative flake/module source scanning now
  covers input provenance and pinning, caches/daemon trust, signatures and
  sandboxing, fetches/impurity/build code, users/SSH/sudo/firewalls, services,
  systemd/activation scripts, kernel/storage/network/containers, secrets, and
  lazy module-evaluation boundaries.
- Salt project gates across the CLI, GitHub Action, and MCP. Strict parsing of
  master/minion configuration, top files, and Salt SSH rosters now covers PKI
  trust, remote authorization, state/Pillar/module sources, GitFS provenance,
  automatic reactors/schedules/startup execution, fleet targeting, SSH
  privilege and host verification, credentials, and project boundaries.
- Native AWS CDK gates across the CLI, GitHub Action, and MCP. Strict parsing of
  Cloud Assembly and asset manifests now covers schema/runtime compatibility,
  stacks, target environments, deployment roles, missing context, artifact graphs,
  synthesis diagnostics, nested assemblies, file/Docker asset producers,
  build secrets/SSH/networking, publishing destinations, and deployment boundaries.
- Puppet project gates across the CLI, GitHub Action, and MCP. Strict parsing of
  `Puppetfile`, module `metadata.json`, and `hiera.yaml` now covers Forge/Git
  provenance, immutable revisions, install paths, dependency bounds, Hiera
  hierarchy/backends/data paths/options, literal secrets, and Ruby boundaries.
- Chef project gates across the CLI, GitHub Action, and MCP. Static parsing of
  `Policyfile.rb`, `Policyfile.lock.json`, and cookbook `metadata.rb` now covers
  run lists, cookbook sources and resolved identity, immutable Git revisions,
  included policies, attributes/secrets, gems, compatibility, privacy, and Ruby boundaries.
- Ansible project configuration gates across the CLI, GitHub Action, and MCP.
  Strict parsing of `ansible.cfg` and Galaxy requirements YAML now covers SSH
  trust, privilege, controller plugins/callbacks, inventory execution, Galaxy
  credentials/TLS, dependency pinning, SCM transport, and signature metadata.
- Jenkins Configuration as Code gates across the CLI, GitHub Action, and MCP.
  JCasC controller YAML now receives explicit authentication, authorization,
  credential, executor, agent/cloud, image provenance, library, script-approval,
  Job DSL, endpoint/TLS, CSRF, secret interpolation, and plugin-boundary findings.
- Native Azure Bicep source gates across the CLI, GitHub Action, and MCP.
  Static analysis now covers resources/modules, deployment scope, RBAC and policy,
  Deployment Scripts, public exposure, complete-mode deletion, secure parameters
  and outputs, secret/file functions, and explicit compiler/What-If boundaries.
- First-party Terraform rules for all 63 resources in New Relic provider v3.94.0.
  Account identity and API/Synthetics credentials, alerting/muting, notification
  workflows and Workflow Automation, dashboards, Synthetics/private locations,
  cloud-account links, telemetry pipelines/drop/obfuscation/retention, federated
  logs, fleet agents/configuration, APM settings, SLOs, workloads, and downtime
  now receive explicit blind-spot, secret-state, data-loss, execution, and recovery semantics.
- First-party Terraform rules for all 51 resources in PagerDuty provider v3.33.0.
  Users/teams/contact paths, schedules and escalation, services/dependencies,
  event orchestration and legacy rulesets, Automation Actions runners, incident
  workflows/response plays/maintenance windows, external integrations, webhooks,
  Slack/ServiceNow/Jira, and custom incident/service schemas now receive explicit
  incident-routing, credential-state, automation, availability, and recovery semantics.
- Complete first-party Terraform rules for all 83 resources in HashiCorp's
  Kubernetes provider v3.2.1 and `helm_release` in the Helm provider v3.2.0.
  Versioned workloads, autoscaling, admission webhooks/CEL, arbitrary manifests,
  RBAC, service identity/tokens/certificates, networking, storage, scheduling,
  quotas, metadata patches, and Helm chart lifecycle now receive explicit
  cluster-impact, state-exposure, disruption, and recovery semantics.
- First-party Terraform rules for all 72 resources in HashiCorp TFE provider
  v0.78.0. Workspaces/projects/stacks and remote state, variables and tokens,
  teams/SAML/SCIM, Sentinel/OPA policy and exclusions, agents/run tasks/triggers,
  VCS and cloud/Vault OIDC trust, private registry supply chain, notifications,
  data retention, SMTP, and HYOK now receive explicit infrastructure-governance
  semantics.
- First-party Terraform rules for all 111 resources in Grafana provider
  v4.40.1. Tokens and secure values, RBAC/permissions/SSO/SCIM, dashboards and
  public sharing, data sources and cloud integrations, alerting and OnCall,
  GitSync, assistant MCP servers, k6, ML and Asserts, hosted stacks/plugins,
  Synthetic Monitoring, and fleet/frontend telemetry now receive explicit
  control-plane semantics.
- First-party Terraform rules for all 198 resources in HashiCorp Vault provider
  v5.10.1. Secret values and generated tokens, auth methods and identity, ACL,
  Sentinel/RGP and quota policy, dynamic-secret engines, PKI/SSH/KMIP/transit
  cryptography, audit devices, namespaces/mounts/Raft recovery, executable
  plugins, and external Secrets Sync destinations now receive explicit
  control-plane and Terraform state-exposure semantics.
- First-party Terraform rules for all 146 resources in Datadog provider v4.14.0,
  provider catalog. Credentials and service accounts, organization identity and
  access policy, cloud and incident integrations, logs/APM/RUM retention and
  routing, monitors/SLOs/Synthetics, Cloud Security and AppSec, sensitive-data
  scanning, findings workflow, on-call and deployment automation, and App
  Builder/catalog data now receive explicit control-plane semantics.
- First-party Terraform rules for all 130 resources in the current GitLab
  provider catalog. Projects/groups and instance defaults, protected refs and
  environments, approvals, identity/federation, tokens/keys/variables, runners
  and cluster agents, hooks/integrations/mirrors, CI job-token trust, releases
  and registry protection, security/compliance policy, and collaboration
  metadata no longer fall back to generic Terraform semantics.
- First-party Terraform rules for the GitHub provider. Repository lifecycle and
  visibility, branches and rulesets, organization/team/collaborator access,
  Actions execution and workflow-token policy, secrets and variables,
  environments, deploy keys, webhooks, hosted runners, OIDC trust, GitHub Apps,
  repository files, and security-analysis settings now receive control-plane
  semantics instead of the generic Terraform baseline.
- First-party Terraform rules for Cloudflare provider v5 and important v4
  aliases. Zones/DNS/DNSSEC, edge rules and settings, Workers, Zero Trust,
  tunnels, R2/D1/KV/Queues, load balancing, TLS, API identity, Logpush, and
  Pages now receive resource-specific risk semantics through every native plan
  surface instead of the generic Terraform baseline.
- Deeper configuration-management gates for Ansible, Jenkins, Chef, and Puppet.
  Privilege/delegation and task controls, agent supply chain and dynamic Groovy,
  remote cookbook artifacts/guards/notifications, and Puppet classes/data,
  custom, virtual, exported, and collected resources now receive explicit
  semantics. A shared local MCP gate and real Action fixtures cover all four.
- First-party Kubernetes rules for Istio, Kyverno, OPA Gatekeeper, KEDA, and
  Knative Serving/Eventing. Mesh traffic and identity, admission policy code and
  exceptions, external scaler credentials, event-driven Jobs, serverless
  revisions/routes, and CloudEvent delivery now receive API-group-aware
  semantics instead of generic custom-resource review.
- First-party Kubernetes rules for Argo Workflows/Events, Gateway API,
  cert-manager/trust-manager, and External Secrets. Executable workflows,
  event-driven triggers, listener/route namespace trust, cross-namespace grants,
  signing authorities and key rotation, distributed trust, external secret-store
  scope, refresh/replication, outbound pushes, and generators no longer collapse
  into generic custom-resource review.
- Native Serverless Framework service and AWS SAM template gates across the CLI,
  generalized Action, and local MCP server. Deployment identities and artifacts,
  wildcard IAM, functions, public events, plugins, variables, packaging,
  transforms/macros, code sources, APIs, state machines, nested applications,
  Connectors, custom builds, and lifecycle policies are visible before synthesis.
- Native Crossplane package and resource gates across the CLI, generalized
  Action, and local MCP server. Providers, Functions, Configurations, image
  policy, runtime overrides, XRDs, Compositions, one-way MRD activation,
  provider credentials, managed-resource lifecycle, and composite selection now
  receive first-party semantics instead of a generic custom-resource review.
- Native Helm Chart.yaml, values YAML, template source, and Kustomize source
  gates across the CLI, generalized Action, and local MCP server. Dependency
  pinning, hooks, dynamic evaluation, generated secrets, resource composition,
  remote bases, patches, generators, image overrides, Helm inflation, and
  plugin execution join the shared risk contract before rendering.
- Native Terraform configuration and Terragrunt HCL/JSON gates across the CLI,
  generalized Action, and local MCP server. Provider/module supply chain,
  backends, provisioners, lifecycle, remote state, static exposure, hooks,
  injected arguments, dependencies/mocks, generated files, assumed identity,
  and configuration-time functions join the shared risk contract before a plan
  exists.
- Native Grafana Loki YAML and Caddyfile/native JSON gates across the CLI,
  generalized Action, and local MCP server. Loki tenancy, listeners, storage,
  schemas, limits, runtime overrides, rules, retention, and query paths join
  Caddy admin/TLS, proxy trust, upstream, authentication, filesystem,
  application execution, and module boundaries in the shared risk contract.
- Native HashiCorp Vault and Consul HCL/JSON gates across the CLI, generalized
  Action, and local MCP server. Vault listeners, storage/HA, seals, plugins,
  telemetry, service registration, and lockout join Consul quorum, ACL, TLS,
  gossip, service mesh, discovery, checks, execution, and dynamic configuration
  in the shared risk contract.
- Native Grafana configuration gates across the CLI, generalized Action, and
  local MCP server. Server/auth/security INI plus provisioning YAML/JSON expose
  listeners, cookies, anonymous/proxy/federated auth, data sources, dashboards,
  alerting, plugins, credentials, deletion, and access control through the
  shared risk contract.
- Native Traefik YAML/JSON/TOML gates across the CLI, generalized Action, and
  local MCP server. Static entry points, forwarded-header trust, providers,
  Docker/Kubernetes scope, API/dashboard, ACME, plugins and observability join
  dynamic routers, auth/CORS middleware, upstreams, certificates, transports,
  and TLS options in the shared risk contract.
- Native OpenTelemetry Collector configuration gates across the CLI, generalized
  Action, and local MCP server. Receivers, host/file collection, public endpoints,
  processors, exporters, connectors, extensions, diagnostics, TLS/auth, secrets,
  service pipeline references, self-telemetry, and file/HTTP/environment config
  providers feed the shared risk contract.
- Native Prometheus and Alertmanager configuration gates across the CLI,
  generalized Action, and local MCP server. Scrape/discovery targets, rule files,
  relabeling, remote read/write, HTTP auth/TLS, OTLP, alert routing, notification
  integrations, credentials, templates, inhibition/time intervals, and event
  export feed the shared risk contract.
- Native Envoy bootstrap and admin config-dump gates across the CLI, generalized
  Action, and local MCP server. Listeners, admin exposure, clusters, xDS sources,
  runtime layers, TLS identity validation, secrets, routes, access logs, filters,
  Lua/Wasm/native extension code, external authorization fail-open behavior, and
  effective runtime boundaries feed the shared risk contract.
- Native Atlantis repo-level and server-side configuration gates across the CLI,
  generalized Action, and local MCP server. Plan/apply/import requirements,
  custom commands, environment steps, workflow hooks, override permissions,
  custom-workflow authorization, repo scope, locks, autoplan, policy checks,
  parallelism, and execution ordering feed the shared risk contract.
- Native Buildkite pipeline gates across the CLI, generalized Action, and local
  MCP server. Commands, dynamic uploads, plugin pinning, agents/queues, secrets,
  environment interpolation, artifacts, triggers, approvals, retries,
  concurrency, soft-fail gates, and agent/runtime policy boundaries feed the
  shared risk contract.
- Native NGINX and HAProxy configuration gates across the CLI, generalized
  Action, and local MCP server. Static parsing surfaces includes, executable
  modules/Lua/programs, runtime identity, public listeners, TLS verification,
  upstream routing, authentication, header/traffic mutation, management APIs,
  host files, state, and effective inherited-configuration boundaries.
- Native systemd unit gates across the CLI, generalized Action, and local MCP
  server. Static parsing preserves repeated/reset directives and surfaces host
  commands, runtime identity, capabilities, credentials, sandboxing, filesystem
  and device access, sockets, timers, mounts, restart loops, activation targets,
  and effective merged-unit boundaries without invoking systemd.
- Tekton-aware Kubernetes rules for Tasks, Pipelines, Runs, remote resolvers,
  workspaces, ServiceAccounts, pod security, EventListeners, TriggerTemplates,
  Triggers, bindings, and ResolutionRequests. Rendered Tekton YAML now receives
  native execution and event-ingress semantics through every Kubernetes surface.
- Native Bitbucket Pipelines YAML gates across the CLI, generalized Action, and
  local MCP server. Images, self-hosted runners, OIDC, deployments, service
  containers, Docker access, caches, scripts, Pipes, artifacts, custom variables,
  shared imports, and external settings feed the shared gate contract.
- Native Azure Pipelines YAML gates across the CLI, generalized Action, and local
  MCP server. Repository/container resources, templates, variable groups, inline
  secrets, pools, deployment environments, service connections, tasks, scripts,
  and protected-resource boundaries feed the shared gate contract.
- Native Dockerfile/Containerfile gates across the CLI, generalized Action, and
  local MCP server. Multi-stage builds, heredocs, mutable base images, commands,
  BuildKit secret/SSH mounts, secret ARG/ENV, sensitive COPY/remote ADD, root
  runtime defaults, health, deferred instructions, and context boundaries are
  classified without invoking a frontend or builder.
- Native cloud-init user-data gates across the CLI, generalized Action, and local
  MCP server. Cloud-config YAML, scripts, boothooks, URL includes, and MIME
  boundaries surface users, SSH trust, files, secrets, commands, storage,
  package, power-state, Jinja, and merged-configuration risks without execution.
- Native Vagrantfile gates across the CLI, generalized Action, and local MCP
  server. Static scanning covers boxes, providers, provisioners, networks,
  synced folders, triggers, private keys, host commands, and unresolved Ruby or
  merged configuration without evaluating the Vagrantfile.
- Native Salt SLS gates across the CLI, generalized Action, and local MCP server.
  Static YAML states receive module/function-aware risk; Jinja files receive a
  conservative fallback, and render-time execution, destructive states,
  credential-like Pillar/SDB inputs, includes, and duplicate keys are surfaced.
- Native Packer inspect gates across the CLI, generalized Action, and local MCP
  server. Human and machine-readable inspect output is normalized into builders,
  provisioners, post-processors, masked/unresolved variables, and an explicit
  inspection-limit review without running a build.
- Flux-aware Kubernetes rules for GitRepository/OCIRepository sources,
  Kustomizations, HelmReleases, image update automation, and webhook Receivers.
  The rules cover source authentication and immutability, pruning, force,
  decryption, remote targets, remediation, automated Git writes, and deletion.
- Native Docker Compose and HashiCorp Nomad gates across the CLI, generalized
  Action, and local MCP server. Compose analysis covers host access and container
  boundaries without resolving external files; Nomad consumes structured job-plan
  API responses and preserves scheduler allocation semantics.
- Native GitHub Actions, GitLab CI, and CircleCI YAML gates across the CLI,
  generalized Action, and local MCP server. The adapters flag write-token scopes,
  unpinned reusable code, secret exposure, arbitrary commands, remote includes,
  deployment environments, SSH keys, orbs, and remote Docker without executing
  pipeline code.
- Exact-first compliance baselines across all six packaged frameworks. Every
  Terraform provider and built-in adapter now receives a change-management or
  secure-configuration control even before a resource-specific mapping exists;
  CloudFormation and Kubernetes MCP tools now accept `framework` like their CLI
  counterparts.
- Azure Bicep/ARM deployment What-If adapter, CLI gate, MCP tool, and Action
  selector. FullResourcePayloads old/new state feeds existing Azure resource
  rules; ResourceIdOnly, potential changes, and diagnostics require review.
- Argo CD-aware Kubernetes rules for Applications, ApplicationSets, and
  AppProjects. Automated pruning and wildcard project boundaries classify as
  dangerous; scoped GitOps changes require review.
- Kubernetes gates now accept individual JSON/YAML manifests, `kind: List`,
  multi-document YAML, and diff wrappers. This enables rendered Helm and
  Kustomize output directly; unknown Crossplane/controller resources require
  review, while control-plane extension kinds classify as dangerous.
- Built-in Pulumi preview adapter, CLI gate, and local MCP tool. It accepts
  preview digest JSON and streaming JSON events, normalizes provider types and
  input property names, and reuses deep resource-aware risk rules.
- Built-in local adapters and CLI gates for Ansible playbooks, Jenkins pipelines,
  Chef recipes, and Puppet manifests. Scripted formats use conservative static
  analysis and never execute user infrastructure code.

## [0.4.0] — 2026-07-11

### Added
- Repository issue templates, pull request template, CODEOWNERS, Dependabot config, and PyPI trusted-publisher workflow scaffolding.
- GitHub Action parser tests and oversized `summary-json` output guardrail.
- CLI `analyze --fail-on <tier>` gating with distinct exit codes: `0` for success, `1` for hard errors, and `2` when the risk threshold is met.
- `agent-gate` and `cloudformation` subcommands now return meaningful exit codes: `0` for `proceed`, `1` for `warn`, `2` for `block`.
- PR comment truncation indicator: when more than 5 resources are flagged, the comment now shows "...and N more".
- **Kubernetes adapter** — agent-gate contract for manifest diffs and single
  manifests: `readtheplan kubernetes` subcommand, `agent_gate_kubernetes` MCP
  tool, and RBAC/Secret/NetworkPolicy-aware rules.
- **Self-improving mode** — `--mode self-improving` on `analyze` and
  `agent-gate` records runs, detects incident patterns, and generates rule
  candidates; candidates activate only via explicit, hash-verified
  `readtheplan evolve approve <rule-id>`.

### Security
- Generated evolution rules can no longer self-activate. Candidates are
  confined to `~/.readtheplan/`, capped at `pr-ready`, and load only from a
  SHA-256 allowlisted manifest after explicit approval (2026-07-10 review,
  finding 1).
- Kubernetes diffs now surface RBAC `rules`, binding `roleRef`/`subjects`,
  Secret `stringData`/`binaryData`, and `aggregationRule` changes; wildcard
  Role/ClusterRole grants classify as dangerous instead of safe (finding 2).
- All MCP file reads (Terraform, CloudFormation, Kubernetes) enforce
  `MCP_ROOT` confinement with race-resistant file-descriptor verification
  (finding 3).

### Fixed
- CLI `analyze` now catches `RecursionError` on deeply nested JSON and prints a friendly error instead of a traceback.
- Self-improving mode is install-safe: candidate verification runs
  in-process (pytest is no longer needed at runtime), and evolution
  diagnostics go to stderr so JSON stdout stays machine-parseable
  (finding 4).
- Importing the CLI no longer creates `~/.readtheplan` as a side effect,
  and `analyze --mode self-improving` now actually records the run
  (finding 5).

### Changed
- Sigstore is now a true optional `sign` extra with a clear install hint when signing is requested without it.
- GitHub Action threshold behavior now checks risks at or above the configured threshold.
- Site and docs copy now label static demos as example output and document the agent-gate JSON contract more explicitly.
- Site deploy target migrated from GitHub Pages to Azure static website hosting (OIDC + blob sync workflow).
- Plan identity hash is now a content-based canonical digest
  (`rtp-plan-hash-v2`, ADR 0014): full SHA-256 over sorted resource changes,
  independent of file path and rule-derived fields. Legacy 16-character
  hashes in existing evolution databases remain untouched.

### Breaking Changes
- **GitHub Action: `fail-on-changes` deprecated.** The `fail-on-changes` input is superseded by `fail-on-any-change`. Workflows using `fail-on-changes` will continue to work but should migrate. The new `fail-on-threshold` input (risk-tier gating: safe/review/dangerous/irreversible) takes precedence over both.
- **Sigstore is now an optional extra.** Signing support requires `pip install "readtheplan[sign]"` instead of `pip install readtheplan`. Running `readtheplan sign` without the extra will print a clear install hint.
- **Python 3.10+ required.** The minimum Python version is now 3.10 (was 3.9). This aligns with the MCP dependency requirement.

## [0.3.0] — 2026-05-11

### Added
- **In-browser playground** — drag a `plan.json`, see instant risk analysis with compliance annotations (SOC 2, ISO 27001, HIPAA). Zero install.
- **Floci integration** — demo pipeline for generating real Terraform plans against emulated AWS. Sample plans (create + destroy) available in playground.
- **Documentation site** — `/docs/` with Quickstart, CLI Reference, and GitHub Action guide.
- **Comparison table** — 8-tool comparison (readtheplan vs tflint/tfsec/checkov/Spacelift/env0/Snyk/infracost/OPA).
- **"Why I built this" story** — linked from README.
- **CloudFormation adapter** — first IaC adapter for readtheplan agent-gate (PR #31).
- **Demo video** — terminal typing animation showing live analysis.
- **GitHub Pages deployment** — site auto-deploys on push to main.

### Changed
- **Killed Alpha label** — readtheplan is now v0.3 with a stability promise.
- **One-liner install** — `pip install readtheplan && readtheplan analyze plan.json`.
- **CONTRIBUTING.md** — dev setup, test commands, coding conventions, good first issues.
- **Site redesign** — split demo into standalone `/demo/` page, dark theme terminal aesthetic.

### Fixed
- **Gate contract** — PR #34: action semantics, tool_name refactor, CFN CLI/MCP compatibility.
- **GitHub Pages paths** — absolute href/src now prefixed with `/readtheplan/` for correct resolution.

## [0.0.2] — 2026-02-15
- Initial PyPI release with CLI, risk classification, and SOC 2 compliance mapping.

## [0.0.1] — 2026-01-20
- First experimental release.
