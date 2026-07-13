# Infrastructure support matrix

readtheplan uses one four-tier risk vocabulary and one agent-gate contract across
multiple infrastructure ecosystems. Support depth differs by input format; this
matrix makes those boundaries explicit.

| Ecosystem | Input | Command | Analysis depth | Maturity |
|---|---|---|---|---|
| Terraform / OpenTofu | `terraform show -json` plan | `readtheplan analyze plan.json` | Native plan diff, old/new state, resource-aware rules, evidence and signing | Stable |
| Terraform / OpenTofu state | `terraform show -json` / `tofu show -json` state or raw v4 snapshot | `readtheplan terraform-state state.json` | Value-safe output/resource inventory, sensitivity gaps, failed checks, tainted/deposed instances, current resource posture, deep rules, and backend/freshness/schema boundaries; never modifies state | Built-in |
| OPA / Rego / Conftest | Rego module, OPA `.manifest` / `.signatures.json`, or `conftest.toml` | `readtheplan opa policy.rego` | Runtime/network/debug built-ins, fail-open rules, exceptions, data dependencies, bundle roots/revisions/Wasm/signature metadata, policy paths, and non-evaluation boundaries | Built-in |
| HashiCorp Sentinel | `.sentinel` policy or `sentinel.hcl` / `sentinel.json` CLI configuration | `readtheplan sentinel policy.sentinel` | HTTP/runtime/Terraform/custom imports, main-rule posture, parameters, remote policy/module sources, enforcement, executable plugins, mocks, secrets, test assertions, and non-execution boundaries | Built-in |
| Cloudflare Terraform provider | Provider v5 plan resources plus important v4 aliases | `readtheplan analyze plan.json` | Zones/DNS/DNSSEC, rulesets/WAF and settings, Workers/routes, Zero Trust/tunnels, R2/D1/KV/Queues, load balancing, TLS, API identity, Logpush, and Pages | Built-in |
| CloudFormation | Change Set JSON or old/new template wrapper | `readtheplan cloudformation changes.json` | Structured operations; template wrappers include deep old/new properties | Built-in |
| AWS CDK | `cdk.out/manifest.json` or asset manifest JSON | `readtheplan cdk cdk.out/manifest.json` | Cloud Assembly schema/runtime, stacks/accounts/regions/roles/templates, missing context, artifact graphs/metadata, nested assemblies, file and Docker asset production/publishing, executable producers, secrets/SSH/networking, and deployment boundaries | Built-in |
| Serverless Framework | `serverless.yml` service source | `readtheplan serverless serverless.yml` | Framework/tool version, deployment identity and artifacts, IAM, functions, events, plugins, external variables, packaging, extensions and embedded CloudFormation | Built-in |
| AWS SAM | SAM template YAML/JSON | `readtheplan sam template.yaml` | Transforms/macros, Globals, functions/code sources, policies, event ingress, APIs, state machines, nested apps, Connectors, custom builds and lifecycle policies | Built-in |
| Azure Bicep source | `.bicep` source | `readtheplan bicep main.bicep` | Resources/modules, broad scopes, RBAC/policy/locks, Deployment Scripts, public access, secure parameters/outputs, secret/file functions, and compiler boundaries | Conservative |
| Azure Bicep / ARM What-If | Deployment What-If JSON | `readtheplan azure whatif.json` | FullResourcePayloads operations and old/new resource state; conservative ResourceIdOnly handling | Built-in |
| Kubernetes | JSON/YAML, `kind: List`, multi-doc YAML, or diff wrapper | `readtheplan kubernetes rendered.yaml` | Workload, RBAC, secret, network, storage, custom-resource, and control-plane rules | Built-in |
| Helm | `Chart.yaml`, values YAML, Go-template source, or rendered manifests | `readtheplan helm Chart.yaml` / `readtheplan kubernetes rendered.yaml` | Dependencies, hooks, dynamic evaluation, files, generated secrets, images, exposure and privilege before rendering; rendered objects receive Kubernetes rules | Built-in |
| Kustomize | `kustomization.yaml` or rendered manifests | `readtheplan kustomize kustomization.yaml` / `readtheplan kubernetes rendered.yaml` | Resources/bases, remote pinning, patches, generators, images, Helm inflation, plugins and transforms before rendering; rendered objects receive Kubernetes rules | Built-in |
| Crossplane | Package and resource YAML/JSON | `readtheplan crossplane resources.yaml` | Packages/functions, OCI mutability, image policy, runtime configuration, XRDs, Compositions, MRD activation, provider credentials, managed-resource lifecycle and composite selection | Built-in |
| Argo CD | Application, ApplicationSet, and AppProject YAML | `readtheplan kubernetes argocd.yaml` | Automated-prune, wildcard project-boundary, source/destination, and deletion semantics | Built-in |
| Flux CD | Source, Kustomization, HelmRelease, image automation, and notification YAML | `readtheplan kubernetes flux.yaml` | Source trust/immutability, pruning/force, remote targets, decryption, Helm remediation, Git writes, webhook triggers, and deletion semantics | Built-in |
| Tekton | Task, Pipeline, Run, and Triggers YAML | `readtheplan kubernetes tekton.yaml` | Scripts/commands, image provenance, privileged settings, identities, workspaces, remote resolvers, event ingress, resource templates, and bindings | Built-in |
| Argo Workflows / Events | Workflow, template, CronWorkflow, EventSource, Sensor, EventBus, and event-binding YAML | `readtheplan kubernetes argo.yaml` | Executable templates, images, pod privilege, ServiceAccounts, Secrets/artifacts, event ingress, payload substitution, triggers, delivery and bus persistence | Built-in |
| Kubernetes Gateway API | GatewayClass, Gateway/ListenerSet, Routes, ReferenceGrant, and BackendTLSPolicy YAML | `readtheplan kubernetes gateway.yaml` | Listener exposure/TLS, route namespace trust, host matching, filters/mirroring, backend references, cross-namespace grants, and backend TLS validation | Built-in |
| cert-manager / trust-manager | Certificate, Issuer, CertificateRequest, ACME, and Bundle YAML | `readtheplan kubernetes certificates.yaml` | Signing authority scope, wildcard/CA issuance, key rotation, ACME DNS/HTTP mutation, request approval, Secret ownership, and distributed trust | Built-in |
| External Secrets Operator | Store, ExternalSecret, PushSecret, and generator YAML | `readtheplan kubernetes external-secrets.yaml` | Backend identity/scope, cluster-wide namespace boundaries, bulk imports, refresh/templates, Secret replication, outbound pushes, deletion policy, and generated credentials | Built-in |
| Istio | Networking, security, telemetry, EnvoyFilter, and WasmPlugin YAML | `readtheplan kubernetes istio.yaml` | Traffic reachability, namespace export, external services, TLS/mTLS, authorization/JWT, low-level proxy patches, extension provenance, and telemetry gaps | Built-in |
| Kyverno | Legacy ClusterPolicy/Policy plus validating, mutating, generating, deleting, image, cleanup, and exception policy YAML | `readtheplan kubernetes kyverno.yaml` | Admission enforcement, CEL/context, mutation/generation/deletion, image verification, scheduled cleanup, cluster scope, and policy exceptions | Built-in |
| OPA Gatekeeper | ConstraintTemplate, Constraint, mutation, Config, SyncSet, ExpansionTemplate, and external-data Provider YAML | `readtheplan kubernetes gatekeeper.yaml` | Rego/CEL policy code, enforcement mode, admission mutation, inventory sync, process exclusions, expansion, and external policy data | Built-in |
| KEDA | ScaledObject, ScaledJob, authentication, and CloudEventSource YAML | `readtheplan kubernetes keda.yaml` | Scale bounds and scale-to-zero, metric endpoints/TLS, fallback, executable Jobs, credential/identity scope, rollout, and autoscaling event export | Built-in |
| Knative Serving / Eventing | Service/Route/Revision plus Broker, Trigger, Channel, Subscription, flows, sources, EventPolicy, transforms, and request/reply YAML | `readtheplan kubernetes knative.yaml` | Container/image/identity risk, traffic visibility and revision splits, CloudEvent routing/filtering, retries/DLQ, event-source identity, and sender authorization | Built-in |
| Pulumi | Preview digest JSON or streaming JSON events | `readtheplan pulumi preview.json` | Structured operations, old/new inputs, provider normalization, deep resource rules | Built-in |
| Pulumi project / stack / policy | `Pulumi.yaml`, `Pulumi.<stack>.yaml`, or `PulumiPolicy.yaml` | `readtheplan pulumi-project Pulumi.yaml` | Strict duplicate-safe YAML; runtime/compiler and path execution, backends, packages/plugins and provenance, project config schemas, encrypted/plaintext stack config, secrets providers, ESC imports, Pulumi YAML resources with deep rules, policy packs, and explicit evaluation boundaries | Built-in |
| Ansible | Playbook YAML or `roles/*/{tasks,handlers}/*.yml` | `readtheplan ansible roles/web/tasks/main.yml` | Strict duplicate-safe plays, reusable tasks, nested blocks, and handlers; global notification scope, static imports/dynamic includes, privilege, controller delegation, check/error controls, dynamic expressions, identity/host security, supply-chain inputs, TLS, secret-bearing environments, and caller/runtime boundaries | Built-in |
| Ansible project / inventory / Controller export / Event-Driven Ansible / content policy / execution environment / Molecule | `ansible.cfg`, requirements, inventory, Automation Controller/AWX export JSON/YAML, `extensions/eda/rulebooks/*.yml`, `galaxy.yml`, role/collection metadata, Ansible-lint config, `execution-environment.yml`, Navigator, or Molecule YAML | `readtheplan ansible-project extensions/eda/rulebooks/remediate.yml` | Controller/AWX assets plus EDA rulesets, source/filter plugins, webhook ingress, event conditions, playbook/module and Controller template actions, concurrency, retries, propagation, credentials and activation boundaries; also dependency provenance, inventory scope, content policy, Builder/Navigator isolation, and Molecule providers/sequences/cleanup | Built-in |
| Salt | SLS YAML/Jinja state | `readtheplan salt state.sls` | State modules/functions, destructive operations, execution modules, credential-like Pillar/SDB inputs, includes/extends, and dynamic renderer boundaries | Built-in |
| Salt project | Master/minion YAML config, top files, or Salt SSH rosters | `readtheplan salt-project master` | PKI trust, remote authorization, state/Pillar/module roots, GitFS provenance, reactors/schedules/startup execution, fleet targeting, SSH privilege, credentials, proxies, and host verification | Built-in |
| Nix / NixOS | `flake.nix`, `flake.lock`, or NixOS module source | `readtheplan nix flake.nix` | Input/lock provenance and graph integrity, substituters/trusted users/signatures/sandbox, fetchers/impurity/build code, users/SSH/sudo/firewall/services/systemd/kernel/storage/network/containers/secrets, and evaluation boundaries | Built-in |
| Jenkins | Jenkinsfile | `readtheplan jenkins Jenkinsfile` | Declarative/scripted step scanner covering agents/images/host arguments, libraries, credentials, commands/dynamic Groovy, triggers, approvals, checkout/HTTP/artifacts, and cleanup | Conservative |
| Jenkins Configuration as Code | JCasC YAML | `readtheplan jenkins-jcasc jenkins.yaml` | Security realms, authorization, credentials, controller executors, nodes/clouds, agent images/privilege, trusted/untrusted libraries, immutable/default/override policy, implicit loading, changelog/cache/SCM/fork trust, script approval, Job DSL, endpoints/TLS, and plugin boundaries | Built-in |
| Jenkins project / Shared Library | Plugin Installation Manager catalogs, Jenkins Job Builder YAML/JSON, or Shared Library `vars/*.groovy` / `src/**/*.groovy` | `readtheplan jenkins-project vars/deploy.groovy` | Strict duplicate-safe plugin/JJB inputs plus non-executing Shared Library source analysis for controller APIs, dependency loading, commands, credentials, mutable globals, CPS/serialization, resources, filesystem/network access, literal-secret redaction, and explicit trust/runtime boundaries | Built-in |
| Chef cookbook content | Recipe, attribute, custom-resource, library, provider, or definition Ruby; cookbook ERB template | `readtheplan chef cookbooks/base/resources/application.rb` | Bounded non-executing inspection covering resources/actions, attribute precedence, sensitive properties/interpolation, commands, direct filesystem/network access, Chef extensions, external data/code, guards, notifications, permissions, includes, and explicit call-site/render/runtime boundaries | Conservative |
| Chef project / dependencies / runtime | `Policyfile.rb`, `Policyfile.lock.json`, `Berksfile`, modern/legacy `Berksfile.lock`, `metadata.rb`, runtime configs, supported `.d` fragments, Test Kitchen YAML, or Chef Habitat `plan.sh`, `plan.ps1`, and lifecycle hooks | `readtheplan chef-project habitat/plan.sh` | Policy/run lists, cookbook and package provenance, Berkshelf migration/source ordering/groups/solver, direct and transitive lock graph integrity, Test Kitchen drivers/provisioners/transports/verifiers, Habitat identity/source/checksum/dependencies/service/binds/exports/exposure/callbacks/hooks, privilege/host access, credentials, mutable toolchains, client identity/convergence, Workstation bootstrap/SSH, Solo remote content, Server TLS/LDAP/database controls, duplicate overrides, and dynamic Ruby/ERB/shell/template/external-state boundaries | Built-in |
| Chef InSpec | `inspec.yml`, `inspec.lock`, `controls/*.rb`, `libraries/*.rb`, or waiver YAML/JSON/CSV | `readtheplan inspec controls/main.rb` | Duplicate-safe metadata/lock/waiver parsing plus non-executing Ruby inspection for platform scope, profile and gem provenance, integrity, inputs, control impact/inheritance/skips, command/remote resources, custom code, waiver justification/run/expiry, secrets, and effective runtime boundaries | Built-in |
| Puppet | Manifest source | `readtheplan puppet site.pp` | Built-in and namespaced resource/state scanner covering execution/identity/connectivity, classes, dynamic data/templates, custom types, virtual/exported resources, collectors, refresh relationships, sources, and permissions | Conservative |
| Puppet project / Server policy / runtime / deployment / Bolt | `Puppetfile`, module metadata, Hiera, `puppet.conf`, `environment.conf`, `puppetdb.conf`, Puppet Server `auth.conf`/`ca.conf`/`webserver.conf`/`puppetserver.conf`/`web-routes.conf`, r10k, Bolt project/inventory, `plans/*.yaml`, or `tasks/*.json` | `readtheplan puppet-project modules/site/plans/deploy.yaml` | Forge/Git dependencies, environment code/cache/commands, PuppetDB transport/fail-open/quorum, strict HOCON authorization and API scope, mTLS/TLS, CA signing, JRuby paths/environment/lifecycle, routes, r10k deployment, and Bolt commands/tasks/scripts/nested plans/transfers/resources, privilege, failure continuation, dynamic expressions, sensitive inputs, no-op/remote contracts, implementation selection, bundled files, and runtime trust boundaries | Built-in |
| GitHub Actions | Workflow YAML | `readtheplan github-actions workflow.yml` | Token permissions, action/reusable-workflow pinning, secret inputs, environments, and run steps | Built-in |
| GitLab CI | `.gitlab-ci.yml` | `readtheplan gitlab-ci .gitlab-ci.yml` | Remote/project includes, scripts, tokens, downstream triggers, and deployment environments | Built-in |
| CircleCI | `.circleci/config.yml` | `readtheplan circleci .circleci/config.yml` | Orbs, machine executors, SSH keys, remote Docker, reusable steps, and run commands | Built-in |
| Azure Pipelines | `azure-pipelines.yml` | `readtheplan azure-pipelines azure-pipelines.yml` | Repository/container resources, templates, variable groups, inline secrets, pools, deployment environments, service connections, tasks, scripts, and protected-resource boundaries | Built-in |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` | `readtheplan bitbucket-pipelines bitbucket-pipelines.yml` | Images, self-hosted runners, OIDC, deployments, services, Docker daemon access, caches, scripts, pipes, artifacts, custom variables, imports, and external settings | Built-in |
| Docker Compose | Compose YAML | `readtheplan docker-compose compose.yml` | Images, builds, commands, privileges, host namespaces, capabilities, mounts, devices, secrets, external files, and published ports | Built-in |
| Docker Buildx Bake | `docker-bake.hcl`, `docker-bake.json`, or Compose YAML build definitions | `readtheplan docker-bake docker-bake.hcl` | Static build graph, target/group references, inheritance/matrices, local/remote contexts, Dockerfile paths/inline source, entitlements/networking, build args, secrets/SSH, cache import/export, outputs/registry publication, source policy, attestations, and non-execution boundaries | Built-in |
| Dockerfile / Containerfile | Dockerfile source | `readtheplan dockerfile Dockerfile` | Frontends, base-image pinning, stages, commands/heredocs, BuildKit mounts, secret ARG/ENV, COPY/ADD, users, health, deferred instructions, and context boundaries | Built-in |
| HashiCorp Nomad | HCL/JSON jobspec or `/v1/job/:id/plan` JSON response | `readtheplan nomad job.nomad.hcl` | Source task drivers, commands/images, artifacts/templates, identity, Vault/Consul, services/networking, storage/secrets, plus scheduler placement/replacement/stops and failures | Built-in |
| HashiCorp Packer | Native HCL2/JSON or human/`-machine-readable` inspect output | `readtheplan packer image.pkr.hcl` | Plugin/core constraints, variables/locals/data, builders/communicators/base inputs, provisioners, post-processors/publishing, secrets, functions, and inspect/source boundaries | Built-in |
| Skaffold | Multi-document Skaffold Config YAML | `readtheplan skaffold skaffold.yaml` | Imported configs, builders/artifacts/hooks, renderers, deployers/flags, verification, custom actions, profiles/patches, port forwarding, secrets, and non-execution boundaries | Built-in |
| DevSpace | `devspace.yaml` v1/v2 configuration | `readtheplan devspace devspace.yaml` | Imports/dependencies, pipelines/functions/commands, builders, Helm/Kubernetes deploys, development mutation/sync/ports/SSH, hooks, profiles, registries, credentials, plugins, and non-execution boundaries | Built-in |
| Tilt | Tiltfile Starlark source | `readtheplan tilt Tiltfile` | AST-backed host command, extension, image build, Compose/Kubernetes deploy, Helm/Kustomize, custom deploy, live-update, file/environment, port, secret, and dynamic-source analysis | Conservative |
| CUE | `.cue`, `*_tool.cue`, `cue.mod/module.cue`, or `local-module.cue` source | `readtheplan cue deploy_tool.cue` | OCI module imports/dependencies/replacements, workflow capabilities and process/file/HTTP/OS/interactive tasks, secrets, embedding, injection, generation, and non-evaluation boundaries | Conservative |
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

- readtheplan does not execute Jenkins, Chef, Puppet, Ansible, Salt, Pulumi, Helm, Kustomize,
  Crossplane packages, providers, or Composition functions,
  Serverless Framework plugins or AWS SAM builds/transforms,
  Pulumi, GitHub Actions, GitLab CI, CircleCI, Azure Pipelines, Bitbucket Pipelines,
  Docker Compose, Docker Buildx Bake, Dockerfiles, Nomad, Packer,
  Vagrant, cloud-init user-data, or provider code.
- Ansible configuration/variable precedence, combined inventory sources, inventory-plugin code
  and live API responses, built collection artifacts and signatures, transitive Galaxy/role
  dependencies, installed plugin/import loader precedence, role-local module/plugin code, caller
  host/variable/tag/privilege context, imported/included file expansion, handler name collisions and
  insertion/notification routing, effective lint CLI
  options/custom Python rules/ignore files, Controller/AWX import permissions and natural-key
  resolution, existing state, encrypted values, project/inventory sync results and omitted-resource
  pruning, Event-Driven Ansible Decision Environment contents, source/filter plugin code, runtime
  variables/Vault inputs, event systems, network controls, activation scaling/restarts, referenced
  automation content and live Controller launches, Molecule base-config merges, environment interpolation,
  installed drivers/plugins, playbooks, verifier code, generated inventory, provider state, and CLI
  destroy policy, and Jenkins shared
  libraries remain external code boundaries. Chef policy-group/node assignment, Berkshelf source
  indexes/cache and manifest-to-lock freshness, credentials, config.rb, Test Kitchen project/local/
  global YAML merge precedence, `KITCHEN_*` path overrides, ERB/environment values, installed Ruby
  plugins, driver state, and live cloud/hypervisor/container/SSH/WinRM systems,
  Chef Habitat plan/hook execution, HART builds, hook/template and `default.toml` rendering,
  Builder/Supervisor access, environment and target resolution, origin keys/signatures, transitive
  packages/install hooks, scaffolding, Supervisor flags, and live service behavior,
  InSpec ERB rendering, profile dependency downloads, gem/plugin loading, input precedence,
  resource/matcher implementations, transport credentials, target state, waiver-file selection,
  and control results, Chef cookbook dynamic dispatch and metaprogramming, effective attribute
  resolution, resource call sites, ERB helper/partial loading and rendered target context, generated
  files and external state, server-side state, Puppet module contents and transitive dependencies,
  Hiera data, eyaml keys, autosign policy/config contents, merged Puppet Server HOCON includes and
  substitutions, live certificates/CRLs, reverse-proxy trust, Ruby extensions,
  custom providers/types, Bolt configuration precedence, installed Bolt module/plugin code and
  task implementation contents, resolved dynamic inventory and external secrets, target state,
  task/command/script/nested-plan execution, file transfers, resource application, Puppet-expression
  evaluation, live results and plan cache, dynamic language expressions, Hiera/data bindings, and compiled catalogs are not
  evaluated; recognized boundaries are surfaced for review instead.
- Jenkins JCasC analysis parses one YAML file without resolving supplementary
  configuration files, secret-source/environment interpolation, installed-plugin
  schemas, init hooks, system properties, or live controller state.
- r10k and Code Manager deployment analysis does not fetch repositories, enumerate remote
  branches, read credential files, resolve Puppetfiles/modules, inspect managed directories,
  execute hooks, or contact Puppet servers.
- Jenkins Job Builder analysis does not load includes, render templates/Jinja, import component
  plugins, generate XML, or contact Jenkins. Effective defaults/macros, installed plugins,
  credentials, permissions, and controller state remain review boundaries.
- Jenkins Shared Library analysis does not execute Groovy, load `resources/`, resolve SCM, or
  contact Jenkins. Global/folder trust, source ownership and revision, implicit loading, version
  overrides, sandbox approvals, replay, CPS transformation, plugins, credentials, and runtime
  values remain review boundaries.
- Jenkins JCasC library analysis distinguishes trusted and untrusted global roots but does not
  resolve folder libraries or version overrides, fetch SCM revisions, inspect repository write
  permissions, read controller caches, or evaluate plugin-specific retriever and trait behavior.
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
- Cloudflare rules inspect provider plan values without contacting the account or
  resolving dashboard/runtime state. Referenced rulesets/lists, Worker source
  artifacts, secret values, identity-provider groups, tunnel connectors, origin
  health, registrar DS records, and Logpush destinations remain external trust
  boundaries to verify before apply.
- Serverless Framework and AWS SAM analysis parses source without resolving
  variables, loading external files, downloading code/application artifacts,
  executing plugins or custom builders, or applying CloudFormation macros. Run
  the corresponding synthesized CloudFormation change set through the existing
  CloudFormation gate for operation-level confirmation before deployment.
- Bicep source analysis never invokes the compiler, restores registry modules,
  reads referenced files, or contacts Azure. Run `bicep lint`/`bicep build`, then
  submit Azure What-If `FullResourcePayloads` JSON to the `azure` gate for the
  authoritative operation-level create/modify/delete prediction.
- AWS CDK analysis never executes the application or reads referenced companion
  artifacts. Run the `cdk` gate on both the Cloud Assembly and each asset manifest,
  inspect referenced templates/assets, then use `cdk diff` or a CloudFormation
  Change Set for the live target-account operation delta. Terragrunt source flows
  through its native gate and Terraform/OpenTofu plan JSON remains authoritative.
- Argo CD/Workflows/Events, Flux, Tekton, Gateway API, cert-manager/trust-manager,
  External Secrets, Istio, Kyverno, Gatekeeper, KEDA, and Knative receive
  first-party controller semantics. Other custom resources remain conservative
  because their reconciliation effects depend on code and runtime configuration
  outside the submitted manifest.
- Controller-aware Kubernetes rules remain static: referenced templates, Secrets,
  Services, stores, trust roots, backends, controller configuration, admission,
  runtime status, and external systems must be verified in the target environment.
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
- Nomad analysis accepts HCL/JSON jobspec source or the structured plan response returned by
  the HTTP API. Generate plans inside the existing Nomad trust boundary; readtheplan never contacts
  the cluster or submits a job.
- Packer analysis accepts native HCL2/JSON templates or `packer inspect` output and
  never initializes plugins or starts a build. Source mode inspects plugin-specific
  configuration without evaluating expressions; inspect output intentionally omits
  that configuration and therefore retains a limitation finding. Run
  `packer validate` only inside the caller's trust boundary.
- Salt analysis parses static SLS YAML with duplicate-key rejection. Jinja-templated
  SLS files receive conservative line-based state discovery plus an unresolved
  renderer finding; calls such as `salt['cmd.run'](...)` during rendering block.
- Salt project analysis strictly parses rendered master/minion configuration,
  top files, and Salt SSH rosters without loading modules or contacting a master.
  Included config, accepted keys, custom modules/renderers, Pillar/grains,
  fileserver precedence, roster plugins, and rendered highstate remain an
  explicit review boundary.
- Nix analysis strictly parses `flake.lock` JSON and scans Nix expressions
  without evaluating them. Lazy functions, overlays, imports, option merging,
  platform/daemon state, package definitions, and command-line overrides remain
  an explicit review boundary; callers should run `nix flake check`/`eval` or
  `nixos-rebuild build` inside their existing Nix trust boundary.
- Vagrant analysis scans the documented Ruby DSL without executing it. Arbitrary
  Ruby, plugins, box Vagrantfiles, provider configuration, and configuration from
  the Vagrant home directory remain an explicit review boundary.
- cloud-init analysis requires a documented user-data header, rejects duplicate
  cloud-config keys, and never executes guest code. MIME parts remain a review
  boundary until decoded, and callers should additionally run `cloud-init schema`
  inside their existing validation environment.
