# Changelog

## [Unreleased]

### Changed
- Self-improving evolution analysis now stays local and deterministic;
  candidate generation never spawns external model tooling.

### Added
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
