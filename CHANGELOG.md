# Changelog

## [Unreleased]

### Added
- Repository issue templates, pull request template, CODEOWNERS, Dependabot config, and PyPI trusted-publisher workflow scaffolding.
- GitHub Action parser tests and oversized `summary-json` output guardrail.

### Changed
- Sigstore is now a true optional `sign` extra with a clear install hint when signing is requested without it.
- GitHub Action threshold behavior now checks risks at or above the configured threshold.
- Site and docs copy now label static demos as example output and document the agent-gate JSON contract more explicitly.

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
