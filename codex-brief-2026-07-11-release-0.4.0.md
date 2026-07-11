# Codex brief — 2026-07-11 — Release 0.4.0

## Context

All six findings from the 2026-07-10 review are closed on `main@cebeec9`
(PRs #144, #145, #146). The security fixes should ship promptly. The
`[Unreleased]` CHANGELOG section already contains breaking changes and the
K8s adapter / self-improving gate never got entries, so per RELEASING.md
semver rules this is a **minor** release: `0.3.0 → 0.4.0`.

## Instructions

Branch from `origin/main` as `release/0.4.0`. Follow RELEASING.md.

### 1. Version bump

- `pyproject.toml`: `version = "0.4.0"`
- `src/readtheplan/__init__.py`: `__version__ = "0.4.0"`

### 2. CHANGELOG.md

Rename `## [Unreleased]` to `## [0.4.0] — 2026-07-11`, keep every existing
item, and merge in the entries below (append to the existing `Added`,
`Fixed`, `Changed` subsections; add the new `Security` subsection after
`Added`). Add a fresh empty `## [Unreleased]` above it.

```markdown
### Added
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
- Self-improving mode is install-safe: candidate verification runs
  in-process (pytest is no longer needed at runtime), and evolution
  diagnostics go to stderr so JSON stdout stays machine-parseable
  (finding 4).
- Importing the CLI no longer creates `~/.readtheplan` as a side effect,
  and `analyze --mode self-improving` now actually records the run
  (finding 5).

### Changed
- Plan identity hash is now a content-based canonical digest
  (`rtp-plan-hash-v2`, ADR 0014): full SHA-256 over sorted resource changes,
  independent of file path and rule-derived fields. Legacy 16-character
  hashes in existing evolution databases remain untouched.
```

### 3. Gates (all must pass)

- `ruff check .`
- `pytest` — full suite, coverage ≥ 78, Python 3.10 and 3.13
- Wheel build + `twine check`
- Site parity checks
- Sanity: `readtheplan --version` (or equivalent) reports 0.4.0 from an
  installed wheel

### 4. PR

- Title: `chore: release 0.4.0`
- Note AI assistance in the PR body. No `AI-Assisted:` commit trailers.
- Do NOT tag. Tagging happens after the release PR is squash-merged, so the
  tag lands on the merge commit on `main` (the maintainer pushes the tag;
  `v0.4.0` tag push triggers `.github/workflows/publish.yml` → PyPI trusted
  publishing + GitHub Release).

### 5. Post-merge verification (after the maintainer tags)

- Watch the `publish.yml` run to completion.
- `pip install readtheplan==0.4.0` in a fresh venv; confirm version and run
  `readtheplan agent-gate --mode self-improving <sample plan>` returns valid
  JSON.
- Confirm the GitHub Release exists with the changelog notes.
