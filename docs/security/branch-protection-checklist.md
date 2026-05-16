# Branch Protection Checklist

This checklist ensures branch protection rules are consistently applied across all readtheplan repos.

## Required checks (per repo)

### OSS repo (`readtheplan/readtheplan`)
- [x] `test-action` — GitHub Action integration test
- [x] `pytest (3.10)` — Core test suite on Python 3.10
- [x] `pytest (3.13)` — Core test suite on Python 3.13
- [x] `site` — Site build validation
- [x] `demo-report` — Terraform risk scenario tests
- [x] `hosted-security-gates` — Security boundary enforcement

### cloud-api (`readtheplan/readtheplan-cloud-api`)
- [x] `Build & Lint` — Ruff lint check
- [x] `Test (pytest + Postgres)` — Integration tests
- [x] `Semgrep SAST` — Static analysis
- [x] `Gitleaks Secret Scan` — Secret detection
- [x] `pip-audit Dependency Scan` — Vulnerability audit
- [ ] Fix Gitleaks license requirement for private org

### cloud-web (`readtheplan/readtheplan-cloud-web`)
- [ ] CI workflow (not yet configured)
- [ ] npm-audit security scan
- [ ] Build verification

## Ruleset configuration

### `main` branch rules (all repos)
- [x] Require pull request before merging
- [x] Require status checks to pass before merging
- [x] Require branch to be up to date before merging
- [x] Block force pushes
- [x] Block deletions

### Additional rules for private repos
- [x] Restrict push access to admin/owners
- [x] Require CODEOWNERS review for `docs/security/` and `.github/workflows/`

## Security scan workflows

### Per-repo requirements
| Repo | SAST | Secret Scan | Dependency Audit | License Scan |
|------|------|-------------|-----------------|-------------|
| readtheplan (OSS) | ✅ Semgrep | ✅ Gitleaks | ✅ pip-audit | — |
| cloud-api | ✅ Semgrep | ⚠️ Gitleaks (license) | ✅ pip-audit | — |
| cloud-web | ❌ Not configured | ❌ Not configured | ❌ Not configured | — |

## Annual review items
- [ ] Rotate deploy keys and API tokens
- [ ] Review CODEOWNERS and access lists
- [ ] Audit branch protection rules against current team size
- [ ] Update security scan tool versions (Semgrep, Gitleaks, pip-audit)
- [ ] Verify CI secrets are rotated and scoped correctly

## Current gaps (2026-05-16)
1. **Gitleaks license** — Private org requires paid license; configure `GITLEAKS_LICENSE` secret or switch to TruffleHog
2. **cloud-web CI** — No CI workflow configured yet
3. **Staging deploy** — No automated staging environment
4. **DB backup** — No automated backup for production Postgres
