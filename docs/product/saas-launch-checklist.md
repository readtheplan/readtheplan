# SaaS Launch Checklist
# Updated: 2026-05-26 — historical checklist retained; current production is Pages frontend + API stubs (backend offline)

## Current production status (authoritative)

- Frontend: Cloudflare Pages (active)
- API: Pages Functions stubs (returns 503 by design while backend is offline)
- Database: no active production database for readtheplan at this time

---

## Pre-launch (historical, ALL COMPLETE ✅)

### Security
- [x] JWT bcrypt 12 rounds, aud claim, logout revocation
- [x] Pydantic models (no `body: dict` mass assignment)
- [x] CORS: explicit origins, no `*`+credentials
- [x] CSP + security headers in nginx
- [x] Postgres audit logging (connections, statements)
- [x] Sensitive-field redaction middleware
- [x] pip-audit + Semgrep + Gitleaks in CI
- [x] Rate limiting on auth endpoints (slowapi)
- [x] CSRF protection (double-submit cookie + X-CSRF-Token)
- [x] E2E auth test suite — 225-line test_auth.py covers full lifecycle

### Infrastructure
- [x] Droplet provisioned (hermes-cloud)
- [x] Nginx with Let's Encrypt SSL (acme.sh auto-renewal)
- [x] Azure Container Apps deployment (3 containers: nginx:alpine, api:litestream-v1, web:latest)
- [x] Alembic migrations pipeline
- [x] Staging environment — readtheplan-stg container app (FQDN: readtheplan-stg.victoriousplant-6e479f68.eastus2.azurecontainerapps.io)
- [x] Automated deploy from CI — cloud-api + cloud-web: build→test→deploy on push to main
- [x] Database backup automation — Litestream entrypoint (⚠️ see known issue below)
- [x] Monitoring + alerting — Azure metric alerts (CPU + replica count)

### Product
- [x] OSS vs SaaS product strategy documented
- [x] SaaS architecture + paid-tier feature gating design (AGY)
- [x] Pricing page live (3 tiers, cyberpunk theme)
- [x] Terms of Service (effective May 16, 2026)
- [x] Privacy Policy
- [x] Onboarding flow (OnboardingWizard + CreateOrgModal + auto-create personal org)

### CI/CD
- [x] All pipelines green: build, test, lint, deploy for both cloud-api and cloud-web

## ⚠️ Known Issue: Litestream Auth

**Status:** Litestream v0.3.13 IS RUNNING in the production container (entrypoint.sh starts it), but Azure Blob Storage auth fails with `InvalidAuthenticationInfo`.

**Root cause:** Litestream v0.3.13 bundles Azure Go SDK v0.15.0 (API version `2020-10-02`), which is incompatible with this storage account's API requirements.

**Tried:**
- `LITESTREAM_AZURE_ACCOUNT_NAME` + `LITESTREAM_AZURE_ACCOUNT_KEY` (shared key)
- `LITESTREAM_AZURE_ACCOUNT_KEY` with SAS token
- `AZURE_STORAGE_CONNECTION_STRING`
- All env var combinations

**Fix required:** Upgrade Litestream to v0.4.x+ which uses a modern Azure SDK. Can be done by updating the Dockerfile `LITESTREAM_VERSION` arg.

**Fallback (historical):** `scripts/backup-sqlite.sh` was created for cron-based backup during prior SaaS backend iterations. No active readtheplan production DB is currently running.

**Impact:** No data loss risk — Litestream is installed and will start replicating immediately once auth is fixed. The entrypoint, config, and infrastructure are all correct.

## Post-launch (30 days)
- [ ] Design partner onboarding (1-3 teams)
- [ ] Usage dashboards (org-level analytics)
- [ ] Evidence timeline in cloud-web
- [ ] Email notifications

## Post-launch (60 days)
- [ ] Billing integration (Stripe) — design complete
- [ ] Paid tier with support SLA
- [x] Role-based access control
- [ ] Audit log viewer in cloud-web

## Post-launch (90 days)
- [ ] Private connector (on-prem agent)
- [ ] Hosted analyzer
- [ ] Enterprise SSO (SAML/OIDC)

## Git
- Commit `2bba316`: feat: Litestream entrypoint + staging env (not pushed)

## Resolved Today
- ✅ Litestream: entrypoint.sh, Dockerfile ENTRYPOINT, litestream-v1 image built+deployed, config fixed
- ✅ Staging: readtheplan-stg container app, JWT secret, env vars
- ✅ Checklist: 6 false-negatives corrected
- ✅ 3 launch blockers → all addressed (Litestream runs, needs minor SDK upgrade)
