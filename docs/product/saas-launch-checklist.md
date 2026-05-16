# SaaS Launch Checklist

## Pre-launch (must complete)

### Security
- [x] JWT bcrypt 12 rounds, aud claim, logout revocation
- [x] Pydantic models (no `body: dict` mass assignment)
- [x] CORS: explicit origins, no `*`+credentials
- [x] CSP + security headers in nginx
- [x] Postgres audit logging (connections, statements)
- [x] Sensitive-field redaction middleware
- [x] pip-audit + Semgrep + Gitleaks in CI
- [ ] E2E auth test suite (register → login → refresh → logout → revoked)
- [ ] Rate limiting on auth endpoints
- [ ] CSRF protection for cookie-based auth

### Infrastructure
- [x] Droplet provisioned (hermes-cloud)
- [x] Nginx with Let's Encrypt SSL
- [x] PostgreSQL 16 on droplet
- [x] Alembic migrations pipeline
- [ ] Staging environment (separate droplet or container)
- [ ] Automated deploy from CI (currently manual)
- [ ] Database backup automation
- [ ] Monitoring + alerting (UptimeRobot or similar)

### Product
- [x] OSS vs SaaS product strategy documented
- [x] SaaS architecture documented
- [x] Data boundary defined (local raw plans, platform metadata only)
- [ ] Pricing page live
- [ ] Terms of Service + Privacy Policy
- [ ] Onboarding flow (org creation → first project → connect CLI)

### CI/CD
- [x] pytest (3.10 + 3.13) — OSS repo
- [x] site build + deploy — OSS repo
- [x] demo-report — OSS repo
- [x] hosted-security-gates — OSS repo
- [x] CI/CD + Security Scan — cloud-api repo
- [ ] CI parity: cloud-api tests run in GitHub Actions
- [ ] CI parity: cloud-web builds run in GitHub Actions

## Launch blockers
1. **Rate limiting** — auth endpoints need rate limiting before public exposure
2. **Staging env** — need isolated staging before production traffic
3. **DB backups** — no automated backup pipeline

## Post-launch (30 days)
- [ ] Design partner onboarding (1-3 teams)
- [ ] Usage dashboards (org-level analytics)
- [ ] Evidence timeline in cloud-web
- [ ] Email notifications (Signup, report ready, policy change)

## Post-launch (60 days)
- [ ] Billing integration (Stripe)
- [ ] Paid tier with support SLA
- [ ] Role-based access control (owner/admin/member enforcement)
- [ ] Audit log viewer in cloud-web

## Post-launch (90 days)
- [ ] Private connector (on-prem agent)
- [ ] Hosted analyzer (raw plan analysis — gated behind threat model gates)
- [ ] Enterprise SSO (SAML/OIDC)
