# readtheplan SaaS Architecture

## Overview

readtheplan operates as two complementary products sharing a common rules engine and compliance catalog:

- **OSS side:** Python CLI (`pip install readtheplan`), GitHub Action, local MCP tool — all local-first, no raw plan upload.
- **SaaS side:** Multi-tenant web platform for team workflows, policy governance, and reporting.

## Stack

| Layer | Technology | Repo |
|-------|-----------|------|
| API | FastAPI (Python 3.12) | `readtheplan/readtheplan-cloud-api` |
| Frontend | Next.js 16 (React) | `readtheplan/readtheplan-cloud-web` |
| Database | PostgreSQL 16 | Managed on droplet |
| Auth | JWT (python-jose + passlib[bcrypt]) | cloud-api |
| Migrations | Alembic | cloud-api |
| Reverse proxy | Nginx + Let's Encrypt | Droplet |
| Hosting | DigitalOcean droplet | `hermes-cloud` |

## Authentication flow

```
Browser (Next.js)                          FastAPI cloud-api
     │                                           │
     ├── POST /api/v1/auth/login ────────────────►
     │    {email, password}                       │
     │                                            ├── verify bcrypt hash
     │                                            ├── create access + refresh JWT
     │◄── 200 {access_token, refresh_token} ─────┤
     │    + Set-Cookie: access_token (HttpOnly)   │
     │    + Set-Cookie: refresh_token (path=/api) │
     │                                            │
     ├── GET /api/v1/auth/me ────────────────────►
     │    Cookie: access_token                    ├── decode JWT
     │                                            ├── check RevokedToken table
     │◄── 200 {id, email, full_name} ────────────┤
```

- Access tokens: 30 min, JWT with `jti` for revocation
- Refresh tokens: 7 days, single-use (rotation on refresh, reuse detection)
- Logout: revokes access token `jti`, clears cookies
- Cookies: HttpOnly, Secure, SameSite=Strict

## Data model

```
User (id, email, hashed_password, full_name, is_active)
  │
  ├── Membership (user_id, organization_id, role: owner|admin|member)
  │     │
  │     └── Organization (id, slug, name)
  │           │
  │           ├── Project (id, org_id, name, slug, description)
  │           │
  │           ├── PolicyOverride (id, org_id, name, risk_threshold, framework, overrides)
  │           │
  │           └── EvidenceArtifact (id, org_id, project_id, framework, plan_hash, ...)
  │
  └── RevokedToken (jti, user_id, token_type, expires_at)
```

## Deployment (hermes-cloud droplet)

```
Internet
  │
  ├── :443 (Nginx + Let's Encrypt)
  │     ├── /api/* → proxy_pass http://127.0.0.1:8080 (FastAPI)
  │     └── /*     → proxy_pass http://127.0.0.1:3000 (Next.js)
  │
  ├── FastAPI (:8080, bound to 127.0.0.1)
  │     └── PostgreSQL (:5432, local)
  │
  └── Next.js (:3000, bound to 127.0.0.1)
```

## Security boundaries

| Boundary | Implementation |
|----------|---------------|
| API port binding | 127.0.0.1 only (not 0.0.0.0) |
| Secrets | `.env` file, never committed |
| JWT validation | `change-me` secret rejected at startup |
| Password hashing | bcrypt with explicit 12 rounds |
| Token revocation | JTI-based blacklist in Postgres |
| Cookie hardening | HttpOnly, Secure, SameSite=Strict |
| CORS | Explicit origins, no `*`+credentials |
| CSP | `Content-Security-Policy` via Nginx |
| DB audit | `log_connections`, `log_disconnections`, `log_statement=mod` |
| Dependency audit | pip-audit + Semgrep in CI |
| Secret scanning | Gitleaks in CI |

## Current state (2026-05-16)

- ✅ API scaffolded (auth, orgs, projects, policies, evidence)
- ✅ Frontend scaffolded (Next.js 16, org dashboard, auth flow)
- ✅ Nginx with CSP + security headers configured
- ✅ JWT with bcrypt 12 rounds, aud claim, logout revocation
- ✅ Pydantic models for all create/update endpoints
- ✅ Sensitive-field redaction middleware
- ❌ No staging deploy (manual droplet deploy)
- ❌ No E2E integration tests
- ❌ No billing/subscription
