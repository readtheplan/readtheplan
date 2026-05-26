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
| Database | N/A (API currently offline) | When SaaS backend is re-enabled, database choice is TBD |
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

## Deployment (current production state)

```
Internet
  │
  ├── :443 (Nginx thin proxy)
  │     ├── /api/* → Cloudflare Pages Functions stubs (503 while backend is offline)
  │     └── /*     → Cloudflare Pages static frontend
  │
  └── No active readtheplan API/database service on this host
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

## Current state (2026-05-26)

- ✅ Frontend is live on Cloudflare Pages
- ✅ Nginx thin-proxy serves `readtheplan.dev`
- ✅ `/health` endpoint is live
- ℹ️ `/api/*` currently returns 503 stub responses while SaaS backend is offline
- ❌ No active readtheplan cloud-api service
- ❌ No active readtheplan production database service
