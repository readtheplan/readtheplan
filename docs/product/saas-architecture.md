# readtheplan SaaS Architecture

## Overview

readtheplan operates as two complementary products sharing a common rules engine and compliance catalog:

- **OSS side:** Python CLI (`pip install readtheplan`), GitHub Action, local MCP tool — all local-first, no raw plan upload.
- **SaaS side:** Multi-tenant web platform for team workflows, policy governance, and reporting.

## Stack (current production state)

| Layer | Technology | Notes |
|-------|-----------|-------|
| Frontend | Static HTML/CSS/JS | Cloudflare Pages (`readtheplan.pages.dev`) |
| API (stubs) | Pages Functions | `/api/v1/*` — static JSON, 6 frameworks, 308 controls |
| Reverse proxy | Nginx thin proxy | Droplet → `readtheplan.pages.dev` |
| Database | None currently | SaaS backend decommissioned 2026-05-29 |

When the SaaS backend is re-enabled, the stack will be:

| Layer | Technology |
|-------|-----------|
| API | FastAPI (Python 3.13) |
| Frontend | Next.js 16 (React) |
| Auth | JWT (python-jose + passlib[bcrypt]) |
| Billing | Stripe (Checkout, Customer Portal, Webhooks) |
| Hosting | DigitalOcean droplet |

## Cloud-only architecture (2026-06-04)

```
Internet
  │
  ├── :443 (Nginx thin proxy on droplet)
  │     ├── /api/* → Cloudflare Pages Functions (static data API)
  │     └── /*     → Cloudflare Pages static frontend
  │
  └── No active readtheplan backend/database service
```

## Authentication flow (when SaaS backend re-enabled)

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
  │           ├── billing_tier: free | paid_managed | enterprise
  │           ├── stripe_customer_id
  │           ├── stripe_subscription_id
  │           ├── subscription_status: active | past_due | canceled | trialing
  │           ├── subscription_period_end
  │           │
  │           ├── Project (id, org_id, name, slug, description)
  │           │
  │           ├── PolicyOverride (id, org_id, name, risk_threshold, framework, overrides)
  │           │
  │           └── EvidenceArtifact (id, org_id, project_id, framework, plan_hash, ...)
  │
  └── RevokedToken (jti, user_id, token_type, expires_at)
```

## Billing & subscription

- **Stripe** integration for checkout, customer portal, and webhook sync.
- **Tiers:** Free (no cloud storage), Paid Managed ($49/org/month), Enterprise (custom).
- **Feature gating** via `require_org_tier(BillingTier.PAID_MANAGED)` dependency.
- **Webhooks** keep Stripe subscription status in sync with local DB.
- Full design: `docs/product/paid-tier-feature-gating-design.md`

## Evidence artifact lifecycle

1. **Generation:** CLI runs `readtheplan analyze --evidence out.json --sign` to produce a signed `rtp-evidence-v1` envelope locally.
2. **Verification:** `readtheplan verify --certificate-identity <id> --certificate-oidc-issuer <issuer> evidence.json` validates Sigstore keyless signature with mandatory identity enforcement.
3. **Ingestion (v2):** Signed envelopes uploaded to SaaS platform via REST API. Raw Terraform plans never touch the server.
4. **Retention:** Paid Managed: 30-day evidence retention. Enterprise: custom/unlimited per contract.
5. **Reporting:** Compliance reports generated from stored evidence envelopes — audit-ready PDF/JSON export.

## Security boundaries

| Boundary | Implementation |
|----------|---------------|
| Site hosting | Cloudflare Pages (auto-deploys on push to main) |
| API surface | Pages Functions — static JSON, no server-side compute |
| TLS termination | Cloudflare (full SSL, orange cloud proxy) + droplet nginx |
| CSP | `default-src 'self'; script-src 'self' https://plausible.io https://cdnjs.cloudflare.com` |
| Identity verification | Sigstore keyless signing with mandatory `--certificate-identity` and `--certificate-oidc-issuer` |
| Password hashing | bcrypt with explicit 12 rounds |
| Token revocation | JTI-based blacklist |
| Cookie hardening | HttpOnly, Secure, SameSite=Strict |
| CORS | Explicit origins, no `*`+credentials |
| Dependency audit | pip-audit + Semgrep in CI |
| Secret scanning | Gitleaks in CI |
| Rate limiting | 20 req/min per IP on chat endpoint |
| Body size limit | 64 KB on API endpoints |

## Current state (2026-06-04)

- ✅ Frontend live on Cloudflare Pages
- ✅ Nginx thin-proxy serves `readtheplan.dev`
- ✅ `/api/v1/health` returns 200
- ✅ `/api/v1/controls` serves 6 frameworks, 308 control mappings
- ✅ `/api/v1/demo` serves Floci Moto-spike plans
- ✅ `/api/v1/version` returns version and stats
- ✅ `/chat` AI sales agent (DeepSeek backend)
- ✅ Playground with in-browser classifier
- ✅ Evidence signing and verification with mandatory identity
- ✅ CSP headers via `_headers` file
- ℹ️ No SaaS backend (API/database decommissioned 2026-05-29)
- ℹ️ Billing and subscription infrastructure designed, pending backend re-enable
