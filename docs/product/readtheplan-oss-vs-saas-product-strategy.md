# readtheplan OSS vs SaaS Product Strategy

## Product thesis
readtheplan should operate as two complementary products:
- **OSS local-first analyzer** for trust and adoption.
- **Managed SaaS platform** for team workflows, reporting, and paid support.

## OSS scope
- Open-source CLI, GitHub Action, and MCP toolchain.
- Local plan analysis with no forced raw-plan upload.
- Transparent rules engine + compliance mappings + evidence artifacts.
- Mandatory Sigstore keyless signing with identity verification.

## SaaS scope
- Authentication, organizations, teams, project workspaces.
- Policy configuration and governance workflow.
- Evidence history + reporting + support operations.
- Subscription billing and managed service tiers.

## Data boundary
### Stays local by default
- Raw Terraform/OpenTofu plan JSON.
- Full infra-topology details from plans.

### Stored in platform (v1)
- Org/project metadata.
- Policy profiles and exceptions.
- Signed local analysis summaries/evidence envelopes.
- Audit metadata for workflow traceability.

## Pricing tiers (concrete, 2026-06-04)

| Tier | Price | Target | Key Features |
|------|-------|--------|-------------|
| **Free OSS** | $0 / forever | Individual developers | Local CLI, public frameworks, client-side playground, zero plan uploads |
| **Paid Managed** | $49 / org / month | Growth & security teams | Custom policy profiles, signed evidence timeline, policy-tuned playground, compliance reports (PDF/JSON), Slack/GitHub integrations, standard SLA |
| **Enterprise** | Custom / contract | Regulated organizations | Private connector (VPC/agent), SAML/SSO, unlimited audit trails, continuous drift checks, premium 1hr SLA |

### Feature gating
- `require_org_tier(BillingTier.PAID_MANAGED)` middleware gates stateful endpoints.
- Free tier: no cloud storage, no attestation tracking, no reports.
- Stripe integration: Checkout + Customer Portal + Webhook sync.
- Full design: `docs/product/paid-tier-feature-gating-design.md`

## v1 architecture
- Frontend app for org/policy/reporting UX.
- API for authz/policy/evidence/audit operations.
- SQLite (transitional) or Postgres-backed metadata store.
- Evidence ingestion from signed local outputs (not raw plans by default).
- Stripe billing with tier-based feature gating.

## v2 hosted analyzer gates
Do not enable hosted raw-plan analysis until:
1. Threat model approved.
2. Retention + deletion controls verified.
3. Redaction pipeline validated.
4. Encryption + key management finalized.
5. Tenant isolation + audit logging verified.

## Evidence artifact lifecycle
1. **Generate:** `readtheplan analyze --evidence out.json --sign` produces signed `rtp-evidence-v1` envelope.
2. **Verify:** `readtheplan verify --certificate-identity <id> --certificate-oidc-issuer <issuer> evidence.json` (identity required).
3. **Ingest:** Signed envelope uploaded via REST API (future).
4. **Retain:** Paid Managed: 30 days. Enterprise: custom/unlimited.
5. **Report:** Compliance reports from stored evidence — audit-ready export.

## 30/60/90
### 30
- Finalize product boundary and scope.
- Ship auth/org/project + policy profile scaffold.

### 60
- Ship signed-evidence ingestion and reporting timeline.
- Run design-partner pilot for managed onboarding workflow.

### 90
- Launch paid managed tier with support SLA.
- Add billing and role/audit controls.
- Reassess private connector priority from pilot feedback.

## Open questions
- Minimum v1 feature set needed for paid conversion?
- Which compliance output formats matter first?
- SLA boundaries for monthly maintenance packaging?
- Trigger criteria for private connector / hosted analyzer expansion?
