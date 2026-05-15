# readtheplan OSS vs SaaS Product Strategy

## Product thesis
readtheplan should operate as two complementary products:
- **OSS local-first analyzer** for trust and adoption.
- **Managed SaaS platform** for team workflows, reporting, and paid support.

## OSS scope
- Open-source CLI, GitHub Action, and MCP toolchain.
- Local plan analysis with no forced raw-plan upload.
- Transparent rules engine + compliance mappings + evidence artifacts.

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

## Pricing hypothesis
- **Free OSS:** self-serve local toolchain.
- **Paid Managed:** monthly maintenance for onboarding, policy tuning, evidence/report workflows, and support SLA.
- **Enterprise:** private connector / stricter controls / contract support.

## v1 architecture
- Frontend app for org/policy/reporting UX.
- API for authz/policy/evidence/audit operations.
- Postgres-backed metadata store.
- Evidence ingestion from signed local outputs (not raw plans by default).

## v2 hosted analyzer gates
Do not enable hosted raw-plan analysis until:
1. Threat model approved.
2. Retention + deletion controls verified.
3. Redaction pipeline validated.
4. Encryption + key management finalized.
5. Tenant isolation + audit logging verified.

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
