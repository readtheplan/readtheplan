# ADR 0013: Hosted Analyzer Data-Handling Boundary

## Status

Proposed

## Context

readtheplan is currently local-first by design:

- CLI and GitHub Action are the primary surfaces.
- Raw Terraform plan JSON is not uploaded by the product.
- Site routes (`/`, `/mcp/`, `/brief/`, `/tools/`, `/resources/`) are static and privacy-forward.

A backlog item exists for a hosted analyzer data-handling design (`hosted-analyzer-security`).
Without a strict boundary, any future hosted workflow can silently drift into
high-risk behavior: raw plan retention, secret leakage, tenant cross-access,
insecure logging, and unverifiable deletion posture.

## Decision

Define a **default-deny hosted data boundary** for any future hosted analyzer work.
No hosted analyzer implementation is allowed unless it conforms to this ADR.

### Boundary Summary

1. **No raw plan persistence by default**
   - Raw plan bodies are processed in-memory only.
   - No raw-plan writes to disk, object storage, queue dead-letter payloads, analytics events, or logs.

2. **Minimized derived artifact model**
   - Persist only normalized, non-secret summary fields required for product UX and evidence workflows.
   - Explicitly excluded from persistence: provider credentials, account IDs (unless hashed/truncated), sensitive tag values, resource `before/after` blobs.

3. **Strict tenancy + encryption controls**
   - Tenant-scoped storage partitions and per-tenant access policies.
   - Encryption in transit (TLS 1.2+) and at rest (KMS-managed keys).
   - Key rotation and access auditability are mandatory.

4. **Time-boxed retention + deletion SLA**
   - Default retention for derived artifacts: 30 days.
   - Hard-delete pipeline with proof-of-deletion audit records.
   - User-initiated delete API/flow with ≤24h deletion SLA.

5. **No training/analytics reuse of customer artifacts**
   - Customer plan inputs and derived outputs are excluded from model training.
   - Product analytics must be metadata-only (counts, latencies, error classes), never raw payload content.

6. **Auditable security posture before GA**
   - Threat model, DLP tests, red-team abuse cases, and access-control tests are release gates.
   - SOC 2-relevant control mapping must be attached to the launch checklist.

## Data Classification Policy

### Class A — Forbidden to Persist

- Raw Terraform plan JSON.
- Any unredacted `before` / `after` attribute payload.
- Secrets/tokens/keys/passwords.
- Full cloud account identifiers where not operationally required.

### Class B — Persist Allowed (Derived + Redacted)

- Risk counts (`safe`, `review`, `dangerous`, `irreversible`).
- Resource-type histograms.
- Policy/rule hit identifiers.
- Timestamped run metadata (tenant ID, run ID, duration, status).

### Class C — Operational Security Logs

- AuthN/AuthZ decisions.
- Request IDs, error codes, latency, rate-limit events.
- No payload bodies.

## Required Architecture Controls

1. **Ingress Guard**
   - Enforce request size limits.
   - Reject unsupported MIME/content shapes.
   - Canonicalize input and strip dangerous encodings.

2. **Sensitive-Field Redaction Layer**
   - Deterministic redaction before any serialization boundary.
   - Fails closed: if redaction cannot prove safe shape, processing aborts.

3. **Ephemeral Processing Runtime**
   - Sandboxed compute with no shared writable volumes.
   - Memory wiped on completion/error.

4. **Derived-Only Storage Writer**
   - Single narrow writer path that accepts only schema-validated derived output.
   - Schema rejects raw blobs and unknown fields.

5. **Policy Enforcement + Audit Trail**
   - Every access path emits auditable decision records.
   - Break-glass admin access must be time-bound and logged.

## Release Gates (Mandatory)

Before any hosted analyzer beta/GA:

- [ ] Threat model approved (spoofing, tampering, data exfiltration, tenant breakout, retention bypass).
- [ ] Automated tests proving raw-plan non-persistence.
- [ ] Logging inspection tests proving no payload body leaks.
- [ ] Tenant isolation tests (positive and adversarial).
- [ ] Deletion pipeline test with verifiable tombstone/audit proof.
- [ ] Incident response runbook for data leak scenarios.
- [ ] Public-facing privacy statement aligned to actual behavior.

## Non-Goals

- This ADR does **not** authorize a hosted analyzer launch.
- This ADR does **not** add a backend, accounts, billing, or new data pipeline in current releases.
- This ADR does **not** relax existing local-first guarantees in CLI/GitHub Action/site surfaces.

## Consequences

### Positive

- Prevents accidental SaaS drift that violates privacy posture.
- Converts "security best practice" into objective release gates.
- Keeps future monetization options open without sacrificing trust.

### Negative

- Increases implementation effort for any hosted path.
- May reduce debugging convenience due to payload minimization.

### Neutral

- Current product behavior remains unchanged.
- Existing static onboarding and local MCP preview strategy remains intact.

## References

- `SECURITY.md` (local-first security model)
- `docs/adr/0011-site-framework-rebuild.md`
- `docs/adr/0012-mcp-preview-adapter.md`
- Weekly brief runbook (internal — moved to Notion, 2026-06-10)
- `site/README.md`
