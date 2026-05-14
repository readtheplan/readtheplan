# Incident Response — Hosted Analyzer Data Handling

Status: draft (required before hosted beta/GA)

## Trigger

Any indication of:
- raw payload persistence
- sensitive value leakage in logs/artifacts
- tenant cross-access
- retention/deletion SLA breach

## Roles

- Incident Commander (IC): Security lead
- Ops Lead: platform/SRE
- Engineering Lead: service owner
- Comms Lead: customer/internal updates

## Severity

- **SEV-1:** confirmed tenant data exposure/cross-tenant access
- **SEV-2:** potential leak, unconfirmed scope
- **SEV-3:** policy/control degradation with no known exposure

## Response Flow

1. **Triage (0-30m)**
   - open incident channel
   - assign IC + owners
   - preserve evidence (logs, request IDs, deploy SHA)
2. **Containment (<=60m)**
   - disable affected endpoint/feature flag
   - revoke risky credentials/tokens
   - block unsafe egress path if needed
3. **Eradication + Recovery**
   - patch root cause
   - validate with hosted-security gate tests
   - run targeted backfill cleanup/deletion
4. **Communication**
   - internal status every 60m for SEV-1/2
   - customer notifications per policy once scope confirmed
5. **Post-incident**
   - RCA within 5 business days
   - add/strengthen automated tests
   - update ADR/runbook

## Evidence Requirements

- incident ID
- timeline of key actions
- impacted tenant/run IDs (if any)
- proof of deletion/remediation where applicable
- links to test reruns and fixed commit

## Exit Criteria

- exploit path closed
- validation tests passing
- monitoring in place for recurrence
- IC sign-off
