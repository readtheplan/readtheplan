# Threat Model — Hosted Analyzer (Pre-Launch)

Status: draft (required before beta/GA)

## Scope

Future hosted analyzer ingestion + processing path for Terraform plan analysis.

## Assets

- Customer Terraform plan content (high sensitivity)
- Derived risk summaries
- Tenant identifiers and run metadata
- Audit logs and deletion proofs

## Trust Boundaries

1. Customer client -> API ingress
2. Ingress -> processing runtime
3. Processing runtime -> derived storage writer
4. Service control plane -> operator/admin access

## Mandatory Abuse Cases

### 1) Tenant breakout
- **Scenario:** tenant A reads tenant B artifacts via IDOR or policy bug.
- **Controls:** tenant-scoped authz checks, opaque IDs, row-level isolation tests.
- **Detection:** authz deny telemetry + anomaly alerts.

### 2) Data exfiltration
- **Scenario:** raw plan or secret values leak via logs, analytics, or debug dumps.
- **Controls:** payload redaction layer, log scrubber, no raw payload persistence, egress controls.
- **Detection:** DLP scanner on logs/artifacts and canary secret detection.

### 3) Retention bypass
- **Scenario:** records survive beyond retention window due to lifecycle bug.
- **Controls:** TTL policy + hard-delete job + reconciliation audit.
- **Detection:** periodic retention drift report.

### 4) Break-glass misuse
- **Scenario:** privileged emergency access used outside incident context.
- **Controls:** time-bound elevation, approval requirement, immutable access logs.
- **Detection:** alert on off-hours/manual access without incident ID.

## STRIDE Summary

- **Spoofing:** stolen session/token -> mitigate with strong auth + short-lived tokens
- **Tampering:** payload mutation -> signed request context + integrity checks
- **Repudiation:** deny harmful action -> immutable audit trail
- **Information disclosure:** payload leaks -> redaction + least-data storage
- **Denial of service:** oversized payloads -> ingress limits + rate limits
- **Elevation of privilege:** admin abuse -> break-glass controls + approval chain

## Required Validation Before Launch

- Adversarial tenant-isolation tests
- Log redaction tests with realistic sensitive fixtures
- Deletion SLA simulation with proof generation
- Break-glass audit trail walkthrough
