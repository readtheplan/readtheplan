# Hosted Analyzer Release Gates

This document operationalizes ADR 0013 (`docs/adr/0013-hosted-analyzer-data-handling-boundary.md`).

A hosted analyzer cannot ship (beta or GA) unless every gate here is passing with machine-verifiable evidence.

## Gate Matrix

### Gate 1 — Raw plan non-persistence
- **Objective:** prove raw Terraform plan JSON is never persisted.
- **Owner:** Backend + Security.
- **Evidence:** `tests/hosted_security/test_forbidden_fields_never_persisted.py` in CI.
- **Pass criteria:** tests fail when raw fields appear in persistence payloads.
- **Fail criteria:** any payload stores raw plan body, `before`, or `after` blobs.

### Gate 2 — Log payload leak prevention
- **Objective:** prove logs never include raw payload bodies or secret values.
- **Owner:** Platform + Security.
- **Evidence:** `tests/hosted_security/test_logs_never_include_raw_payload.py`.
- **Pass criteria:** sanitizer tests pass for representative sensitive samples.
- **Fail criteria:** raw payload or secret-like values appear in logs.

### Gate 3 — Derived-schema allowlist enforcement
- **Objective:** only derived, redacted schema is storable.
- **Owner:** Backend.
- **Evidence:** `tests/hosted_security/test_derived_schema_rejects_raw_blobs.py`.
- **Pass criteria:** unknown keys and raw blobs are rejected.
- **Fail criteria:** permissive schema accepts arbitrary/raw fields.

### Gate 4 — Retention and delete-SLA contract
- **Objective:** enforce 30-day default retention and ≤24h delete SLA contract metadata.
- **Owner:** Backend + SRE.
- **Evidence:** `tests/hosted_security/test_retention_and_delete_sla_contract.py`.
- **Pass criteria:** contract metadata validates retention window + deletion deadline.
- **Fail criteria:** retention unset/too long, deletion metadata missing or >24h.

### Gate 5 — Threat model completeness
- **Objective:** have approved threat model for hosted analyzer data flow.
- **Owner:** Security.
- **Evidence:** `docs/security/threat-model-hosted-analyzer.md` exists and covers required abuse cases.
- **Pass criteria:** includes tenant breakout, exfiltration, retention bypass, break-glass misuse.
- **Fail criteria:** missing file or missing mandatory abuse cases.

### Gate 6 — Incident response readiness
- **Objective:** define hosted-data incident response procedure before launch.
- **Owner:** Security + Ops.
- **Evidence:** `docs/security/incident-response-hosted-data.md` exists with triage/containment/notification steps.
- **Pass criteria:** runbook includes ownership, severity model, evidence handling, comms path.
- **Fail criteria:** missing or incomplete runbook.

## CI Enforcement

- Workflow: `.github/workflows/hosted-security-gates.yml`
- Artifact: `hosted-security-gate-report.json`
- Merge policy: this workflow must be a required check for hosted/security path changes.

## Release Rule

If any gate is red or unverifiable: **do not ship hosted analyzer**.
