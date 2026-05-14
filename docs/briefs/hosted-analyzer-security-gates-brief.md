# Hosted Analyzer Security Gates — Implementation Brief

> **For Hermes/Codex:** implement these gates before any hosted analyzer beta or GA. If a gate cannot be automated yet, block launch and keep feature behind an explicit non-production flag.

## Goal

Translate ADR 0013 (`docs/adr/0013-hosted-analyzer-data-handling-boundary.md`) into enforceable engineering controls, tests, and CI checks so the hosted analyzer cannot launch with weak or unverifiable data handling.

## Scope

- Define gate artifacts and testable acceptance criteria.
- Add CI-required checks that fail closed.
- Keep current local-first product surfaces unchanged.

## Non-goals

- Building a production hosted analyzer in this brief.
- Adding billing/accounts/multi-tenant control plane in this brief.
- Relaxing local-first guarantees for CLI/GitHub Action/site.

---

## Required Deliverables

1. **Security Gate Spec Document**
   - New file: `docs/security/hosted-analyzer-release-gates.md`
   - Must include each ADR 0013 gate with:
     - objective
     - owner
     - automated evidence source (test/log/report path)
     - pass/fail criteria

2. **Redaction + Data-classification Test Suite (contract tests)**
   - New tests folder: `tests/hosted_security/`
   - Test categories:
     - `test_forbidden_fields_never_persisted.py`
     - `test_logs_never_include_raw_payload.py`
     - `test_derived_schema_rejects_raw_blobs.py`
     - `test_retention_and_delete_sla_contract.py`
   - If hosted modules do not yet exist, create fixture-based contract tests with explicit TODO markers bound to issue IDs.

3. **CI Gate Workflow**
   - New workflow: `.github/workflows/hosted-security-gates.yml`
   - Trigger: pull_request + push on branches touching hosted/security paths.
   - Must fail on:
     - forbidden-field persistence detection
     - payload leakage in log fixtures
     - missing threat model artifact
     - missing deletion-proof artifact format

4. **Threat Model + Incident Runbook Skeletons**
   - New files:
     - `docs/security/threat-model-hosted-analyzer.md`
     - `docs/security/incident-response-hosted-data.md`
   - Must include abuse cases: tenant breakout, data exfiltration, retention bypass, break-glass misuse.

---

## File Plan

### Create
- `docs/security/hosted-analyzer-release-gates.md`
- `docs/security/threat-model-hosted-analyzer.md`
- `docs/security/incident-response-hosted-data.md`
- `tests/hosted_security/test_forbidden_fields_never_persisted.py`
- `tests/hosted_security/test_logs_never_include_raw_payload.py`
- `tests/hosted_security/test_derived_schema_rejects_raw_blobs.py`
- `tests/hosted_security/test_retention_and_delete_sla_contract.py`
- `.github/workflows/hosted-security-gates.yml`

### Modify
- `README.md` (short pointer under security model to hosted gate policy)
- `SECURITY.md` (reference ADR 0013 + hosted gate workflow)
- `CHANGELOG.md` (if this lands in release scope)

---

## Acceptance Criteria (must all pass)

1. **Raw-plan non-persistence gate is objective**
   - There is at least one automated test that fails when raw plan JSON appears in persistence payload fixtures.

2. **Log leak gate is objective**
   - There is at least one automated test that fails when log output contains raw payload body or secret-like key names/values.

3. **Derived schema is enforceable**
   - Tests prove schema rejects unknown keys and raw `before/after` blobs.

4. **Deletion posture is testable**
   - Contract tests exist for deletion request + tombstone/proof shape and SLA metadata.

5. **CI blocks unsafe merges**
   - `hosted-security-gates` is a required check for hosted/security path changes.

6. **Docs are aligned**
   - `SECURITY.md` and docs explicitly state hosted analyzer remains blocked until these gates pass.

---

## Test Commands

```bash
python3 -m pytest tests/hosted_security -q
python3 -m pytest -q
```

If environment lacks pytest, use:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run --with pytest python -m pytest tests/hosted_security -q
```

---

## CI Workflow Requirements

`hosted-security-gates.yml` should:

- use least-privilege permissions
- run fast (<5 min target)
- execute hosted security tests
- upload a compact gate report artifact (`hosted-security-gate-report.json`)
- explicitly fail if required docs are missing:
  - `docs/security/threat-model-hosted-analyzer.md`
  - `docs/security/incident-response-hosted-data.md`
  - `docs/security/hosted-analyzer-release-gates.md`

---

## Risk Notes

- **High risk** if gates are advisory-only docs without failing automation.
- **Medium risk** if tests exist but are not required checks.
- **Low risk** only when tests are required and release checklist evidence is machine-verifiable.

---

## Suggested Execution Order

1. Add docs skeletons and gate spec.
2. Add contract tests (fixture-based if implementation absent).
3. Add CI workflow.
4. Wire required status check in branch protection/ruleset.
5. Update SECURITY.md + README references.
6. Run tests and open PR with gate report.

---

## Done Definition

This brief is done when:

- all files above exist,
- hosted security tests pass,
- CI workflow is green,
- and branch protection treats `hosted-security-gates` as required for relevant changes.
