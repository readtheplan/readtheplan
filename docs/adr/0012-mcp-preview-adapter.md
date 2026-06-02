# ADR 0012: MCP Preview Adapter

## Status

Accepted (2026-06-02)

## Context

readtheplan's primary product surface is the Python CLI and the composite
GitHub Action. Both are intentionally local-first: users produce Terraform
plan JSON, run deterministic analysis, optionally write an evidence envelope,
and optionally verify a signed attestation. The machine-readable contracts for
those workflows already exist in the CLI JSON output and the
`rtp-evidence-v1` envelope.

AI coding agents and IDEs increasingly discover local tools through the Model
Context Protocol (MCP). An MCP preview can make readtheplan easier for those
clients to call, but it must not change the product boundary. MCP is an
adapter over the existing local workflows, not a new server-first product.

The constraints for this preview are:

- The Python CLI and GitHub Action remain primary.
- MCP runs locally over stdio.
- MCP delegates to the existing CLI/imported Python contracts.
- Terraform plan JSON stays local to the user's machine.
- Existing JSON schemas remain the source of truth.
- No SaaS dashboard, raw plan upload service, policy engine, remote rule
  service, or schema fork is introduced.

## Decision

Ship an experimental MCP preview as a local stdio adapter. The preview
exposes a small tool surface that reuses existing readtheplan analysis
behavior and returns existing JSON shapes.

### v0 Tool Surface

The v0 implementation exposes three tools — `analyze_plan`, `agent_gate`,
and `agent_gate_cloudformation`. While the initial ADR draft proposed a
single-tool surface (`analyze_plan` only), implementation revealed that
`agent_gate` and `agent_gate_cloudformation` are lightweight wrappers over
the same analysis pipeline. They add no new contracts, schema drift, or
audit risk, and removing them would break tested behavior without adding
safety.

| Tool | Purpose |
|---|---|
| `analyze_plan` | Classify Terraform plan changes; returns the CLI JSON summary. |
| `agent_gate` | Return proceed/warn/block gate decision with required checks. |
| `agent_gate_cloudformation` | Same gate contract for CloudFormation Change Sets. |

#### `analyze_plan`

Purpose: classify Terraform plan changes for local agent or IDE review.

Inputs:

- `plan_path` (*required*): local path to `terraform show -json` output.
- `framework` (*optional*): compliance framework name (`soc2`, `hipaa`,
  `iso27001`, etc.). When set, each resource change in the summary is
  annotated with matching control IDs, titles, and rationales from the
  framework catalog, and a top-level `framework` key identifies the
  catalog version.

Behavior:

- Parse the same Terraform plan JSON accepted by the CLI.
- Apply the same built-in rules and default risk taxonomy as the CLI.
- When `framework` is provided, delegate to `load_catalog()` and annotate
  each change with the framework's control entries via the existing
  `summary_to_dict(…, catalog)` contract.
- Return the same JSON summary object as `readtheplan analyze --format json`
  (or `--format json --framework <name>`).
- Return structured MCP errors for missing files, invalid JSON, unsupported
  plan shapes, unknown frameworks, path-traversal violations, or analysis
  failures.

#### `agent_gate`

Purpose: deterministic proceed/warn/block decision for coding agents.

Inputs:

- `plan_path` (*required*): local path to `terraform show -json` output.
- `framework` (*optional*): compliance framework name for per-resource
  control checks in the `required_checks` list.

Returns the `rtp-agent-gate-v1` contract (same as CLI `agent-gate`).

#### `agent_gate_cloudformation`

Purpose: same gate contract for CloudFormation Change Sets or template
diffs.

Inputs:

- `input_path` (*required*): local path to CloudFormation JSON.

Returns the `rtp-agent-gate-v1` contract with `tool_name="CloudFormation"`.

### Deferred Tools

#### `create_evidence`

Deferred until after v0 because evidence output is an audit artifact, not just
an interactive explanation. If added, it must return an `rtp-evidence-v1`
object equivalent to:

```bash
readtheplan analyze --framework <framework> --evidence - <plan_path>
```

It must not expose signing in MCP v0.x. Local browser-based OIDC and CI OIDC
belong in the existing CLI and GitHub Action surfaces.

#### `verify_evidence`

Deferred until after the evidence path is added and the verify code has a
machine-readable function boundary suitable for adapter use. If added, it must
verify an existing local evidence file and return the same verification facts
as the CLI, without changing signed-envelope semantics.

## High-Level JSON Schemas

These schemas describe the MCP-facing shape at a high level. The detailed
analysis and evidence payloads remain governed by existing readtheplan
contracts and ADRs.

### `analyze_plan` Input

```json
{
  "type": "object",
  "properties": {
    "plan_path": {
      "type": "string",
      "description": "Local path to Terraform plan JSON from terraform show -json."
    },
    "framework": {
      "type": "string",
      "description": "Optional compliance framework name (e.g. soc2, hipaa, iso27001)."
    }
  },
  "required": ["plan_path"],
  "additionalProperties": false
}
```

### `analyze_plan` Result

Without framework (same as CLI `--format json`):

```json
{
  "resource_change_count": 3,
  "actions": {
    "create": 1,
    "update": 1,
    "delete/create": 1
  },
  "risks": {
    "safe": 1,
    "review": 1,
    "dangerous": 1,
    "irreversible": 0
  },
  "changes": [
    {
      "address": "aws_s3_bucket.logs",
      "type": "aws_s3_bucket",
      "actions": ["update"],
      "risk": "review",
      "explanation": "..."
    }
  ]
}
```

With framework (same as CLI `--format json --framework soc2`):

```json
{
  "resource_change_count": 3,
  "actions": { "...": "..." },
  "risks": { "...": "..." },
  "framework": {
    "name": "soc2",
    "version": "2023",
    "schema_version": 1
  },
  "changes": [
    {
      "address": "aws_s3_bucket.logs",
      "type": "aws_s3_bucket",
      "actions": ["update"],
      "risk": "review",
      "explanation": "...",
      "controls": [
        {
          "id": "CC6.1",
          "title": "Logical Access Security",
          "rationale": "..."
        }
      ]
    }
  ]
}
```

### Deferred `create_evidence` Input

```json
{
  "type": "object",
  "properties": {
    "plan_path": {
      "type": "string"
    },
    "framework": {
      "type": "string",
      "enum": ["soc2", "iso27001", "hipaa"]
    },
    "reviewer_id": {
      "type": "string"
    },
    "run_id": {
      "type": "string"
    }
  },
  "required": ["plan_path", "framework"],
  "additionalProperties": false
}
```

Result: existing `rtp-evidence-v1` JSON from ADR 0007.

### Deferred `verify_evidence` Input

```json
{
  "type": "object",
  "properties": {
    "evidence_path": {
      "type": "string"
    }
  },
  "required": ["evidence_path"],
  "additionalProperties": false
}
```

Result: existing signed-attestation verification facts from ADR 0008, shaped
for MCP only after the CLI/library boundary is available.

## Security Model

- Local stdio only. The preview does not introduce an HTTP server, hosted
  endpoint, SaaS relay, or cloud proxy.
- Plan JSON stays on the user's machine. The adapter reads local files and
  returns analysis to the calling local MCP client.
- The adapter has the same operating-system privileges as the user process
  that starts it. It is not a sandbox and does not claim stronger isolation
  than the CLI.
- The adapter is read-only in v0. `analyze_plan` reads a plan file and returns
  JSON; it does not write evidence files, signatures, cache entries, or logs
  containing raw plan contents.
- **Working-root path validation**: when the `MCP_ROOT` environment variable
  is set, every `plan_path` is resolved to its canonical absolute path and
  checked to fall within the `MCP_ROOT` directory tree. Paths outside the root
  are rejected with a `PATH_TRAVERSAL` error before any file read occurs.
  When `MCP_ROOT` is unset, path resolution still occurs but no boundary
  check is enforced (matching CLI behavior).
- Path traversal is checked via `Path.resolve()` followed by
  `Path.relative_to()`, which correctly handles symlinks and `..` segments.
- Logs go to stderr and must not include raw plan JSON.
- No credentials are requested or stored by v0. Sigstore signing remains
  outside the MCP preview.

## Non-Goals

- No MCP server implementation in this ADR.
- No hosted MCP service.
- No raw plan upload service.
- No SaaS dashboard.
- No new policy engine or OPA/Sentinel replacement.
- No remote rules, remote overlays, or policy downloads.
- No schema drift from `readtheplan analyze --format json`.
- No schema drift from `rtp-evidence-v1`.
- No MCP-specific signing model.
- No MCP prompt resources, subscriptions, streaming, or long-running progress
  protocol in v0.
- No multi-cloud expansion.

## Test Plan

For the MCP implementation:

- Unit-test each tool handler against imported readtheplan functions.
- Assert that `analyze_plan` output exactly matches
  `readtheplan analyze --format json` for representative fixtures.
- Assert that `analyze_plan` with `--framework` matches
  `readtheplan analyze --format json --framework <name>`.
- Test invalid paths, missing files, malformed JSON, unsupported Terraform plan
  structures, unknown frameworks, and permission errors.
- Test working-root path traversal: `MCP_ROOT` set → paths outside rejected;
  `MCP_ROOT` unset → no boundary check.
- Test that MCP errors are structured and do not leak raw plan contents.
- **Stdio integration smoke test**: starts the real `readtheplan mcp` server
  as a subprocess, performs the full MCP handshake (initialize →
  initialized), lists tools via `tools/list`, calls `analyze_plan` via
  `tools/call`, and compares the result with the CLI JSON contract.
  A second stdio test exercises `analyze_plan` with framework.
- If `create_evidence` is later added, compare its result with the CLI
  `--evidence -` output for each supported framework.
- If `verify_evidence` is later added, compare success and failure cases with
  `readtheplan verify`.

## Implementation Sequencing

1. Prepare library boundaries for the existing CLI behavior where needed.
   Analysis should be callable without invoking a subprocess.
2. Add an optional MCP runtime dependency or extra only if required by the
   chosen Python MCP SDK. Keep dependency scope narrow and pinned.
3. Add a preview `readtheplan mcp` stdio entry point.
4. Implement `analyze_plan`, `agent_gate`, and `agent_gate_cloudformation`,
   backed by the existing analyzer, gate contract, and JSON summary
   contracts.
5. Add framework parameter to `analyze_plan` (and `agent_gate`) delegating
   to `load_catalog()` via the existing `summary_to_dict(…, catalog)`
   contract.
6. Add working-root path traversal protection via `MCP_ROOT` env var.
7. Add unit tests and two stdio integration smoke tests.
8. Document preview client configuration and mark the feature experimental.
9. Revisit `create_evidence` after v0 feedback. Add it only if it can return
   exactly `rtp-evidence-v1` without MCP-only fields.
10. Revisit `verify_evidence` after the evidence path and verify library
    boundary are stable.

## Consequences

### Positive

- AI agents and IDEs can call readtheplan without hand-written shell wrappers.
- The preview reinforces the existing local-first product boundary.
- The initial implementation remains small because it adapts existing analysis
  instead of creating new policy behavior.
- Framework annotations are available through `analyze_plan` (with optional
  `framework` parameter), matching CLI parity.
- Working-root path validation (`MCP_ROOT`) provides a security boundary for
  MCP client configurations that restrict file access.

### Negative

- MCP adds another integration surface to document and test.
- A Python MCP SDK may add a new dependency or optional extra.
- Users may expect MCP parity with every CLI flag. The preview must state that
  the CLI is the complete interface.

### Neutral

- The MCP adapter is opt-in and local.
- The adapter can be removed or redesigned before general availability if MCP
  client expectations change.
- Evidence and verification remain available through the CLI and GitHub Action
  while their MCP shape is deferred.

## References

- ADR 0002: Plan Input Format
- ADR 0003: Risk Classification Taxonomy
- ADR 0007: Evidence Envelope
- ADR 0008: Signed Attestation
- ADR 0010: Customer-Supplied Rule Overrides
- README: CLI JSON output, evidence envelope, and signed attestation sections
