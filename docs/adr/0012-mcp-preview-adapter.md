# ADR 0012: MCP Preview Adapter

## Status

Proposed

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

Ship an experimental MCP preview as a local stdio adapter in a future release.
The preview exposes a small tool surface that reuses existing readtheplan
analysis behavior and returns existing JSON shapes.

For v0, expose one tool:

1. `analyze_plan`: read a local Terraform plan JSON file and return the same
   summary object as `readtheplan analyze --format json <plan_path>`.

Evidence generation and signed evidence verification are not v0 MCP tools.
They are a documented follow-on path because they have stronger audit and
identity semantics than basic plan analysis. They can be added only after the
adapter proves useful and the implementation can preserve the existing
`rtp-evidence-v1` and verify contracts without adding MCP-specific schema
fields.

The MCP adapter may call imported Python functions directly. It should not
shell out to the CLI when the same behavior is available as a library call.
The CLI remains the canonical user-facing interface and the GitHub Action
remains the canonical CI interface.

## Tool Set

### v0

#### `analyze_plan`

Purpose: classify Terraform plan changes for local agent or IDE review.

Inputs:

- `plan_path`: local path to `terraform show -json` output.

Behavior:

- Parse the same Terraform plan JSON accepted by the CLI.
- Apply the same built-in rules and default risk taxonomy as the CLI.
- Return the same JSON summary object as `readtheplan analyze --format json`.
- Return structured MCP errors for missing files, invalid JSON, unsupported
  plan shapes, or analysis failures.

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
    }
  },
  "required": ["plan_path"],
  "additionalProperties": false
}
```

### `analyze_plan` Result

The result is the existing CLI JSON summary:

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

Framework annotations may appear only if the future MCP tool explicitly
accepts framework selection and delegates to the same CLI contract. v0 does
not add framework, evidence, signing, or overlay options.

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
- File handling should be explicit and conservative. The implementation should
  reject missing paths, directories, non-JSON inputs, and paths outside an
  allowed working root when the MCP client supplies such a root.
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

For this ADR-only change:

- Run the existing documentation/ADR tests.
- Run the practical unit test subset if it is lightweight in the local
  environment.

For the future MCP implementation:

- Unit-test each tool handler against imported readtheplan functions.
- Assert that `analyze_plan` output exactly matches
  `readtheplan analyze --format json` for representative fixtures.
- Test invalid paths, missing files, malformed JSON, unsupported Terraform plan
  structures, and permission errors.
- Test that MCP errors are structured and do not leak raw plan contents.
- Add an integration smoke test that starts the stdio server, performs tool
  discovery, calls `analyze_plan`, and compares the result with the CLI JSON
  contract.
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
4. Implement `analyze_plan` only, backed by the existing analyzer and JSON
   summary contract.
5. Add unit tests and one stdio integration smoke test.
6. Document preview client configuration and mark the feature experimental.
7. Revisit `create_evidence` after v0 feedback. Add it only if it can return
   exactly `rtp-evidence-v1` without MCP-only fields.
8. Revisit `verify_evidence` after the evidence path and verify library
   boundary are stable.

## Consequences

### Positive

- AI agents and IDEs can call readtheplan without hand-written shell wrappers.
- The preview reinforces the existing local-first product boundary.
- The initial implementation remains small because it adapts existing analysis
  instead of creating new policy behavior.
- Keeping v0 to `analyze_plan` reduces audit, signing, and schema risk while
  the MCP surface is still experimental.

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
