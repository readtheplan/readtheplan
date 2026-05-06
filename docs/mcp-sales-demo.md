# MCP Sales and Demo Notes

readtheplan's MCP preview is a local-first productization path for secure
AI-agent integrations in Terraform and compliance review workflows. The current
OSS preview is not a hosted service. It starts with:

```bash
pip install "readtheplan[mcp]"
readtheplan mcp
```

## What the MCP Tool Exposes Today

The preview exposes one stdio MCP tool:

- `analyze_plan` with input `{"plan_path": "plan.json"}`.

It reads local Terraform plan JSON from `terraform show -json` output and
returns the same summary object as:

```bash
readtheplan analyze --format json plan.json
```

The intended demo flow is:

1. Generate plan JSON locally with `terraform plan -out=tfplan` and
   `terraform show -json tfplan > plan.json`.
2. Start the local MCP server with `readtheplan mcp`.
3. Ask an MCP-capable agent to call `analyze_plan` for the local `plan.json`.
4. Review risk tiers, dangerous-change explanations, and control-review notes.

## Deliberately Not Exposed Yet

The MCP preview does not expose these CLI features yet:

- Evidence envelope generation.
- Signature verification.
- Sigstore signing.
- Framework selection.
- Customer rule overlays.
- `--no-rules`.
- Remote prompt resources, subscriptions, streaming, or progress protocol.

Use the CLI and GitHub Action for evidence, signing, framework annotations, and
production CI gates.

## Product Boundary

The product boundary remains local-first and static:

- No raw Terraform plan upload.
- No hosted MCP service.
- No hosted plan analysis.
- No backend, storage layer, accounts, or billing.
- No MCP signing parity unless it has been implemented and documented.

The MCP preview has the same operating-system access as the local process that
starts it. It is a convenience adapter over existing readtheplan analysis, not a
sandbox or remote security boundary.

## Production Custom-MCP Offer Notes

Custom MCP engagements can cover production concerns around a team's local or
self-managed environment, including:

- Authentication design.
- Least-privilege client and workspace setup.
- Audit logging strategy that avoids raw plan capture.
- Deployment guidance for developer workstations or controlled CI runners.
- Support for pilot rollout, prompts, and reviewer workflows.

Do not imply these are included in the OSS preview. They are custom engagement
items for teams that need secure AI-agent integrations around Terraform and
SOC 2 workflows.
