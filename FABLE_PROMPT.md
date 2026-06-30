# Fable 5 Prompt — readtheplan Architecture Review

You are acting as a **senior product architect + developer experience consultant**. Conduct a deep, thorough review of the **readtheplan** project — a Terraform/OpenTofu plan risk analysis tool. Be blunt. Disagree where warranted. Your goal is to make this the best tool in its category and maximize developer adoption.

## Project Context

**readtheplan** classifies every Terraform plan change into risk tiers: safe, review, dangerous, irreversible. It produces compliance evidence for SOC 2, ISO 27001, and HIPAA. Runs locally — no uploads, no accounts, no backend.

- GitHub: https://github.com/readtheplan/readtheplan  
- Website: https://readtheplan.dev  
- Language: Python 3.10+  
- Package: `pip install readtheplan` (v0.3.0 on PyPI)  
- CI: GitHub Actions (pytest, coverage 78% gate, deploy, publish, demo report, site health)  
- Repo: ~5 commits, branches include chore/repo-leanup, feat/arch-review-improvements, fix/cli-typeerror  

## Source Components (review each)

1. **cli.py** — CLI entry point. How does it handle `readtheplan analyze plan.json`? Output formatting, error handling, exit codes, help text?
2. **plan.py** — Plan parser. What formats does it accept? JSON plan? Terraform Cloud? OpenTofu? How does it handle malformed/incomplete plans?
3. **rules.py** — Risk classification rules. How are they organized? 4 tiers (safe/review/dangerous/irreversible)? Are there blind spots? Does it handle every Terraform resource type?
4. **controls.py** — Compliance control mappings. SOC 2, ISO 27001, HIPAA — how complete are the mappings? Any missing controls? How does it map plan changes → specific control IDs?
5. **evidence.py** — Evidence envelopes. What's in the envelope? Timestamp, plan hash, risk summary, controls triggered? Is it audit-proof?
6. **signing.py** — Signed attestation. What signing method? GPG? Cosign? How does a CI pipeline verify the signature?
7. **agent_gate.py** — CI/agent gating. Returns proceed/warn/block? How does an AI agent consume this? MCP protocol? JSON output?
8. **summary.py** — Report output. What formats? Terminal output? JSON? HTML? SARIF for GitHub?
9. **attestation.py** — Compliance attestation. Different from evidence? How?
10. **overlays.py** — Rule overrides/customizations. Can users write custom rules? How?
11. **mcp_server.py** — MCP server. What tools does it expose? For Claude Desktop? Codex? Other MCP clients?
12. **adapters/** — Currently CloudFormation adapter. How easy to add Pulumi, CDK, or others?

## Test Suite (review the coverage and quality)

- 23 test files across tests/ and tests/hosted_security/
- Coverage gate at 78%
- What's NOT tested? Edge cases? Error paths? Integration with real Terraform?

## Website & Docs (review every page)

- **Site structure:** 404, app.js, blog, brief, chat, demo, docs, playground, compliance data (soc2.json, hipaa.json, iso27001.json, pci_dss.json, hitrust.json, fedramp_moderate.json)
- **Docs:** quickstart, CLI reference, GitHub Action, MCP server, rule authoring
- **Demo:** Does it effectively show the value? Can someone understand it in 30 seconds?
- **Blog:** What's there? SEO? Content strategy?
- **Chat/Playground:** Interactive? Can users paste plans and test without installing?

## Developer Experience (DX)

- `pip install readtheplan` — any platform issues (Windows, macOS, Linux)?
- Are error messages helpful or cryptic?
- Tab completion? Colored output? Progress indicators?
- Contribution guide — is it welcoming? Clear?
- GitHub issue templates — bug report + feature request. Are they useful?
- PR template — any?
- CODEOWNERS file?
- Dependabot configured?
- AGENTS.md — useful for AI contributors?

## Compliance & Security

- SOC 2 control catalog — complete or gaps?
- ISO 27001 — all Annex A controls mapped?
- HIPAA — all safeguards covered?
- FedRAMP Moderate — is this realistic for an open-source tool?
- HITRUST, PCI DSS — how complete?
- No data uploads — does it hold true in all modes? What about the hosted analyzer?
- Evidence envelope — tamper-proof? How does an auditor verify it?

## Competitive Positioning

- **Competitors:** tfsec, checkov, Sputnik, OPA, Sentinel, Spacelift, env0, infracost
- readtheplan's differentiator: local-only, 4 risk tiers, compliance evidence, agent gate
- Is this differentiator clear from the README and website?
- Who is the primary user? DevOps engineer? Security team? Compliance officer? AI agent?
- Pricing? Open source + hosted tier?

## Scenarios & Edge Cases (address each)

1. **Empty plan** — `terraform plan` with no changes. Should it return "all safe" or error?
2. **Huge plan** — 10,000+ resources. Performance? Memory?
3. **Malformed plan** — truncated JSON, wrong schema version, binary plan output
4. **CI pipeline failure** — what exit codes? How does GitHub Actions integration handle non-zero exits?
5. **AI agent integration** — Claude Code, Codex, Cline all call this via MCP. What happens on timeout? Rate limit?
6. **Multiple providers** — AWS + Azure + GCP in one plan. Does it handle cross-provider?
7. **Plan with null/sensitive values** — Terraform masks sensitive values. How does the analysis handle `(sensitive value)`?
8. **Terragrunt** — popular wrapper. Does readtheplan work with Terragrunt output?
9. **Terraform Cloud/Enterprise** — remote plans. Can it analyze a plan pulled from TFC API?
10. **OpenTofu** — fork of Terraform. Compatible plan format? Any differences?
11. **Custom rule collisions** — user defines an override that conflicts with built-in rules. Who wins?
12. **Network failure** — does any feature phone home? What happens if it can't reach the hosted analyzer?
13. **Multi-version support** — Terraform 1.6, 1.7, 1.8, 1.9 changes to plan format. Version compatibility?

## Recommendations

For every issue you find, provide:
1. **The problem** — what's wrong or missing
2. **Severity** — critical / high / medium / low / nit
3. **Suggested fix** — concrete, actionable
4. **Effort estimate** — small / medium / large

If you disagree with a design decision in the ADRs (docs/adr/), say so and explain why.

## Output Format

End with a ranked priority list of the top 10 most impactful changes, ordered by value-to-effort ratio. The first item should be the one thing that would most improve developer adoption.

Be thorough. Don't skip anything. Take your time.
