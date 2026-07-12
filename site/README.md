# readtheplan.dev

Static setup generator for readtheplan.

The first release is intentionally client-side only: it helps visitors choose CI,
framework, plan artifact/path, blocking threshold, and evidence settings, then
captures optional client intake context and generates GitHub Actions YAML, CLI
commands, privacy guidance, an onboarding checklist, and a transparent mailto
handoff without uploading Terraform plan data.

The pilot handoff destination is configured in `site/app.js` as
`PILOT_HANDOFF_EMAIL`. It currently uses `info@readtheplan.dev` as a
placeholder; replace it before production use. The intake form has no backend
action, and client context stays in the browser until the visitor chooses to open
the generated email draft.

The `tools/` and `resources/` routes are static SEO lead-gen pages. They use
manual counts and high-level Terraform/AWS control examples only; they do not
accept raw plan files or send form submissions.

The `/mcp/` route productizes the local MCP preview for secure AI-agent demo
workflows. It documents `pip install "readtheplan[mcp]"`, `readtheplan mcp`,
the current `analyze_plan`-only tool surface, sample prompts, and custom pilot
boundaries. It must stay local-first: no raw Terraform plan upload, no hosted
MCP service, no hosted plan analysis, no backend, no accounts, and no billing.

The `/brief/` route is a free community artifact: weekly Terraform/SOC 2 change
intelligence for platform teams. It is a static landing page, sample brief, and
editorial runbook only. It must not add raw plan upload, hosted analysis,
accounts, billing, storage, a backend, or automatic delivery.

The `/pricing/` route documents the free-forever model. There are no paid product
tiers or feature gates. Funding experiments must remain optional, must not change
analysis results, and must not add behavioral advertising or plan-data collection.
See [`MONETIZATION.md`](MONETIZATION.md) for the Cloudflare rollout and guardrails.

## Commands

```bash
npm --prefix site test
npm --prefix site run build
```

The build output is written to `site/dist/`, which is the intended Cloudflare
Pages output directory.
