# readtheplan.dev

Static setup generator for readtheplan.

The first release is intentionally client-side only: it helps visitors choose CI,
framework, plan artifact/path, blocking threshold, and evidence settings, then
captures optional setup context and generates GitHub Actions YAML, CLI commands,
privacy guidance, an onboarding checklist, and a transparent optional mailto
handoff without uploading Terraform plan data.

The free setup-help destination is configured in `site/app.js` as
`SETUP_HELP_EMAIL`. The intake form has no backend action, and setup context stays
in the browser until the visitor chooses to open the generated email draft.

The `tools/` and `resources/` routes are static SEO lead-gen pages. They use
manual counts and high-level Terraform/AWS control examples only; they do not
accept raw plan files or send form submissions.

The `/mcp/` route productizes the local MCP preview for secure AI-agent demo
workflows. It documents `pip install "readtheplan[mcp]"`, `readtheplan mcp`,
the current `analyze_plan`-only tool surface, sample prompts, and setup-help
boundaries. It must stay local-first: no raw Terraform plan upload, no hosted
MCP service, no hosted plan analysis, no backend, no accounts, and no billing.

The `/brief/` route is a free community digest for weekly Terraform/SOC 2 change
intelligence. It is a static landing page, sample brief, and editorial runbook
only. It must not add raw plan upload, hosted analysis, product accounts, billing,
storage, a backend, or automatic delivery.

Every readtheplan feature is free and MIT licensed. The project may accept
sponsorships or prepare additive machine-facing services for future funding, but
it must not add behavioral ads or gate human access or local features.

## Commands

```bash
npm --prefix site test
npm --prefix site run build
```

The build output is written to `site/dist/`, which is the intended Cloudflare
Pages output directory.
