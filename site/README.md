# readtheplan.dev

Static website and browser tools for readtheplan.

The first release is intentionally client-side only: it helps visitors choose CI,
framework, plan artifact/path, blocking threshold, and evidence settings, then
generates GitHub Actions YAML, CLI commands, privacy guidance, and an onboarding
checklist without uploading infrastructure data.

The `tools/` and `resources/` routes are free static reference pages. They use
manual counts and high-level Terraform/AWS control examples only; they do not
accept raw plan files or send form submissions.

The `/mcp/` route productizes the local MCP preview for secure AI-agent demo
workflows. It documents `pip install "readtheplan[mcp]"`, `readtheplan mcp`,
the current tool surface, sample prompts, and community contribution boundaries.
It must stay local-first: no raw Terraform plan upload, no hosted
MCP service, no hosted plan analysis, no backend, no accounts, and no billing.

The `/brief/` route is a free infrastructure and compliance digest for platform
teams. It is a static landing page, sample brief, and editorial runbook only.
Future sponsorships must be clearly labeled; Cloudflare machine-traffic
monetization must not restrict normal human access. The route must not add raw
plan upload, hosted analysis, accounts, billing, storage, or a backend.

## Commands

```bash
npm --prefix site test
npm --prefix site run build
```

The build output is written to `site/dist/`, which is the intended Cloudflare
Pages output directory.
